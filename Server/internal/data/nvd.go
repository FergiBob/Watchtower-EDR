// package data handles cloning cpe data and querying cve entries in NIST NVD
package data

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/logs"
)

// FormatNVDTime converts a Go time object to the specific string format the NVD API requires.
func FormatNVDTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000")
}

// ------------------------------------------------------------------------------------------------------------
//                                           CPE SPECIFIC FUNCTIONS
// ------------------------------------------------------------------------------------------------------------

type CPEResponse struct {
	ResultsPerPage int          `json:"resultsPerPage"`
	StartIndex     int          `json:"startIndex"`
	TotalResults   int          `json:"totalResults"`
	Products       []CPEProduct `json:"products"`
}

type CPEProduct struct {
	CPE CPEData `json:"cpe"`
}

type CPEData struct {
	CpeName               string `json:"cpeName"`
	Deprecated            bool   `json:"deprecated"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
}

func ParseCPE(cpe string) []string {
	trimmed := strings.TrimPrefix(cpe, "cpe:2.3:")
	parts := strings.Split(trimmed, ":")
	for len(parts) < 11 {
		parts = append(parts, "*")
	}
	return parts
}

func getCPEStartTime(db *sql.DB) string {
	var lastSync string
	err := db.QueryRow("SELECT last_sync_timestamp FROM sync_metadata WHERE key = 'nvd_cpe'").Scan(&lastSync)

	if err == sql.ErrNoRows || lastSync == "" {
		logs.Sys.Info("No CPE sync history found. Initializing first-time seed from 2002.")
		start := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		return FormatNVDTime(start)
	} else if err != nil {
		logs.DB.Error("Database error checking CPE sync metadata", "error", err)
		return FormatNVDTime(time.Now().AddDate(0, 0, -120))
	}
	return lastSync
}

func processBatch(db *sql.DB, products []CPEProduct) {
	tx, err := db.Begin()
	if err != nil {
		logs.DB.Error("Failed to begin CPE transaction", "error", err)
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO cpe_dictionary (cpe_uri, vendor, product, version, deprecated) 
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cpe_uri) DO UPDATE SET
			vendor=excluded.vendor, product=excluded.product, version=excluded.version, deprecated=excluded.deprecated`)
	if err != nil {
		logs.DB.Error("Failed to prepare CPE batch statement", "error", err)
		return
	}
	defer stmt.Close()

	for _, p := range products {
		parts := strings.Split(p.CPE.CpeName, ":")
		if len(parts) < 6 {
			continue
		}
		_, _ = stmt.Exec(p.CPE.CpeName, parts[3], parts[4], parts[5], p.CPE.Deprecated)
	}
	tx.Commit()
}

func SyncCPE(ctx context.Context, db *sql.DB, apiKey string) error {
	lastSyncStr := getCPEStartTime(db)
	lastSyncTime, _ := time.Parse("2006-01-02T15:04:05.000", lastSyncStr)

	now := time.Now()
	for lastSyncTime.Before(now) {
		windowEnd := lastSyncTime.AddDate(0, 0, 120)
		if windowEnd.After(now) {
			windowEnd = now
		}
		if !lastSyncTime.Before(windowEnd) {
			break
		}

		startIndex := 0
		resultsPerPage := 5000
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("sync interrupted")
			default:
			}

			params := url.Values{}
			params.Add("resultsPerPage", strconv.Itoa(resultsPerPage))
			params.Add("startIndex", strconv.Itoa(startIndex))
			params.Add("lastModStartDate", FormatNVDTime(lastSyncTime))
			params.Add("lastModEndDate", FormatNVDTime(windowEnd))

			req, _ := http.NewRequestWithContext(ctx, "GET", internal.AppConfig.NVD.CpeURL+"?"+params.Encode(), nil)
			req.Header.Set("apiKey", apiKey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("NVD API error: %s", resp.Status)
			}

			var data CPEResponse
			json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()

			if len(data.Products) > 0 {
				processBatch(db, data.Products)
			}

			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			time.Sleep(1 * time.Second)
		}
		db.Exec("INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cpe', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))
		lastSyncTime = windowEnd
	}
	return nil
}

func StartCPEUpdater(ctx context.Context) {
	db := CPE_Database
	apikey := internal.AppConfig.NVD.APIKey
	ticker := time.NewTicker(12 * time.Hour)

	if apikey == "" || apikey == "YOUR_API_KEY_HERE" {
		logs.Sys.Error("NVD API Key missing. CPE Sync disabled.")
		return
	}

	go func() {
		defer ticker.Stop()
		logs.Sys.Info("CPE Updater background worker started.")

		// Initial sync
		if err := SyncCPE(ctx, db, apikey); err != nil {
			logs.Sys.Error("Initial CPE sync failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				logs.Sys.Info("Starting scheduled CPE sync...")
				if err := SyncCPE(ctx, db, apikey); err != nil {
					logs.Sys.Error("CPE sync failed, scheduling 1hr retry", "error", err)

					// This nested select is what makes it "safe" for shutdowns
					select {
					case <-time.After(1 * time.Hour):
						logs.Sys.Info("Retrying CPE sync...")
						if err := SyncCPE(ctx, db, apikey); err != nil {
							logs.Sys.Error("CPE retry failed. Waiting for next 12hr cycle.", "error", err)
						}
					case <-ctx.Done():
						return // Exit immediately if the app shuts down during the 1hr wait
					}
				}
			case <-ctx.Done():
				logs.Sys.Info("CPE Updater background worker stopped.")
				return
			}
		}
	}()
}

// MapCPEs correlates both Software and Operating Systems to CPE URIs
func MapCPEs() error {
	// 1. Map Software
	swRows, _ := ReadQuery(Main_Database, `SELECT id, name, version, vendor FROM software WHERE cpe_uri IS NULL OR cpe_uri = ''`)
	defer swRows.Close()
	for swRows.Next() {
		var id int
		var name, version, vendor string
		swRows.Scan(&id, &name, &version, &vendor)
		var cpeURI string
		query := `SELECT cpe_uri FROM cpe_dictionary WHERE (vendor LIKE ? OR ? LIKE '%' || vendor || '%') AND (product LIKE ? OR ? LIKE '%' || product || '%') AND (version = ? OR version = '*') ORDER BY version DESC, deprecated ASC LIMIT 1`
		if err := QuerySingleRow(CPE_Database, query, []any{"%" + vendor + "%", vendor, "%" + name + "%", name, version}, &cpeURI); err == nil {
			WriteQuery(Main_Database, "UPDATE software SET cpe_uri = ? WHERE id = ?", cpeURI, id)
		}
	}

	// 2. Map Operating Systems (New OS Logic)
	agentRows, _ := ReadQuery(Main_Database, `SELECT agent_id, os, os_version FROM agents WHERE os_cpe_uri IS NULL OR os_cpe_uri = ''`)
	defer agentRows.Close()
	for agentRows.Next() {
		var aid, osName, osVer string
		agentRows.Scan(&aid, &osName, &osVer)
		var cpeURI string
		// Look specifically for 'o' (Operating System) part CPEs
		query := `SELECT cpe_uri FROM cpe_dictionary WHERE cpe_uri LIKE 'cpe:2.3:o:%' AND (product LIKE ? OR ? LIKE '%' || product || '%') AND (version = ? OR version = '*') ORDER BY version DESC LIMIT 1`
		if err := QuerySingleRow(CPE_Database, query, []any{"%" + osName + "%", osName, osVer}, &cpeURI); err == nil {
			WriteQuery(Main_Database, "UPDATE agents SET os_cpe_uri = ? WHERE agent_id = ?", cpeURI, aid)
		}
	}
	return nil
}

func StartCPEMapper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		logs.Sys.Info("CPE-Software Mapper background worker started.")

		if err := MapCPEs(); err != nil {
			logs.Sys.Error("Initial CPE-Software map failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				if err := MapCPEs(); err != nil {
					logs.Sys.Error("CPE-Software mapping failed", "error", err)
				}
			case <-ctx.Done():
				logs.Sys.Info("Shutting down CPE-Software Mapper...")
				return
			}
		}
	}()
}

// ------------------------------------------------------------------------------------------------------------
//                                           CVE SPECIFIC FUNCTIONS
// ------------------------------------------------------------------------------------------------------------

type NVDCVEResponse struct {
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

type CVEItem struct {
	CVE CVEDataDetail `json:"cve"`
}

type CVEDataDetail struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	Descriptions   []Description   `json:"descriptions"`
	Metrics        CVEMetrics      `json:"metrics"`
	Configurations []Configuration `json:"configurations"`
}

type Description struct {
	Value string `json:"value"`
}

type CVEMetrics struct {
	CvssMetricV31 []CvssV31 `json:"cvssMetricV31"`
}

type CvssV31 struct {
	CvssData CvssData `json:"cvssData"`
}

type CvssData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	CpeMatches []CpeMatch `json:"cpeMatch"`
}

type CpeMatch struct {
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
}

func getCVEStartTime(db *sql.DB) string {
	var lastSync string
	err := db.QueryRow("SELECT last_sync_timestamp FROM sync_metadata WHERE key = 'nvd_cve'").Scan(&lastSync)

	if err == sql.ErrNoRows || lastSync == "" {
		logs.Sys.Info("No CVE sync history found. Seeding from 2002.")
		start := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		return FormatNVDTime(start)
	} else if err != nil {
		logs.DB.Error("Database error checking CVE sync metadata", "error", err)
		return FormatNVDTime(time.Now().AddDate(0, 0, -120))
	}
	return lastSync
}

func SyncCVE(ctx context.Context, db *sql.DB, apiKey string) error {
	lastSyncStr := getCVEStartTime(db)
	lastSyncTime, _ := time.Parse("2006-01-02T15:04:05.000", lastSyncStr)
	now := time.Now()

	for lastSyncTime.Before(now) {
		windowEnd := lastSyncTime.AddDate(0, 0, 120)
		if windowEnd.After(now) {
			windowEnd = now
		}
		if !lastSyncTime.Before(windowEnd) {
			break
		}

		startIndex := 0
		resultsPerPage := 2000
		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("interrupted")
			default:
			}

			params := url.Values{}
			params.Add("resultsPerPage", strconv.Itoa(resultsPerPage))
			params.Add("startIndex", strconv.Itoa(startIndex))
			params.Add("lastModStartDate", FormatNVDTime(lastSyncTime))
			params.Add("lastModEndDate", FormatNVDTime(windowEnd))

			req, _ := http.NewRequestWithContext(ctx, "GET", internal.AppConfig.NVD.CveURL+"?"+params.Encode(), nil)
			req.Header.Set("apiKey", apiKey)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}

			var data NVDCVEResponse
			json.NewDecoder(resp.Body).Decode(&data)
			resp.Body.Close()

			if len(data.Vulnerabilities) > 0 {
				processCVEBatch(db, data.Vulnerabilities)
			}

			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			time.Sleep(6 * time.Second)
		}
		db.Exec("INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cve', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))
		lastSyncTime = windowEnd
	}
	return nil
}

func processCVEBatch(db *sql.DB, items []CVEItem) {
	tx, _ := db.Begin()
	defer tx.Rollback()
	for _, item := range items {
		cve := item.CVE
		var score float64
		var severity string
		if len(cve.Metrics.CvssMetricV31) > 0 {
			score = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}
		_, _ = tx.Exec(`INSERT INTO vulnerabilities (cve_id, description, severity, cvss_score, published) VALUES (?, ?, ?, ?, ?) ON CONFLICT(cve_id) DO UPDATE SET cvss_score=excluded.cvss_score`, cve.ID, cve.Descriptions[0].Value, severity, score, cve.Published)

		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CpeMatches {
					_, _ = tx.Exec(`INSERT INTO software_vulnerabilities (cve_id, cpe_uri, version_start, version_end) VALUES (?, ?, ?, ?)`, cve.ID, match.Criteria, match.VersionStartIncluding, match.VersionEndIncluding)
				}
			}
		}
	}
	tx.Commit()
}

func StartCVEUpdater(ctx context.Context) {
	db := CVE_Database
	apikey := internal.AppConfig.NVD.APIKey
	ticker := time.NewTicker(12 * time.Hour)

	if apikey == "" {
		logs.Sys.Error("NVD API Key missing. CVE Sync disabled.")
		return
	}

	go func() {
		defer ticker.Stop()
		logs.Sys.Info("CVE Updater background worker started.")

		// Initial sync on startup
		if err := SyncCVE(ctx, db, apikey); err != nil {
			logs.Sys.Error("Initial CVE sync failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				logs.Sys.Info("Starting scheduled 12-hour CVE sync...")
				if err := SyncCVE(ctx, db, apikey); err != nil {
					logs.Sys.Error("CVE sync failed, scheduling 1hr retry", "error", err)

					// Retry Logic
					select {
					case <-time.After(1 * time.Hour):
						logs.Sys.Info("Executing 1hr retry for CVE sync...")
						if err := SyncCVE(ctx, db, apikey); err != nil {
							logs.Sys.Error("CVE sync retry failed. Will wait for next 12hr cycle", "error", err)
						}
					case <-ctx.Done():
						logs.Sys.Info("CVE Updater stopped during retry wait.")
						return
					}
				}
			case <-ctx.Done():
				logs.Sys.Info("CVE Updater background worker stopped.")
				return
			}
		}
	}()
}

func versionCompare(v1, v2 string) int {
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	for i := 0; i < len(parts1) || i < len(parts2); i++ {
		var n1, n2 int
		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}
		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}
	return 0
}

func isVulnerable(swVersion string, vStart, vEnd sql.NullString) bool {
	if !vStart.Valid && !vEnd.Valid {
		return true
	}
	inStartRange := !vStart.Valid || versionCompare(swVersion, vStart.String) >= 0
	inEndRange := !vEnd.Valid || versionCompare(swVersion, vEnd.String) < 0
	return inStartRange && inEndRange
}

// MapCVEs correlates both Software and Operating Systems to CVE URIs
func MapCVEs(mainDB *sql.DB, vulnDB *sql.DB) {
	logs.Sys.Info("Starting vulnerability correlation...")

	// Correlate Software Vulnerabilities
	rows, _ := mainDB.Query(`
		SELECT asw.agent_id, s.id, s.cpe_uri, s.version 
		FROM agent_software asw 
		JOIN software s ON asw.software_id = s.id 
		WHERE s.cpe_uri IS NOT NULL AND s.cpe_uri != ''`)
	defer rows.Close()
	for rows.Next() {
		var agentID string
		var softwareID int
		var cpeURI, swVersion string
		rows.Scan(&agentID, &softwareID, &cpeURI, &swVersion)
		correlate(mainDB, vulnDB, agentID, &softwareID, cpeURI, swVersion, "application")
	}

	// Correlate OS Vulnerabilities
	osRows, _ := mainDB.Query(`
		SELECT agent_id, os_cpe_uri, os_version 
		FROM agents 
		WHERE os_cpe_uri IS NOT NULL AND os_cpe_uri != ''`)
	defer osRows.Close()
	for osRows.Next() {
		var agentID, cpeURI, osVersion string
		osRows.Scan(&agentID, &cpeURI, &osVersion)
		correlate(mainDB, vulnDB, agentID, nil, cpeURI, osVersion, "os")
	}
}

// correlate handles the actual matching logic and DB insertion
func correlate(mainDB, vulnDB *sql.DB, agentID string, swID *int, cpeURI, version, targetType string) {
	// Query the vulnerability DB for any CVEs matching this CPE
	vRows, err := vulnDB.Query(`
		SELECT sv.cve_id, sv.version_start, sv.version_end, v.severity, v.cvss_score 
		FROM software_vulnerabilities sv 
		JOIN vulnerabilities v ON sv.cve_id = v.cve_id 
		WHERE sv.cpe_uri = ?`, cpeURI)
	if err != nil {
		return
	}
	defer vRows.Close()

	for vRows.Next() {
		var cveID, severity string
		var vStart, vEnd sql.NullString
		var score float64
		vRows.Scan(&cveID, &vStart, &vEnd, &severity, &score)

		// Check if the specific version reported by the agent falls within the CVE's range
		if isVulnerable(version, vStart, vEnd) {
			// Insert into discovered_vulnerabilities
			_, err := mainDB.Exec(`
				INSERT OR IGNORE INTO discovered_vulnerabilities 
				(agent_id, target_type, software_id, cpe_uri, cve_id, severity, cvss_score) 
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				agentID, targetType, swID, cpeURI, cveID, severity, score)

			if err == nil {
				logs.Audit.Warn("Vulnerability Alert",
					"agent", agentID,
					"type", targetType,
					"cve", cveID,
					"severity", severity)
			}
		}
	}
}

func StartCVEMapper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				MapCVEs(Main_Database, CVE_Database)
			case <-ctx.Done():
				return
			}
		}
	}()
}
