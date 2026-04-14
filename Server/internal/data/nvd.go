// provides functions to handle cloning cpe data and querying cve entries in NIST NVD

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
	"Watchtower_EDR/server/internal/logs" // Import the tiered logging package
)

// FormatNVDTime converts a Go time object to the specific string
// format the NVD API requires (ISO 8601 with milliseconds).
func FormatNVDTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000")
}

// ------------------------------------------------------------------------------------------------------------
//                                           CPE SPECIFIC FUNCTIONS
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

	logs.Sys.Info("Resuming CPE sync from last recorded timestamp", "timestamp", lastSync)
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
        INSERT INTO cpe_dictionary (
            cpe_uri, vendor, product, version, deprecated
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(cpe_uri) DO UPDATE SET
            vendor=excluded.vendor,
            product=excluded.product,
            version=excluded.version,
            deprecated=excluded.deprecated`)
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

		_, err := stmt.Exec(
			p.CPE.CpeName,
			parts[3], // vendor
			parts[4], // product
			parts[5], // version
			p.CPE.Deprecated,
		)
		if err != nil {
			logs.DB.Warn("Failed to insert CPE record", "uri", p.CPE.CpeName, "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		logs.DB.Error("Failed to commit CPE batch transaction", "error", err)
	} else {
		logs.Sys.Debug("Successfully processed CPE batch", "count", len(products))
	}
}

func updateCPESyncMetadata(db *sql.DB, timestamp string, count int) {
	_, err := db.Exec(`
        INSERT INTO sync_metadata (key, last_sync_timestamp, record_count) 
        VALUES ('nvd_cpe', ?, ?)
        ON CONFLICT(key) DO UPDATE SET 
            last_sync_timestamp = excluded.last_sync_timestamp,
            record_count = excluded.record_count`,
		timestamp, count)
	if err != nil {
		logs.DB.Error("Failed to update CPE sync metadata", "error", err)
	}
}

func SyncCPE(ctx context.Context, db *sql.DB, apiKey string) error {
	lastSyncStr := getCPEStartTime(db)
	lastSyncTime, err := time.Parse("2006-01-02T15:04:05.000", lastSyncStr)
	if err != nil {
		logs.Sys.Error("Failed to parse last CPE sync time", "error", err)
		lastSyncTime = time.Now().AddDate(0, 0, -120)
	}

	now := time.Now()
	for lastSyncTime.Before(now) {
		windowEnd := lastSyncTime.AddDate(0, 0, 120)
		if windowEnd.After(now) {
			windowEnd = now
		}

		if !lastSyncTime.Before(windowEnd) {
			break
		}

		logs.Sys.Info("Syncing CPE 120-day window", "start", FormatNVDTime(lastSyncTime), "end", FormatNVDTime(windowEnd))
		startIndex := 0
		resultsPerPage := 5000

		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("sync interrupted by shutdown")
			default:
			}

			params := url.Values{}
			params.Add("resultsPerPage", strconv.Itoa(resultsPerPage))
			params.Add("startIndex", strconv.Itoa(startIndex))
			params.Add("lastModStartDate", FormatNVDTime(lastSyncTime))
			params.Add("lastModEndDate", FormatNVDTime(windowEnd))
			fullURL := internal.AppConfig.NVD.CpeURL + "?" + params.Encode()

			req, _ := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
			req.Header.Set("apiKey", apiKey)
			req.Header.Set("User-Agent", "WatchtowerEDR-CPE-Updater")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("network error during CPE sync: %w", err)
			}

			if resp.StatusCode == 429 || resp.StatusCode == 503 {
				resp.Body.Close()
				logs.Sys.Warn("NVD API is throttled or down. Sleeping 30s...", "status", resp.Status)
				time.Sleep(30 * time.Second)
				return fmt.Errorf("server busy: %s", resp.Status)
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("NVD API returned error: %s", resp.Status)
			}

			var data CPEResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				resp.Body.Close()
				return fmt.Errorf("failed to decode NVD JSON: %w", err)
			}
			resp.Body.Close()

			if len(data.Products) > 0 {
				processBatch(db, data.Products)
			}

			logs.Sys.Debug("CPE Progress", "total", data.TotalResults, "index", startIndex)
			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			time.Sleep(1 * time.Second)
		}

		updateCPESyncMetadata(db, FormatNVDTime(windowEnd), 0)
		lastSyncTime = windowEnd
		time.Sleep(2 * time.Second)
	}
	logs.Sys.Info("CPE Dictionary is fully up to date")
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

func MapCPEs() error {
	rows, err := ReadQuery(Main_Database, `
        SELECT id, name, version, vendor 
        FROM software 
        WHERE cpe_uri IS NULL OR cpe_uri = ''`)
	if err != nil {
		logs.DB.Error("failed to fetch unmatched software", "error", err)
		return fmt.Errorf("failed to fetch unmatched software: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name, version, vendor string
		if err := rows.Scan(&id, &name, &version, &vendor); err != nil {
			logs.DB.Error("Failed to scan software row for CPE mapping", "error", err)
			continue
		}

		name = strings.TrimSpace(name)
		vendor = strings.TrimSpace(vendor)
		var cpeURI string

		// TIER 1: EXACT MATCH
		queryExact := `SELECT cpe_uri FROM cpe_dictionary WHERE (vendor LIKE ? OR ? LIKE '%' || vendor || '%') AND (product LIKE ? OR ? LIKE '%' || product || '%') AND version = ? ORDER BY deprecated ASC LIMIT 1`
		argsExact := []any{"%" + vendor + "%", vendor, "%" + name + "%", name, version}
		err := QuerySingleRow(CPE_Database, queryExact, argsExact, &cpeURI)

		// TIER 2: WILDCARD
		if err != nil && err == sql.ErrNoRows {
			queryWildcard := `SELECT cpe_uri FROM cpe_dictionary WHERE (vendor LIKE ? OR ? LIKE '%' || vendor || '%') AND (product LIKE ? OR ? LIKE '%' || product || '%') AND version = '*' ORDER BY deprecated ASC LIMIT 1`
			argsWildcard := []any{"%" + vendor + "%", vendor, "%" + name + "%", name}
			err = QuerySingleRow(CPE_Database, queryWildcard, argsWildcard, &cpeURI)
		}

		switch err {
		case nil:
			err = WriteQuery(Main_Database, "UPDATE software SET cpe_uri = ? WHERE id = ?", cpeURI, id)
			if err != nil {
				logs.DB.Error("Failed to update software table with CPE", "id", id, "error", err)
			} else {
				logs.Sys.Debug("Successfully matched software to CPE", "name", name, "cpe", cpeURI)
			}
		case sql.ErrNoRows:
			// No match found
		default:
			logs.DB.Error("Database error during CPE mapping lookup", "error", err)
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
//                                           CVE SPECIFIC FUNCTIONS
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

func processCVEBatch(db *sql.DB, items []CVEItem) {
	tx, err := db.Begin()
	if err != nil {
		logs.DB.Error("Failed to begin CVE transaction", "error", err)
		return
	}
	defer tx.Rollback()

	for _, item := range items {
		cve := item.CVE
		var score float64
		var severity string
		if len(cve.Metrics.CvssMetricV31) > 0 {
			score = cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
			severity = cve.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}

		_, err = tx.Exec(`
            INSERT INTO vulnerabilities (cve_id, description, severity, cvss_score, published) 
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET 
                description=excluded.description, 
                severity=excluded.severity, 
                cvss_score=excluded.cvss_score`,
			cve.ID, cve.Descriptions[0].Value, severity, score, cve.Published)

		if err != nil {
			logs.DB.Warn("Failed to insert CVE record", "id", cve.ID, "error", err)
			continue
		}

		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CpeMatches {
					_, _ = tx.Exec(`
                        INSERT INTO software_vulnerabilities (cve_id, cpe_uri, version_start, version_end) 
                        VALUES (?, ?, ?, ?)`,
						cve.ID, match.Criteria, match.VersionStartIncluding, match.VersionEndIncluding)
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		logs.DB.Error("Failed to commit CVE batch transaction", "error", err)
	}
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

		logs.Sys.Info("Syncing CVE 120-day window", "start", FormatNVDTime(lastSyncTime), "end", FormatNVDTime(windowEnd))
		startIndex := 0
		resultsPerPage := 2000

		for {
			select {
			case <-ctx.Done():
				return fmt.Errorf("CVE sync interrupted")
			default:
			}

			params := url.Values{}
			params.Add("resultsPerPage", strconv.Itoa(resultsPerPage))
			params.Add("startIndex", strconv.Itoa(startIndex))
			params.Add("lastModStartDate", FormatNVDTime(lastSyncTime))
			params.Add("lastModEndDate", FormatNVDTime(windowEnd))

			fullURL := internal.AppConfig.NVD.CveURL + "?" + params.Encode()
			req, _ := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
			req.Header.Set("apiKey", apiKey)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}

			if resp.StatusCode == 429 || resp.StatusCode == 503 {
				resp.Body.Close()
				logs.Sys.Warn("NVD API throttled during CVE sync. Sleeping 30s...")
				time.Sleep(30 * time.Second)
				return fmt.Errorf("server busy: %s", resp.Status)
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("NVD CVE API error: %s", resp.Status)
			}

			var data NVDCVEResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				resp.Body.Close()
				return err
			}
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

		_, err := db.Exec("INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cve', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))
		if err != nil {
			logs.DB.Error("Failed to update CVE sync metadata", "error", err)
		}
		lastSyncTime = windowEnd
	}
	return nil
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

func MapCVEs(mainDB *sql.DB, vulnDB *sql.DB) {
	logs.Sys.Info("Starting vulnerability correlation...")

	rows, err := mainDB.Query(`
        SELECT asw.agent_id, s.id, s.cpe_uri, s.version 
        FROM agent_software asw
        JOIN software s ON asw.software_id = s.id
        WHERE s.cpe_uri IS NOT NULL`)
	if err != nil {
		logs.DB.Error("Failed to query software for CVE correlation", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID string
		var softwareID int
		var cpeURI, swVersion string
		rows.Scan(&agentID, &softwareID, &cpeURI, &swVersion)

		vRows, err := vulnDB.Query(`
            SELECT sv.cve_id, sv.version_start, sv.version_end, v.severity, v.cvss_score 
            FROM software_vulnerabilities sv
            JOIN vulnerabilities v ON sv.cve_id = v.cve_id
            WHERE sv.cpe_uri = ?`, cpeURI)

		if err != nil {
			logs.DB.Error("Failed to query vulnerabilities for CPE", "cpe", cpeURI, "error", err)
			continue
		}

		for vRows.Next() {
			var cveID, severity string
			var vStart, vEnd sql.NullString
			var score float64
			vRows.Scan(&cveID, &vStart, &vEnd, &severity, &score)

			isVulnerable := false
			if !vStart.Valid && !vEnd.Valid {
				isVulnerable = true
			} else {
				inStartRange := !vStart.Valid || versionCompare(swVersion, vStart.String) >= 0
				inEndRange := !vEnd.Valid || versionCompare(swVersion, vEnd.String) < 0
				if inStartRange && inEndRange {
					isVulnerable = true
				}
			}

			if isVulnerable {
				_, err = mainDB.Exec(`
                    INSERT OR IGNORE INTO discovered_vulnerabilities 
                    (agent_id, software_id, cve_id, severity, cvss_score) 
                    VALUES (?, ?, ?, ?, ?)`,
					agentID, softwareID, cveID, severity, score)

				if err == nil {
					// ROUTED TO AUDIT LOGGER: This is a significant security event
					logs.Audit.Warn("Vulnerability Correlation Alert",
						"agent", agentID,
						"cve", cveID,
						"version", swVersion,
						"severity", severity)
				} else {
					logs.DB.Error("Failed to record discovered vulnerability", "error", err)
				}
			}
		}
		vRows.Close()
	}
}

func StartCVEMapper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)
	mainDB := Main_Database
	vulnDB := CVE_Database
	go func() {
		defer ticker.Stop()
		logs.Sys.Info("CVE Correlation Mapper worker started.")
		MapCVEs(mainDB, vulnDB)
		for {
			select {
			case <-ticker.C:
				MapCVEs(mainDB, vulnDB)
			case <-ctx.Done():
				logs.Sys.Info("Shutting down CVE Correlation Mapper...")
				return
			}
		}
	}()
}
