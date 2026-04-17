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
//                                          CPE SPECIFIC FUNCTIONS
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
	// Using QuerySingleRow (which uses the handle provided, usually CPE_Database)
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
	if len(products) == 0 {
		return
	}

	// Acquire the PriorityLock - Other goroutines (Enrollment) will wait here
	PriorityLock.Lock()

	// Wrap the transaction in a closure to ensure it's 100% finished
	// before we release the Lock and before the function returns.
	err := func() error {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		stmt, err := tx.Prepare(`INSERT INTO cpe_dictionary (cpe_uri, vendor, product, version, deprecated) 
            VALUES (?, ?, ?, ?, ?) ON CONFLICT(cpe_uri) DO UPDATE SET deprecated=excluded.deprecated`)
		if err != nil {
			return err
		}
		defer stmt.Close()

		for _, p := range products {
			parts := strings.Split(p.CPE.CpeName, ":")
			if len(parts) < 6 {
				continue
			}
			// Executing directly on the prepared statement within the transaction
			if _, err := stmt.Exec(p.CPE.CpeName, parts[3], parts[4], parts[5], p.CPE.Deprecated); err != nil {
				logs.DB.Error("Batch exec error", "error", err)
			}
		}
		return tx.Commit()
	}()

	// Release the lock IMMEDIATELY after the transaction is committed
	PriorityLock.Unlock()

	if err != nil {
		logs.DB.Error("CPE Batch failed", "error", err)
	}

	// Yield AFTER releasing the lock to let Agents talk to the DB
	time.Sleep(50 * time.Millisecond)
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
				// Critical: Give the CPU and DB a break to allow Agent API traffic
				time.Sleep(100 * time.Millisecond)
			}

			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			time.Sleep(1 * time.Second) // Respect NVD API rate limits
		}

		// Update metadata using WriteQuery
		WriteQuery(db, "INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cpe', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))

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

	WG.Add(1)

	go func() {
		defer WG.Done()
		defer ticker.Stop()
		logs.Sys.Info("CPE Updater background worker started.")

		if err := SyncCPE(ctx, db, apikey); err != nil {
			logs.Sys.Error("Initial CPE sync failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				logs.Sys.Info("Starting scheduled CPE sync...")
				if err := SyncCPE(ctx, db, apikey); err != nil {
					logs.Sys.Error("CPE sync failed, scheduling 1hr retry", "error", err)
					select {
					case <-time.After(1 * time.Hour):
						logs.Sys.Info("Retrying CPE sync...")
						SyncCPE(ctx, db, apikey)
					case <-ctx.Done():
						return
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// MapCPEs correlates both Software and Operating Systems to CPE URIs
func MapCPEs() error {
	type swUpdate struct {
		id  int
		cpe string
	}
	type agentUpdate struct {
		id  string
		cpe string
	}

	var swTasks []swUpdate
	var agentTasks []agentUpdate

	// --- 1. COLLECT SOFTWARE TASKS (Use READ pool) ---
	swRows, err := ReadQuery(Main_Read_Database, `SELECT id, name, version, vendor FROM software WHERE cpe_uri IS NULL OR cpe_uri = ''`)
	if err == nil {
		for swRows.Next() {
			var id int
			var name, version, vendor string
			if err := swRows.Scan(&id, &name, &version, &vendor); err == nil {
				var cpeURI string
				query := `SELECT cpe_uri FROM cpe_dictionary 
                          WHERE (vendor LIKE ? OR ? LIKE '%' || vendor || '%') 
                          AND (product LIKE ? OR ? LIKE '%' || product || '%') 
                          AND (version = ? OR version = '*') 
                          ORDER BY version DESC, deprecated ASC LIMIT 1`

				// CPE_Database is its own file, so it's safe to query directly
				if err := QuerySingleRow(CPE_Database, query, []any{"%" + vendor + "%", vendor, "%" + name + "%", name, version}, &cpeURI); err == nil && cpeURI != "" {
					swTasks = append(swTasks, swUpdate{id: id, cpe: cpeURI})
				}
			}
		}
		swRows.Close()
	}

	// --- 2. COLLECT OS TASKS (Use READ pool) ---
	agentRows, err := ReadQuery(Main_Read_Database, `SELECT agent_id, os, os_version FROM agents WHERE os_cpe_uri IS NULL OR os_cpe_uri = ''`)
	if err == nil {
		for agentRows.Next() {
			var aid, osName, osVer string
			if err := agentRows.Scan(&aid, &osName, &osVer); err == nil {
				var cpeURI string
				query := `SELECT cpe_uri FROM cpe_dictionary 
                          WHERE cpe_uri LIKE 'cpe:2.3:o:%' 
                          AND (product LIKE ? OR ? LIKE '%' || product || '%') 
                          AND (version = ? OR version = '*') 
                          ORDER BY version DESC LIMIT 1`

				if err := QuerySingleRow(CPE_Database, query, []any{"%" + osName + "%", osName, osVer}, &cpeURI); err == nil && cpeURI != "" {
					agentTasks = append(agentTasks, agentUpdate{id: aid, cpe: cpeURI})
				}
			}
		}
		agentRows.Close()
	}

	// --- 3. EXECUTE UPDATES (Use WRITE pool) ---
	for _, task := range swTasks {
		PriorityLock.Lock()
		WriteQuery(Main_Database, "UPDATE software SET cpe_uri = ? WHERE id = ?", task.cpe, task.id)
		PriorityLock.Unlock()
		time.Sleep(10 * time.Millisecond) // Yield for Agents
	}

	for _, task := range agentTasks {
		PriorityLock.Lock()
		WriteQuery(Main_Database, "UPDATE agents SET os_cpe_uri = ? WHERE agent_id = ?", task.cpe, task.id)
		PriorityLock.Unlock()
		time.Sleep(10 * time.Millisecond) // Yield for Agents
	}

	return nil
}

func StartCPEMapper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	WG.Add(1)
	go func() {
		defer ticker.Stop()
		defer WG.Done()
		time.Sleep(10 * time.Second)
		logs.Sys.Info("CPE-Software Mapper background worker started.")

		MapCPEs()

		for {
			select {
			case <-ticker.C:
				MapCPEs()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ------------------------------------------------------------------------------------------------------------
//                                          CVE SPECIFIC FUNCTIONS
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
		WriteQuery(db, "INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cve', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))
		lastSyncTime = windowEnd
	}
	return nil
}

func processCVEBatch(db *sql.DB, items []CVEItem) {
	PriorityLock.Lock()
	defer PriorityLock.Unlock()

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

	WG.Add(1)
	go func() {
		defer WG.Done()
		defer ticker.Stop()
		time.Sleep(15 * time.Second)
		logs.Sys.Info("CVE Updater background worker started.")

		SyncCVE(ctx, db, apikey)

		for {
			select {
			case <-ticker.C:
				SyncCVE(ctx, db, apikey)
			case <-ctx.Done():
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

func MapCVEs() {
	type vulnTask struct {
		agentID, cpeURI, version, targetType string
		swID                                 *int
	}
	var tasks []vulnTask

	// 1. READ PHASE (Collect tasks from Main_Read_Database)
	rows, _ := ReadQuery(Main_Read_Database, `SELECT asw.agent_id, s.id, s.cpe_uri, s.version FROM agent_software asw 
                               JOIN software s ON asw.software_id = s.id WHERE s.cpe_uri != ''`)
	if rows != nil {
		for rows.Next() {
			var aid string
			var sid int
			var cpe, ver string
			rows.Scan(&aid, &sid, &cpe, &ver)
			tasks = append(tasks, vulnTask{aid, cpe, ver, "application", &sid})
		}
		rows.Close()
	}

	// 2. CORRELATE PHASE
	for _, t := range tasks {
		correlate(t.agentID, t.swID, t.cpeURI, t.version, t.targetType)
		time.Sleep(20 * time.Millisecond) // Yield for Agents
	}
}

func correlate(agentID string, swID *int, cpeURI, version, targetType string) {
	vRows, err := CVE_Database.Query(`SELECT sv.cve_id, sv.version_start, sv.version_end, v.severity, v.cvss_score 
                                 FROM software_vulnerabilities sv JOIN vulnerabilities v ON sv.cve_id = v.cve_id 
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

		if isVulnerable(version, vStart, vEnd) {
			// WriteQuery handles its own lock. No manual Lock/Unlock here.
			WriteQuery(Main_Database, `INSERT OR IGNORE INTO discovered_vulnerabilities 
                (agent_id, target_type, software_id, cpe_uri, cve_id, severity, cvss_score, detected_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
				agentID, targetType, swID, cpeURI, cveID, severity, score)
		}
	}
}

func StartCVEMapper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)

	WG.Add(1)
	go func() {
		defer WG.Done()
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				MapCVEs()
			case <-ctx.Done():
				return
			}
		}
	}()
}
