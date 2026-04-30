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
	"sync"
	"time"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/logs"
)

// FormatNVDTime converts a Go time object to the specific string format the NVD API requires.
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

func getCPEStartTime() string {
	var lastSync string
	// Use the Read database for the check
	err := QuerySingleRow(CPE_Read_Database, "SELECT last_sync_timestamp FROM sync_metadata WHERE key = 'nvd_cpe'", nil, &lastSync)

	if err == sql.ErrNoRows || lastSync == "" {
		logs.Sync.Info("No CPE sync history found. Initializing first-time seed from 2002.")
		start := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		return FormatNVDTime(start)
	} else if err != nil {
		logs.Sync.Error("Database error checking CPE sync metadata", "error", err)
		return FormatNVDTime(time.Now().AddDate(0, 0, -120))
	}
	return lastSync
}

func processBatch(products []CPEProduct) {
	if len(products) == 0 {
		return
	}

	PriorityLock.Lock()
	err := func() error {
		tx, err := CPE_Database.Begin()
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
			if _, err := stmt.Exec(p.CPE.CpeName, parts[3], parts[4], parts[5], p.CPE.Deprecated); err != nil {
				logs.Sync.Error("Batch exec error", "error", err)
			}
		}
		return tx.Commit()
	}()
	PriorityLock.Unlock()

	if err != nil {
		logs.Sync.Error("CPE Batch failed", "error", err)
	}
	time.Sleep(50 * time.Millisecond)
}

// Updates the local CPE dictionary with CPE data from NIST going back to the last update time (or 2006 by default to reseed the database)
func SyncCPE(ctx context.Context, apiKey string, engine *SearchEngine) error {
	lastSyncStr := getCPEStartTime()
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
				// Log network error and break inner loop to try the next window
				logs.Sync.Error("CPE Sync: Network error for window", "start", lastSyncTime, "error", err)
				break
			}

			if resp.StatusCode != http.StatusOK {
				logs.Sync.Error("CPE Sync: NVD API returned error", "status", resp.Status)
				resp.Body.Close()
				break
			}

			var data CPEResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				resp.Body.Close()
				return err
			}
			resp.Body.Close()

			// Batch write the products to database and perform search engine indexing
			if len(data.Products) > 0 {
				// 1. Save to SQLite (is_indexed defaults to 0)
				processBatch(data.Products)

				// 2. Attempt Incremental Indexing
				if err := UpdateIndexBatch(engine, data.Products); err != nil {
					// Graceful failure: Log error but do NOT stop the sync.
					// The "Safety Net" worker will pick these up later.
					logs.Sync.Error("CPE Sync: Indexing failed for batch; items marked for retry", "error", err)
				} else {
					// 3. Success: Mark these specific items as indexed in SQL
					if err := MarkItemsAsIndexed(data.Products); err != nil {
						logs.Sync.Error("CPE Sync: Failed to update indexed status in DB", "error", err)
					}
				}

				time.Sleep(100 * time.Millisecond)
			}

			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			// Rate limiting respect for NIST API
			time.Sleep(1 * time.Second)
		}

		// Update sync metadata so we don't re-fetch this window next time
		WriteQuery(CPE_Database, "INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cpe', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))
		lastSyncTime = windowEnd
	}

	// Final step: Run the Repair Worker once to catch any batches that failed during this sync
	logs.Sync.Info("CPE Sync finished. Running final index repair safety check...")
	RunIndexRepair(ctx, engine)

	return nil
}

func StartCPEUpdater(ctx context.Context, engine *SearchEngine) {
	apikey := internal.AppConfig.NVD.APIKey
	ticker := time.NewTicker(12 * time.Hour)

	if apikey == "" || apikey == "YOUR_API_KEY_HERE" {
		logs.Sync.Error("NVD API Key missing. CPE Sync disabled.")
		return
	}

	WG.Add(1)
	go func() {
		defer WG.Done()
		defer ticker.Stop()
		logs.Sync.Info("CPE Updater background worker started.")

		// Perform initial sync on startup
		if err := SyncCPE(ctx, apikey, engine); err != nil {
			logs.Sync.Error("Initial CPE sync failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				logs.Sys.Info("Starting scheduled CPE sync...")
				if err := SyncCPE(ctx, apikey, engine); err != nil {
					logs.Sync.Error("CPE sync failed, scheduling 1hr retry", "error", err)
					select {
					case <-time.After(1 * time.Hour):
						SyncCPE(ctx, apikey, engine)
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
	LastModified   string          `json:"lastModified"` // New: Required for delta-syncing
	Descriptions   []Description   `json:"descriptions"`
	Metrics        CVEMetrics      `json:"metrics"`
	Configurations []Configuration `json:"configurations"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type CVEMetrics struct {
	// NVD API v2.0 uses "cvssMetricV31" for modern CVEs
	CvssMetricV31 []CvssV31 `json:"cvssMetricV31"`
}

type CvssV31 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CvssData            CvssData `json:"cvssData"`
	ExploitabilityScore float64  `json:"exploitabilityScore"` // New: Mapping easy-of-use
	ImpactScore         float64  `json:"impact_score"`        // New: Mapping total damage
}

type CvssData struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Operator   string     `json:"operator"`
	Negate     bool       `json:"negate"`
	CpeMatches []CpeMatch `json:"cpeMatch"`
}

type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	// Note: NVD also occasionally uses VersionStartExcluding / VersionEndExcluding
	// You may want to add those if you need 100% edge-case coverage.
}

func getCVEStartTime() string {
	var lastSync string
	err := QuerySingleRow(CVE_Read_Database, "SELECT last_sync_timestamp FROM sync_metadata WHERE key = 'nvd_cve'", nil, &lastSync)

	if err == sql.ErrNoRows || lastSync == "" {
		logs.Sync.Info("No CVE sync history found. Seeding from 2002.")
		start := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		return FormatNVDTime(start)
	} else if err != nil {
		logs.Sync.Error("Database error checking CVE sync metadata", "error", err)
		return FormatNVDTime(time.Now().AddDate(0, 0, -120))
	}
	return lastSync
}

func SyncCVE(ctx context.Context, apiKey string) error {
	lastSyncStr := getCVEStartTime()
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
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				resp.Body.Close()
				return err
			}
			resp.Body.Close()

			if len(data.Vulnerabilities) > 0 {
				processCVEBatch(data.Vulnerabilities)
			}

			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			time.Sleep(6 * time.Second)
		}
		WriteQuery(CVE_Database, "INSERT INTO sync_metadata (key, last_sync_timestamp) VALUES ('nvd_cve', ?) ON CONFLICT(key) DO UPDATE SET last_sync_timestamp=excluded.last_sync_timestamp", FormatNVDTime(windowEnd))
		lastSyncTime = windowEnd
	}
	return nil
}

func processCVEBatch(items []CVEItem) {
	PriorityLock.Lock()
	defer PriorityLock.Unlock()

	tx, _ := CVE_Database.Begin()
	defer tx.Rollback()

	for _, item := range items {
		cve := item.CVE
		var score, exploitScore, impactScore float64
		var severity string

		// Prioritize CVSS V3.1 metrics
		if len(cve.Metrics.CvssMetricV31) > 0 {
			m := cve.Metrics.CvssMetricV31[0]
			score = m.CvssData.BaseScore
			severity = m.CvssData.BaseSeverity
			exploitScore = m.ExploitabilityScore
			impactScore = m.ImpactScore
		}

		description := ""
		if len(cve.Descriptions) > 0 {
			description = cve.Descriptions[0].Value
		}

		// 1. Insert/Update Core Vulnerability Data
		_, _ = tx.Exec(`
            INSERT INTO vulnerabilities (
                cve_id, description, severity, cvss_score, 
                exploit_score, impact_score, published, last_modified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?) 
            ON CONFLICT(cve_id) DO UPDATE SET 
                cvss_score=excluded.cvss_score,
                exploit_score=excluded.exploit_score,
                impact_score=excluded.impact_score,
                last_modified=excluded.last_modified`,
			cve.ID, description, severity, score,
			exploitScore, impactScore, cve.Published, cve.LastModified)

		// 2. Map CPE configurations
		for _, config := range cve.Configurations {
			for _, node := range config.Nodes {
				for _, match := range node.CpeMatches {
					_, _ = tx.Exec(`
                        INSERT OR IGNORE INTO software_vulnerabilities 
                        (cve_id, cpe_uri, version_start, version_end) 
                        VALUES (?, ?, ?, ?)`,
						cve.ID, match.Criteria, match.VersionStartIncluding, match.VersionEndIncluding)
				}
			}
		}
	}
	tx.Commit()
}

func StartCVEUpdater(ctx context.Context) {
	apikey := internal.AppConfig.NVD.APIKey
	ticker := time.NewTicker(12 * time.Hour)

	if apikey == "" {
		logs.Sync.Error("NVD API Key missing. CVE Sync disabled.")
		return
	}

	WG.Add(1)
	go func() {
		defer WG.Done()
		defer ticker.Stop()
		time.Sleep(4 * time.Second)
		logs.Sync.Info("CVE Updater background worker started.")

		SyncCVE(ctx, apikey)

		for {
			select {
			case <-ticker.C:
				SyncCVE(ctx, apikey)
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

var (
	ScanMutex  sync.Mutex
	IsScanning bool
)

// Collects software and operating system information and checks it against vulnerability entries in cve database
func MapCVEs(ctx context.Context) {

	// Ensure we release the lock even if the function panics
	defer func() {
		logs.Map.Info("Vulnerability mapping process ended")
	}()

	logs.Map.Info("Starting vulnerability mapping process...")

	// --- PHASE 1: UNIQUE SOFTWARE SCAN ---
	swRows, _ := ReadQuery(Main_Read_Database, `
        SELECT id, cpe_uri, version 
        FROM software 
        WHERE cpe_uri != ''`)

	if swRows != nil {
		defer swRows.Close()
	SoftwareLoop:
		for swRows.Next() {
			select {
			case <-ctx.Done():
				logs.Map.Warn("Software scan interrupted by context cancellation")
				break SoftwareLoop // Exit loop, don't return
			default:
			}

			var sid int
			var cpe, ver string
			if err := swRows.Scan(&sid, &cpe, &ver); err == nil {
				Correlate(nil, &sid, cpe, ver, "application")
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	// --- PHASE 2: INDIVIDUAL OS SCAN ---
	osRows, _ := ReadQuery(Main_Read_Database, `
        SELECT agent_id, os_cpe_uri, os_build 
        FROM agents 
        WHERE os_cpe_uri != ''`)

	if osRows != nil {
		defer osRows.Close()
	OSLoop:
		for osRows.Next() {
			select {
			case <-ctx.Done():
				logs.Map.Warn("OS scan interrupted by context cancellation")
				break OSLoop // Exit loop, don't return
			default:
			}

			var aid, cpe, build string
			if err := osRows.Scan(&aid, &cpe, &build); err == nil {
				Correlate(&aid, nil, cpe, build, "os")
			}
		}
	}

	// Always attempt cleanup, even if the loops were interrupted
	logs.Map.Info("Running vulnerability cleanup phase...")
	CleanupOrphanedVulnerabilities()
}

func Correlate(agentID *string, swID *int, cpeURI, version, targetType string) {
	baseCPE := strings.Join(strings.Split(cpeURI, ":")[:5], ":")
	rows, err := CVE_Read_Database.Query(`
        SELECT 
            sv.cve_id, sv.version_start, sv.version_end, 
            v.severity, v.cvss_score, v.exploit_score, v.impact_score, 
            v.published, v.last_modified 
        FROM software_vulnerabilities sv 
        JOIN vulnerabilities v ON sv.cve_id = v.cve_id 
        WHERE sv.cpe_uri LIKE ?`, baseCPE+"%")

	if err != nil {
		logs.Map.Error("Correlation query failed", "error", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var cveID, severity, published, modified string
		var vStart, vEnd sql.NullString
		var score, exploit, impact float64

		if err := rows.Scan(&cveID, &vStart, &vEnd, &severity, &score, &exploit, &impact, &published, &modified); err != nil {
			continue
		}

		if isVulnerable(version, vStart, vEnd) {
			// CHANGE 1: Handle Application "Fan-out"
			if targetType == "application" && swID != nil {
				// We use SELECT from agent_software to update the whole fleet at once
				err = WriteQuery(Main_Database, `
                    INSERT INTO discovered_vulnerabilities (
                        agent_id, target_type, software_id, cpe_uri, cve_id, 
                        severity, cvss_score, exploit_score, impact_score, 
                        published_date, last_modified, status
                    ) 
                    SELECT agent_id, 'application', software_id, ?, ?, ?, ?, ?, ?, ?, ?, 'open'
                    FROM agent_software 
                    WHERE software_id = ?
                    ON CONFLICT(agent_id, target_type, software_id, cve_id) DO UPDATE SET
                        cvss_score = excluded.cvss_score`,
					cpeURI, cveID, severity, score, exploit, impact, published, modified, *swID)

				// CHANGE 2: Handle OS (Individual Agent)
			} else if targetType == "os" && agentID != nil {
				err = WriteQuery(Main_Database, `
                    INSERT INTO discovered_vulnerabilities (
                        agent_id, target_type, software_id, cpe_uri, cve_id, 
                        severity, cvss_score, status
                    ) VALUES (?, 'os', NULL, ?, ?, ?, ?, 'open')
                    ON CONFLICT(agent_id, target_type, software_id, cve_id) DO UPDATE SET
                        cvss_score = excluded.cvss_score`,
					*agentID, cpeURI, cveID, severity, score)
			}

			if err != nil {
				logs.Map.Error("Failed to log discovered vulnerability", "cve", cveID, "error", err)
			}
		}
	}
}

// Helper: Immediate re-correlation for the fleet
func RescanCVECorrelation(name, vendor, version, cpe string) {
	// Collect software information using id
	var sid int
	err := QuerySingleRow(Main_Read_Database,
		"SELECT id FROM software WHERE name = ? AND vendor = ? AND version = ? LIMIT 1",
		[]any{name, vendor, version}, &sid)

	if err != nil {
		logs.Map.Error("Rescan failed: software asset not found", "name", name, "error", err)
		return
	}

	// Call Correlate to check the new mapping for a CVE entry
	// - Pass nil for the agentID (first param)
	// - Pass &sid for the softwareID (second param)
	// - Use baseCPE logic to ensure generic matches work

	Correlate(nil, &sid, cpe, version, "application")

	logs.Map.Info("Global rescan triggered for asset", "name", name, "version", version)
}

// Remove disvoered_vulnerabilities entries for software that is no longer present
func CleanupOrphanedVulnerabilities() {
	var orphanCount int

	// Count how many we are about to delete
	err := QuerySingleRow(Main_Read_Database, `
        SELECT COUNT(*) FROM discovered_vulnerabilities
        WHERE (target_type = 'application' AND (agent_id, software_id) NOT IN (SELECT agent_id, software_id FROM agent_software))
        OR (target_type = 'os' AND agent_id NOT IN (SELECT agent_id FROM agents))`,
		nil, &orphanCount)

	if err == nil && orphanCount > 0 {
		// Now perform the delete
		WriteQuery(Main_Database, `
            DELETE FROM discovered_vulnerabilities
            WHERE (target_type = 'application' AND (agent_id, software_id) NOT IN (SELECT agent_id, software_id FROM agent_software))
            OR (target_type = 'os' AND agent_id NOT IN (SELECT agent_id FROM agents))`)

		logs.Map.Info("Vulnerability cleanup complete", "resolved_orphans", orphanCount)
	}
}

// Valid entries for the status of a discovered vulnerability
var ValidRemediationStatuses = []string{
	"open", "in-progress", "resolved", "risk-accepted", "false-positive",
}

func IsValidStatus(status string) bool {
	for _, s := range ValidRemediationStatuses {
		if s == status {
			return true
		}
	}
	return false
}

func StartCVEMapper(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Minute)

	WG.Add(1)
	go func() {
		defer WG.Done()
		defer ticker.Stop()

		// Helper function to safely execute the map with locking logic
		runSafeMap := func() {
			ScanMutex.Lock()
			if IsScanning {
				ScanMutex.Unlock()
				logs.Map.Warn("Scheduled background scan skipped: manual scan already in progress.")
				return
			}
			IsScanning = true
			ScanMutex.Unlock()

			// Reset flag when MapCVEs finishes
			defer func() {
				ScanMutex.Lock()
				IsScanning = false
				ScanMutex.Unlock()
			}()

			MapCVEs(ctx)
		}

		// --- INITIAL DELAYED START ---
		select {
		case <-time.After(1 * time.Minute):
			logs.Map.Info("Starting initial vulnerability mapping job...")
			runSafeMap()
			logs.Map.Info("Initial vulnerability mapping job complete.")
		case <-ctx.Done():
			return
		}

		// --- REGULAR INTERVAL LOOP ---
		for {
			select {
			case <-ticker.C:
				logs.Map.Info("Starting scheduled vulnerability mapping job...")
				runSafeMap()
				logs.Map.Info("Scheduled vulnerability mapping job complete.")
			case <-ctx.Done():
				return
			}
		}
	}()
}
