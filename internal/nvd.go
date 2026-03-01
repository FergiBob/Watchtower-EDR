// provides functions to handle cloning cpe data and querying cve entries in NIST NVD

package internal

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type NVDResponse struct {
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

// takes a string in NIST CPE format (cpe:2.3:a:vendor:software:......) and breaks it into an array of its parts
func ParseCPE(cpe string) []string {
	// remove prefix
	trimmed := strings.TrimPrefix(cpe, "cpe:2.3:")
	parts := strings.Split(trimmed, ":")

	// check for all 11 fields
	for len(parts) < 11 {
		parts = append(parts, "*")
	}
	return parts
}

// FormatNVDTime converts a Go time object to the specific string
// format the NVD API requires (ISO 8601 with milliseconds).
func FormatNVDTime(t time.Time) string {
	// Format: 2023-12-01T00:00:00.000
	return t.UTC().Format("2006-01-02T15:04:05.000")
}

// GetSyncStartTime retrieves the last sync time or defaults
// to 120 days ago if the table is empty (to follow NIST 120-day recall rule, will adjust after testing)
func getSyncStartTime(db *sql.DB) string {
	var lastSync string
	// We query for the key; sql.ErrNoRows is returned if it's not there
	err := db.QueryRow("SELECT last_sync_timestamp FROM sync_metadata WHERE key = 'nvd_cpe'").Scan(&lastSync)

	if err == sql.ErrNoRows || lastSync == "" { //checks if there are no sync entries and thus, no dictionary entries
		slog.Info("No sync history found. Initializing first-time seed from 2002.")
		// Start of NVD era (seeds the entire database with all historical data)
		start := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		return FormatNVDTime(start)
	} else if err != nil {
		slog.Error("Database error checking sync metadata", "error", err)
		// Fallback to 120 days ago as a safety measure if DB is acting up
		return FormatNVDTime(time.Now().AddDate(0, 0, -120))
	}

	slog.Info("Resuming sync from last recorded timestamp", "timestamp", lastSync)
	return lastSync
}

// inserts data into cpe dictionary in batch jobs for performance
func processBatch(db *sql.DB, products []CPEProduct) {
	// begin database transaction
	tx, err := db.Begin()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
        INSERT INTO cpe_dictionary (
            cpe_uri, vendor, product, version, deprecated,
            version_start_including, version_start_excluding,
            version_end_including, version_end_excluding
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cpe_uri) DO UPDATE SET
            vendor=excluded.vendor,
            product=excluded.product,
            version=excluded.version,
            deprecated=excluded.deprecated,
            version_start_including=excluded.version_start_including,
            version_start_excluding=excluded.version_start_excluding,
            version_end_including=excluded.version_end_including,
            version_end_excluding=excluded.version_end_excluding`)
	if err != nil {
		slog.Error("Failed to prepare statement", "error", err)
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
			p.CPE.VersionStartIncluding,
			p.CPE.VersionStartExcluding,
			p.CPE.VersionEndIncluding,
			p.CPE.VersionEndExcluding,
		)
		if err != nil {
			slog.Warn("Failed to insert CPE", "uri", p.CPE.CpeName, "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("Failed to commit transaction", "error", err)
	} else {
		slog.Info("Successfully processed batch", "count", len(products))
	}
}

// UpdateSyncMetadata saves the most recent timestamp after a successful fetch
func updateSyncMetadata(db *sql.DB, timestamp string, count int) {
	_, err := db.Exec(`
        INSERT INTO sync_metadata (key, last_sync_timestamp, record_count) 
        VALUES ('nvd_cpe', ?, ?)
        ON CONFLICT(key) DO UPDATE SET 
            last_sync_timestamp = excluded.last_sync_timestamp,
            record_count = excluded.record_count`,
		timestamp, count)
	if err != nil {
		slog.Error("Failed to update sync metadata", "error", err)
	}
}

func SyncCPE(db *sql.DB, apiKey string) {
	// 1. Get the last sync string and parse it into a time.Time object
	lastSyncStr := getSyncStartTime(db)
	// Note: Use the same format string used in FormatNVDTime
	lastSyncTime, err := time.Parse("2006-01-02T15:04:05.000", lastSyncStr)
	if err != nil {
		slog.Error("Failed to parse last sync time, defaulting to 120 days ago", "error", err)
		lastSyncTime = time.Now().AddDate(0, 0, -120)
	}

	now := time.Now()

	// OUTER LOOP: Move through time in 120-day chunks
	for lastSyncTime.Before(now) {
		// Calculate the end of this 120-day window
		windowEnd := lastSyncTime.AddDate(0, 0, 120)
		if windowEnd.After(now) {
			windowEnd = now
		}

		slog.Info("Syncing 120-day window", "start", FormatNVDTime(lastSyncTime), "end", FormatNVDTime(windowEnd))

		startIndex := 0
		resultsPerPage := 5000 // NIST is more stable at 5k than 10k

		// INNER LOOP: Handle pagination within the current time window
		for {
			url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d&lastModStartDate=%s&lastModEndDate=%s",
				AppConfig.NVD.CpeURL, resultsPerPage, startIndex, FormatNVDTime(lastSyncTime), FormatNVDTime(windowEnd))

			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Set("apiKey", apiKey)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				slog.Error("Network error during sync", "err", err)
				return // Stop the sync to prevent data gaps
			}

			if resp.StatusCode != http.StatusOK {
				slog.Error("NVD API returned error status", "status", resp.Status)
				resp.Body.Close()
				return
			}

			var data NVDResponse
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				slog.Error("Failed to decode NVD JSON", "error", err)
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			// Batch insert the current page
			if len(data.Products) > 0 {
				processBatch(db, data.Products)
			}

			slog.Info("Progress", "totalResults", data.TotalResults, "currentStartIndex", startIndex)

			// Check if we need to keep paginating
			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}

			// Respect rate limits (Wait longer if you don't have an API key)
			time.Sleep(1 * time.Second)
		}

		// Update metadata AFTER each window is fully successfully processed
		updateSyncMetadata(db, FormatNVDTime(windowEnd), 0)

		// Move the cursor forward for the next outer loop iteration
		lastSyncTime = windowEnd

		// Optional: extra rest between windows
		time.Sleep(2 * time.Second)
	}

	slog.Info("CPE Dictionary is fully up to date")
}
