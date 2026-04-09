// provides functions to handle cloning cpe data and querying cve entries in NIST NVD

package data

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"Watchtower_EDR/server/internal"
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
	// Query for the key; sql.ErrNoRows is returned if it's not there
	err := db.QueryRow("SELECT last_sync_timestamp FROM sync_metadata WHERE key = 'nvd_cpe'").Scan(&lastSync)

	if err == sql.ErrNoRows || lastSync == "" { //checks if there are no sync entries and thus, no dictionary entries
		slog.Info("No sync history found. Initializing first-time seed from 2002.", "category", "NVD Database")
		// Start of NVD era (seeds the entire database with all historical data)
		start := time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		return FormatNVDTime(start)
	} else if err != nil {
		slog.Error("Database error checking sync metadata", "error", err, "category", "NVD Database")
		// Fallback to 120 days ago as a safety measure if DB is acting up
		return FormatNVDTime(time.Now().AddDate(0, 0, -120))
	}

	slog.Info("Resuming sync from last recorded timestamp", "timestamp", lastSync, "category", "NVD Database")
	return lastSync
}

// inserts data into cpe dictionary in batch jobs for performance
func processBatch(db *sql.DB, products []CPEProduct) {
	// begin database transaction
	tx, err := db.Begin()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err, "category", "NVD Database")
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
		slog.Error("Failed to prepare statement", "error", err, "category", "NVD Database")
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
			slog.Warn("Failed to insert CPE", "uri", p.CPE.CpeName, "error", err, "category", "NVD Database")
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("Failed to commit transaction", "error", err, "category", "NVD Database")
	} else {
		slog.Info("Successfully processed batch", "count", len(products), "category", "NVD Database")
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
		slog.Error("Failed to update sync metadata", "error", err, "category", "NVD Database")
	}
}

// SyncCPE handles the full or incremental update of the CPE database.
func SyncCPE(ctx context.Context, db *sql.DB, apiKey string) error {
	lastSyncStr := getSyncStartTime(db)
	lastSyncTime, err := time.Parse("2006-01-02T15:04:05.000", lastSyncStr)
	if err != nil {
		slog.Error("Failed to parse last sync time, defaulting to 120 days ago", "error", err, "category", "NVD Database")
		lastSyncTime = time.Now().AddDate(0, 0, -120)
	}

	now := time.Now()
	for lastSyncTime.Before(now) {
		windowEnd := lastSyncTime.AddDate(0, 0, 120)
		if windowEnd.After(now) {
			windowEnd = now
		}

		// If windowEnd is somehow before or equal to lastSyncTime due to clock drift, stop.
		if !lastSyncTime.Before(windowEnd) {
			break
		}

		slog.Info("Syncing 120-day window", "start", FormatNVDTime(lastSyncTime), "end", FormatNVDTime(windowEnd), "category", "NVD Database")
		startIndex := 0
		resultsPerPage := 5000

		for {
			// Check if context was cancelled
			select {
			case <-ctx.Done():
				return fmt.Errorf("sync interrupted by shutdown")
			default:
			}

			// Build URL safely
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
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				return fmt.Errorf("NVD API returned error status: %s", resp.Status)
			}

			var data NVDResponse
			// Load CPE json data into struct
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
				resp.Body.Close()
				return fmt.Errorf("failed to decode NVD JSON: %w", err)
			}
			resp.Body.Close()

			// Check if there is data, then process it in batches
			if len(data.Products) > 0 {
				processBatch(db, data.Products)
			}

			// Log progress and increment index
			slog.Info("Progress", "totalResults", data.TotalResults, "currentStartIndex", startIndex, "category", "NVD Database")
			startIndex += resultsPerPage
			if startIndex >= data.TotalResults {
				break
			}
			time.Sleep(1 * time.Second)
		}

		updateSyncMetadata(db, FormatNVDTime(windowEnd), 0)
		lastSyncTime = windowEnd
		time.Sleep(2 * time.Second)
	}
	slog.Info("CPE Dictionary is fully up to date", "category", "NVD Database")
	return nil
}

func StartCPEUpdater(ctx context.Context) {
	db := CPE_Database
	apikey := internal.AppConfig.NVD.APIKey
	ticker := time.NewTicker(12 * time.Hour)

	if apikey == "" || apikey == "YOUR_API_KEY_HERE" {
		slog.Error("NVD API Key missing. CPE Sync disabled.", "category", "NVD Database")
		return
	}

	go func() {
		defer ticker.Stop()
		slog.Info("CPE Updater background worker started.", "category", "NVD Database")

		// Initial Sync
		// This ensures the DB is seeded before the first 12hr loop
		if err := SyncCPE(ctx, db, apikey); err != nil {
			slog.Error("Initial CPE sync failed", "error", err, "category", "NVD Database")
		}

		for {
			select {
			case <-ticker.C:
				slog.Info("Starting scheduled 12-hour CPE sync...", "category", "NVD Database")
				if err := SyncCPE(ctx, db, apikey); err != nil {
					slog.Error("CPE sync failed, scheduling 1hr retry", "error", err, "category", "NVD Database")

					// Linear retry check
					select {
					case <-time.After(1 * time.Hour):
						slog.Info("Retrying CPE sync...", "category", "NVD Database")
						_ = SyncCPE(ctx, db, apikey) // Attempt retry
					case <-ctx.Done():
						return
					}
				}

			case <-ctx.Done():
				slog.Info("CPE Updater background worker stopped.", "category", "NVD Database")
				return
			}
		}
	}()
}

func MapCPEs() error {
	// Get unmatched software from Main DB
	rows, err := ReadQuery(Main_Database, `SELECT id, name, version, vendor FROM software WHERE cpe_uri IS NULL OR cpe_uri = ''`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var name, version, vendor string
		if err := rows.Scan(&id, &name, &version, &vendor); err != nil {
			slog.Error("Failed to scan software row", "error", err)
			continue
		}

		// Search the Dictionary DB
		var cpeURI string
		query := `
            SELECT cpe_uri 
            FROM cpe_dictionary 
            WHERE (vendor LIKE ? OR ? LIKE '%' || vendor || '%')
              AND (product LIKE ? OR ? LIKE '%' || product || '%')
              AND version = ? 
            LIMIT 1`

		// Attempt to match the software information to a URI
		args := []any{"%" + vendor + "%", vendor, "%" + name + "%", name, version}
		err := QuerySingleRow(CPE_Database, query, args, &cpeURI)

		if err != nil {
			if err == sql.ErrNoRows {
				continue // No match, move to next
			}
			slog.Error("Dictionary lookup error", "error", err)
			continue
		}

		// Update the Main DB with the found URI using your WriteQuery wrapper
		err = WriteQuery(Main_Database, "UPDATE software SET cpe_uri = ? WHERE id = ?", cpeURI, id)
		if err != nil {
			slog.Error("Failed to update software with CPE", "id", id, "error", err)
		} else {
			slog.Info("Successfully matched software", "name", name, "cpe", cpeURI)
		}
	}
	return nil
}

func StartCPEMapper(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)

	go func() {
		defer ticker.Stop()
		slog.Info("CPE-Software Mapper background worker started.")

		// 1. Run immediately on startup
		if err := MapCPEs(); err != nil {
			slog.Error("Initial CPE-Software map failed", "error", err)
		}

		for {
			select {
			case <-ticker.C:
				slog.Info("Starting scheduled CPE-Software mapping...")
				if err := MapCPEs(); err != nil {
					slog.Error("CPE-Software mapping failed, scheduling retry", "error", err)

					// uses After to wait for retry
					select {
					case <-time.After(1 * time.Minute):
						slog.Info("Retrying CPE-Software mapping...")
						if err := MapCPEs(); err != nil {
							slog.Error("Retry failed. Waiting for next 5-minute cycle.")
						}
					case <-ctx.Done():
						return
					}
				}

			case <-ctx.Done():
				slog.Info("Shutting down CPE-Software Mapper...")
				return
			}
		}
	}()
}
