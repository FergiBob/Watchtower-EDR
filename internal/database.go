package internal

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	_ "modernc.org/sqlite"
)

// defines the two database connections as global pointers to a sql.DB object
var Main_Database *sql.DB
var CPE_Database *sql.DB

// takes a path to a database, initializes it and returns that connection as a pointer to the sql object
func initDB(path string) *sql.DB {
	slog.Info("Initializing database connection", "path", path)

	// Build a DSN string for increases functionality
	// _busy_timeout: prevents "database is locked" errors
	// _journal_mode: WAL prevents readers and writers from blocking one another
	dsn := fmt.Sprintf("%s?_busy_timeout=5000&_journal_mode=WAL", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		slog.Error("Failed to open database file", "DB_path", path, "error", err)
		os.Exit(1)
	}

	db.SetMaxOpenConns(1)

	err = db.Ping()
	if err != nil {
		slog.Error("Database connection test failed", "DB_path", path, "error", err)
		os.Exit(1)
	}

	slog.Info("Database connection established successfully")
	return db
}

// builds the schemas for the two tables found in the NVD Dictionary
// used for initial creation or in the event of loss of database
func setupNVDDictionary(db *sql.DB) {
	const schema = `
	CREATE TABLE IF NOT EXISTS cpe_dictionary (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cpe_uri TEXT UNIQUE,
		vendor TEXT,
		product TEXT,
		version TEXT,
		deprecated INTEGER DEFAULT 0,
		version_start_including TEXT,
		version_start_excluding TEXT,
		version_end_including TEXT,
		version_end_excluding TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_vendor_product ON cpe_dictionary(vendor, product);

	CREATE TABLE IF NOT EXISTS sync_metadata (
		key TEXT PRIMARY KEY,
		last_sync_timestamp TEXT,
		record_count INTEGER
	);
	`
	if _, err := db.Exec(schema); err != nil {
		slog.Error("Failed to create NVD tables", "error", err)
		os.Exit(1)
	}
}

// uses initDB to open connections to the internal database and the cpe dictionary database
// as well as perform a schema check
func StartDatabases() {
	// opens connections
	Main_Database = initDB(AppConfig.Database.MainDB)
	CPE_Database = initDB(AppConfig.Database.CpeDB)

}

// ensures schemas and data are correct and up-to-date
func VerifyDatabases() {
	// ensures tables exist as defined
	setupNVDDictionary(CPE_Database)

	// performs a NIST CPE data-sync
	SyncCPE(CPE_Database, AppConfig.NVD.APIKey)
}
