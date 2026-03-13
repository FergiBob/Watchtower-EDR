package data

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"watchtower_edr/server/internal"

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
		slog.Error("Failed to open database file", "DB_path", path, "error", err, "action", "Exiting")
		os.Exit(1)
	}

	db.SetMaxOpenConns(1)

	err = db.Ping()
	if err != nil {
		slog.Error("Database connection test failed", "DB_path", path, "error", err, "action", "Exiting")
		os.Exit(1)
	}

	slog.Info("Database connection established successfully")
	return db
}

// helper function used to write data with parameters to a database
// takes database to connect to, the query string, and a variable list of parameters to apply to the query
// returns an error
func WriteQuery(db *sql.DB, query string, params ...interface{}) error {
	// begins transaction
	tx, err := db.Begin()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return err
	}

	// executes query within transaction
	if _, err := tx.Exec(query, params...); err != nil {
		slog.Error("Failed to execute query", "error", err)
		tx.Rollback() // rolls back to previous state in event of failure
		return err
	}

	// commit the transaction
	if err := tx.Commit(); err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		return err
	}

	return nil
}

// builds the schemas for the two tables found in the NVD Dictionary
// used for initial creation or in the event of loss of database
func setupNVDDictionary(db *sql.DB) {

	query := `
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
	if err := WriteQuery(db, query); err != nil {
		slog.Error("NVD Dictionary initialization failed...Exiting", "error", err, "action", "Exiting")
		os.Exit(1)
	}

	slog.Info("NVD Dictionary initialized successfully")

}

func setupMainSQL(db *sql.DB) {
	// creates tables if they don't already exist: agents, software, agent_software, vulnerabilities, software_vulnerability
	query := `
		PRAGMA foreign_keys = ON;
		CREATE TABLE IF NOT EXISTS agents (
			agent_id TEXT PRIMARY KEY,
			hostname TEXT,
			os TEXT,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			ip_address TEXT
		);

		CREATE TABLE IF NOT EXISTS software (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			cpe_uri TEXT UNIQUE,
			name TEXT,
			version TEXT,
			vendor TEXT
    	);

		CREATE TABLE IF NOT EXISTS agent_software (
			agent_id TEXT,
			software_id INTEGER,
			PRIMARY KEY (agent_id, software_id),
			FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
			FOREIGN KEY (software_id) REFERENCES software(id)
		);

		CREATE TABLE IF NOT EXISTS vulnerabilities (
			cve_id TEXT PRIMARY KEY,
			severity REAL,
			description TEXT,
			published_date TEXT
		);

		CREATE TABLE IF NOT EXISTS software_vulnerabilities (
			software_id INTEGER,
			cve_id TEXT,
			discovered TIMSTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (software_id, cve_id),
			FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE,
			FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
		);



		-- Indexes
		CREATE INDEX IF NOT EXISTS idx_agent_hostname ON agents(hostname);
		CREATE INDEX IF NOT EXISTS idx_cat_cpe ON software(cpe_uri);
		CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
	`

	// call WriteQuery with parameters
	if err := (WriteQuery(db, query)); err != nil {
		slog.Error("Main database initialization failed", "error", err, "action", "Exiting")
	}

}

// function for cleaning up any orphaned vulnerabilities or software in the main database
func CleanupOrphans() {
	db := Main_Database
	query := `
		-- Delete software that no agent is currently using
		DELETE FROM software_catalog 
		WHERE id NOT IN (SELECT DISTINCT software_id FROM agent_software);

		-- Delete vulnerability details that aren't linked to any software in our catalog
		DELETE FROM vulnerability_cache 
		WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM software_vulnerabilities);
	`
	WriteQuery(db, query)
}

// uses initDB to open connections to the internal database and the cpe dictionary database
// as well as perform a schema check
func StartDatabases() {
	// opens connections
	Main_Database = initDB(internal.AppConfig.Database.MainDB)
	CPE_Database = initDB(internal.AppConfig.Database.CpeDB)

}

// ensures schemas and data are correct and up-to-date
func VerifyDatabases() {
	// ensures tables exist as defined
	setupNVDDictionary(CPE_Database)

	// performs a NIST CPE data-sync
	SyncCPE(CPE_Database, internal.AppConfig.NVD.APIKey)
}
