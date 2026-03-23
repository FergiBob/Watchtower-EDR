package data

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"Watchtower_EDR/server/internal"

	_ "modernc.org/sqlite"
)

// Defines the two database connections as global pointers to a sql.DB object
var Main_Database *sql.DB
var User_Database *sql.DB
var CPE_Database *sql.DB

// Takes a path to a database, initializes it and returns that connection as a pointer to the sql object
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

// Helper function used to write data with parameters to a database
// Takes database to connect to, the query string, and a variable list of parameters to apply to the query
// Returns an error
func WriteQuery(db *sql.DB, query string, params ...interface{}) error {
	// Begins transaction
	tx, err := db.Begin()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return err
	}

	// Rolls back to previous state in case of early exit
	defer tx.Rollback()

	// Executes query within transaction
	if _, err := tx.Exec(query, params...); err != nil {
		slog.Error("Failed to execute query", "error", err)
		return err
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		return err
	}

	return nil
}

// Helper function used to read data from a database
// Takes database to connect to, the query string, and a variable list of parameters to apply to the query
// Returns a rows pointer and an error value
func ReadQuery(db *sql.DB, query string, params ...interface{}) (*sql.Rows, error) {
	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		slog.Error("Failed to begin transaction", "error", err)
		return nil, err
	}

	// Rolls back to previous state in case of early exit
	defer tx.Rollback()

	// Execute SELECT query
	rows, err := tx.Query(query, params...)

	// Commit to release transaction lock and apply any potential changes
	if err = tx.Commit(); err != nil {
		slog.Error("Failed to commit transaction", "error", err)
		return nil, err
	}

	return rows, nil
}

// QuerySingleRow simplifies read queries that only return one row by providing the items to scan results into in the arguments and returning the scanned values, rather than sql.Rows object that still has to be parsed
func QuerySingleRow(db *sql.DB, query string, args []any, dest ...any) error {
	row := db.QueryRow(query, args...)
	return row.Scan(dest...)
}

// Builds the schemas for the two tables found in the NVD Dictionary
// Used for initial creation or in the event of loss of database
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
	// Creates tables if they don't already exist: agents, software, agent_software, vulnerabilities, software_vulnerability
	query := `
		PRAGMA foreign_keys = ON;
		CREATE TABLE IF NOT EXISTS agents (
			agent_id TEXT PRIMARY KEY,
			machine_id TEXT,
			hostname TEXT,
			ip_address TEXT,
			os TEXT,
			os_version TEXT,
			architecture TEXT,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			status TEXT,
			binary_version TEXT
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

	// Call WriteQuery with parameters
	if err := (WriteQuery(db, query)); err != nil {
		slog.Error("Main database initialization failed", "error", err, "action", "Exiting")
		os.Exit(1)
	}

}

// Function for cleaning up any orphaned vulnerabilities or software in the main database
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

// Uses initDB to open connections to the internal database and the cpe dictionary database
// As well as perform a schema check
func StartDatabases() {
	// opens connections
	Main_Database = initDB(internal.AppConfig.Database.MainDB)
	User_Database = initDB(internal.AppConfig.Database.UserDB)
	CPE_Database = initDB(internal.AppConfig.Database.CpeDB)

}

func CloseDatabases() {
	slog.Info("Closing all database connections...")
	if Main_Database != nil {
		Main_Database.Close()
	}
	if User_Database != nil {
		User_Database.Close()
	}
	if CPE_Database != nil {
		CPE_Database.Close()
	}
	CloseAllArchives() // Prevents any active archive file connections from leaking
}

// Ensures schemas and data are correct and up-to-date
func VerifyDatabases() {
	// Ensures tables exist, creates them if not
	setupNVDDictionary(CPE_Database)
	setupMainSQL(Main_Database)

	nvdAPIKey := internal.AppConfig.NVD.APIKey

	// Checks to ensure
	if nvdAPIKey == "YOUR_API_KEY_HERE" {
		slog.Error("NVD API Key not configured. Unable to sync CPE Database")
		return
	}

	// Performs a NIST CPE data-sync
	SyncCPE(CPE_Database, nvdAPIKey)
}

// -------------------- ARCHIVE HANDLING --------------------------

// Map of all archive db connections open at any given time
var ActiveArchives = make(map[string]*sql.DB)
var archiveMutex sync.Mutex // Prevents crashes in the event of multiple processes attempting to access the same archive

// Adds archive name to the list of active archives
func RegisterArchive(name string, db *sql.DB) {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()
	ActiveArchives[name] = db
}

// Closes an archive connection and removes it from the list of active connections
func CloseAllArchives() {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()

	for name, db := range ActiveArchives {
		slog.Info("Closing archive connection", "archive", name)
		db.Close()
		delete(ActiveArchives, name)
	}
}

// Opens an archive connection and adds it to the list of active connections
func OpenArchive(path string) (*sql.DB, error) {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()

	// Check if a connection already exists
	if db, exists := ActiveArchives[path]; exists {
		return db, nil
	}

	// Build Connection string
	dsn := fmt.Sprintf("file:%s?mode=ro", path)

	// Open connection
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	// Test Connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}

	ActiveArchives[path] = db
	return db, nil
}
