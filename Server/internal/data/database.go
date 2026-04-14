package data

import (
	"database/sql"
	"fmt"
	"os"
	"sync"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/logs"

	_ "modernc.org/sqlite"
)

// Global database connections
var Main_Database *sql.DB
var User_Database *sql.DB
var CPE_Database *sql.DB
var CVE_Database *sql.DB

// initDB initializes a database connection
func initDB(path string) *sql.DB {
	logs.DB.Info("Initializing database connection", "path", path)

	dsn := fmt.Sprintf("%s?_busy_timeout=5000&_journal_mode=WAL", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logs.DB.Error("Failed to open database file", "path", path, "error", err)
		os.Exit(1)
	}

	db.SetMaxOpenConns(1)

	err = db.Ping()
	if err != nil {
		logs.DB.Error("Database connection test failed (Ping)", "path", path, "error", err)
		os.Exit(1)
	}

	logs.DB.Info("Database connection established successfully", "path", path)
	return db
}

// WriteQuery executes a write operation inside a transaction
func WriteQuery(db *sql.DB, query string, params ...interface{}) error {
	tx, err := db.Begin()
	if err != nil {
		logs.DB.Error("Failed to begin write transaction", "error", err)
		return err
	}

	defer tx.Rollback()

	if _, err := tx.Exec(query, params...); err != nil {
		logs.DB.Error("Failed to execute write query", "query", query, "error", err)
		return err
	}

	if err := tx.Commit(); err != nil {
		logs.DB.Error("Failed to commit write transaction", "error", err)
		return err
	}

	return nil
}

// ReadQuery executes a read operation and returns rows
func ReadQuery(db *sql.DB, query string, params ...interface{}) (*sql.Rows, error) {
	// Note: Standard reads often don't need a transaction,
	// but kept here to match your original implementation logic.
	rows, err := db.Query(query, params...)
	if err != nil {
		logs.DB.Error("Failed to execute read query", "query", query, "error", err)
		return nil, err
	}

	return rows, nil
}

// QuerySingleRow simplifies read queries that only return one row
func QuerySingleRow(db *sql.DB, query string, args []any, dest ...any) error {
	row := db.QueryRow(query, args...)
	err := row.Scan(dest...)
	if err != nil && err != sql.ErrNoRows {
		logs.DB.Error("Failed to scan single row", "query", query, "error", err)
	}
	return err
}

// setupCPEDictionary builds the schemas for the CPE database
func setupCPEDictionary(db *sql.DB) {
	query := `
    CREATE TABLE IF NOT EXISTS cpe_dictionary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpe_uri TEXT UNIQUE,
        vendor TEXT,
        product TEXT,
        version TEXT,
        deprecated INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_cpe_search ON cpe_dictionary(vendor, product, version);
    CREATE TABLE IF NOT EXISTS sync_metadata (
        key TEXT PRIMARY KEY,
        last_sync_timestamp TEXT,
        record_count INTEGER
    );`

	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("CPE Database schema initialization failed", "error", err)
		os.Exit(1)
	}
	logs.DB.Info("CPE Dictionary schema verified/initialized")
}

// setupCVEDatabase builds the schemas for the CVE database
func setupCVEDatabase(db *sql.DB) {
	query := `
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        severity TEXT,
        cvss_score REAL,
        published TEXT
    );
    CREATE TABLE IF NOT EXISTS software_vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT,
        cpe_uri TEXT,
        version_start TEXT,
        version_end TEXT,
        FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_sv_cpe_lookup ON software_vulnerabilities(cpe_uri);
    CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
    CREATE TABLE IF NOT EXISTS sync_metadata (
        key TEXT PRIMARY KEY,
        last_sync_timestamp TEXT,
        record_count INTEGER
    );`

	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("Vulnerability Database schema initialization failed", "error", err)
		os.Exit(1)
	}
	logs.DB.Info("Vulnerability Database schema verified/initialized")
}

// setupMainSQL builds the schemas for the primary EDR database
func setupMainSQL(db *sql.DB) {
	query := `
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        machine_id TEXT UNIQUE, 
        hostname TEXT,
        ip_address TEXT,
        os TEXT,
        os_version TEXT,
		os_cpe_uri TEXT,
        status TEXT DEFAULT 'active',
        binary_version TEXT,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        description TEXT DEFAULT ''
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
        FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE
    );
	CREATE TABLE IF NOT EXISTS discovered_vulnerabilities (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id      TEXT NOT NULL,
		target_type   TEXT NOT NULL CHECK(target_type IN ('application', 'os')),
		software_id   INTEGER, 
		cpe_uri       TEXT, 
		cve_id        TEXT NOT NULL,
		severity      TEXT,         
		cvss_score    REAL,         
		detected_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
		status        TEXT DEFAULT 'open',
		
		FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
		FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE,
		
		UNIQUE(agent_id, target_type, software_id, cve_id) 
	);
    CREATE INDEX IF NOT EXISTS idx_agent_hostname ON agents(hostname);
    CREATE INDEX IF NOT EXISTS idx_sw_cpe ON software(cpe_uri);
    CREATE INDEX IF NOT EXISTS idx_dv_agent ON discovered_vulnerabilities(agent_id);
    CREATE INDEX IF NOT EXISTS idx_dv_severity ON discovered_vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_dv_status ON discovered_vulnerabilities(status);
    `

	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("Main database schema initialization failed", "error", err)
		os.Exit(1)
	}
	logs.DB.Info("Main Database schema verified/initialized")
}

// CleanupOrphans removes orphaned software records
func CleanupOrphans() {
	query := `
        DELETE FROM software 
        WHERE id NOT IN (SELECT DISTINCT software_id FROM agent_software);
    `
	if err := WriteQuery(Main_Database, query); err != nil {
		logs.DB.Error("Failed to cleanup orphaned database records", "error", err)
	} else {
		// Cleanup is an administrative action
		logs.Audit.Info("Orphaned software records cleaned up successfully")
	}
}

// StartDatabases opens connections to all configured databases
func StartDatabases() {
	logs.Sys.Info("Starting all database engines...")
	Main_Database = initDB(internal.AppConfig.Database.MainDB)
	User_Database = initDB(internal.AppConfig.Database.UserDB)
	CPE_Database = initDB(internal.AppConfig.Database.CpeDB)
	CVE_Database = initDB(internal.AppConfig.Database.CveDB)
}

// CloseDatabases ensures all connections are closed safely
func CloseDatabases() {
	logs.Sys.Info("Closing all database connections...")
	dbs := map[string]*sql.DB{
		"Main": Main_Database,
		"User": User_Database,
		"CPE":  CPE_Database,
		"CVE":  CVE_Database,
	}

	for name, db := range dbs {
		if db != nil {
			if err := db.Close(); err != nil {
				logs.DB.Error("Error closing database connection", "name", name, "error", err)
			}
		}
	}
	CloseAllArchives()
}

// VerifyDatabases ensures schemas are correct
func VerifyDatabases() {
	logs.Sys.Info("Verifying database schemas...")
	setupCPEDictionary(CPE_Database)
	setupCVEDatabase(CVE_Database)
	setupMainSQL(Main_Database)
}

// -------------------- ARCHIVE HANDLING --------------------------

var ActiveArchives = make(map[string]*sql.DB)
var archiveMutex sync.Mutex

func RegisterArchive(name string, db *sql.DB) {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()
	ActiveArchives[name] = db
	// Registering an archive is an Audit-level event
	logs.Audit.Info("Database archive registered", "name", name)
}

func CloseAllArchives() {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()

	for name, db := range ActiveArchives {
		logs.DB.Info("Closing archive connection", "archive", name)
		db.Close()
		delete(ActiveArchives, name)
	}
}

func OpenArchive(path string) (*sql.DB, error) {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()

	if db, exists := ActiveArchives[path]; exists {
		return db, nil
	}

	logs.DB.Info("Opening archive database", "path", path)
	dsn := fmt.Sprintf("file:%s?mode=ro", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logs.DB.Error("Failed to open archive file", "path", path, "error", err)
		return nil, err
	}

	if err := db.Ping(); err != nil {
		logs.DB.Error("Archive ping failed", "path", path, "error", err)
		db.Close()
		return nil, err
	}

	ActiveArchives[path] = db
	return db, nil
}
