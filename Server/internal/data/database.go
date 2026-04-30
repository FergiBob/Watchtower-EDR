package data

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/logs"

	_ "modernc.org/sqlite"
)

var (
	// --- EXCLUSIVE WRITERS (SetMaxOpenConns = 1) ---
	Main_Database *sql.DB
	User_Database *sql.DB
	CPE_Database  *sql.DB
	CVE_Database  *sql.DB

	// --- CONCURRENT READERS (SetMaxOpenConns = 10) ---
	Main_Read_Database *sql.DB
	CPE_Read_Database  *sql.DB
	CVE_Read_Database  *sql.DB

	// WG is used to ensure database processes are complete before server closes
	WG sync.WaitGroup

	// PriorityLock is used to ensure only one goroutine even ATTEMPTS a write at a time.
	PriorityLock sync.Mutex
)

// -------------------- CORE QUERY FUNCTIONS --------------------------

// WriteQuery executes a write operation with a closure to ensure transaction cleanup and retries.
func WriteQuery(db *sql.DB, query string, params ...interface{}) error {
	PriorityLock.Lock()
	defer PriorityLock.Unlock()

	var lastErr error
	for i := 0; i < 5; i++ {
		err := func() error {
			tx, err := db.Begin()
			if err != nil {
				return err
			}
			defer tx.Rollback()

			if _, err := tx.Exec(query, params...); err != nil {
				return err
			}
			return tx.Commit()
		}()

		if err == nil {
			return nil
		}

		lastErr = err
		if strings.Contains(err.Error(), "locked") || strings.Contains(err.Error(), "transaction") {
			time.Sleep(time.Duration(i+1) * 50 * time.Millisecond)
			continue
		}
		break
	}
	return lastErr
}

// ReadQuery executes a read operation and returns rows.
func ReadQuery(db *sql.DB, query string, params ...interface{}) (*sql.Rows, error) {
	rows, err := db.Query(query, params...)
	if err != nil {
		logs.DB.Error("Failed to execute read query", "query", query, "error", err)
		return nil, err
	}
	return rows, nil
}

// QuerySingleRow simplifies read queries that only return one row.
func QuerySingleRow(db *sql.DB, query string, args []any, dest ...any) error {
	err := db.QueryRow(query, args...).Scan(dest...)
	if err != nil && err != sql.ErrNoRows {
		logs.DB.Error("Failed to scan single row", "query", query, "error", err)
	}
	return err
}

// -------------------- DATABASE INITIALIZATION --------------------------

func initDB(path string, maxConns int, readOnly bool) *sql.DB {
	logs.DB.Info("Initializing database connection", "path", path, "readonly", readOnly)

	var dsn string
	if readOnly {
		// READERS: use cache=shared to allow multiple read handles to coordinate
		dsn = fmt.Sprintf("file:%s?mode=ro&cache=shared&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)", path)
	} else {
		// WRITERS: no shared cache to prevent permission inheritance issues, explicit WAL mode
		dsn = fmt.Sprintf("file:%s?mode=rwc&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logs.DB.Error("Failed to open database file", "path", path, "error", err)
		os.Exit(1)
	}

	db.SetMaxOpenConns(maxConns)
	db.SetConnMaxIdleTime(30 * time.Second)

	if err = db.Ping(); err != nil {
		logs.DB.Error("Database connection test failed (Ping)", "path", path, "error", err)
		os.Exit(1)
	}

	return db
}

func StartDatabases() {
	logs.Sys.Info("Starting all database engines...")

	// Exclusive Writers
	Main_Database = initDB(internal.AppConfig.Database.MainDB, 1, false)
	User_Database = initDB(internal.AppConfig.Database.UserDB, 1, false)
	CPE_Database = initDB(internal.AppConfig.Database.CpeDB, 1, false)
	CVE_Database = initDB(internal.AppConfig.Database.CveDB, 1, false)

	// Functional Readers (Used for Mappers and UI)
	Main_Read_Database = initDB(internal.AppConfig.Database.MainDB, 10, true)
	CPE_Read_Database = initDB(internal.AppConfig.Database.CpeDB, 10, true)
	CVE_Read_Database = initDB(internal.AppConfig.Database.CveDB, 10, true)
}

func CloseDatabases() {
	logs.Sys.Info("Initiating global database checkpoint and shutdown...")

	dbs := map[string]*sql.DB{
		"Main_Write": Main_Database,
		"Main_Read":  Main_Read_Database,
		"User":       User_Database,
		"CPE_Write":  CPE_Database,
		"CPE_Read":   CPE_Read_Database,
		"CVE_Write":  CVE_Database,
		"CVE_Read":   CVE_Read_Database,
	}

	for name, db := range dbs {
		if db == nil {
			continue
		}

		// Checkpoint writers to merge WAL files
		if !strings.Contains(name, "Read") {
			if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
				logs.DB.Debug("Note: WAL checkpoint skipped or restricted", "db", name, "error", err)
			}
		}

		if err := db.Close(); err != nil {
			logs.DB.Error("Error closing database handle", "db", name, "error", err)
		} else {
			logs.Sys.Info("Database handle closed cleanly", "db", name)
		}
	}

	CloseAllArchives()
	logs.Sys.Info("All Watchtower database systems are now offline.")
}

func VerifyDatabases() {
	logs.Sys.Info("Verifying database schemas...")
	setupCPEDictionary(CPE_Database)
	setupCVEDatabase(CVE_Database)
	setupMainSQL(Main_Database)
}

// -------------------- SCHEMA SETUP FUNCTIONS --------------------------

func setupCPEDictionary(db *sql.DB) {
	query := `
    CREATE TABLE IF NOT EXISTS cpe_dictionary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpe_uri TEXT UNIQUE,
        vendor TEXT, product TEXT, version TEXT,
        deprecated INTEGER DEFAULT 0,
		is_indexed INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_cpe_search ON cpe_dictionary(vendor, product, version);
	CREATE INDEX IF NOT EXISTS idx_cpe_unindexed ON cpe_dictionary(is_indexed) WHERE is_indexed = 0;
    CREATE TABLE IF NOT EXISTS sync_metadata (
        key TEXT PRIMARY KEY,
        last_sync_timestamp TEXT,
        record_count INTEGER
    );`
	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("CPE Database initialization failed", "error", err)
		os.Exit(1)
	}
	logs.DB.Info("CPE Dictionary schema verified/initialized")
}

func setupCVEDatabase(db *sql.DB) {
	query := `
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        description TEXT,
        severity TEXT,
        cvss_score REAL,
        exploit_score REAL,
        impact_score REAL,
        published TEXT,
        last_modified TEXT,
        solution TEXT
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
    CREATE TABLE IF NOT EXISTS sync_metadata (
        key TEXT PRIMARY KEY,
        last_sync_timestamp TEXT,
        record_count INTEGER
    );`
	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("CVE Database initialization failed", "error", err)
		os.Exit(1)
	}
}

func setupMainSQL(db *sql.DB) {
	query := `
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS agents (
        agent_id TEXT PRIMARY KEY,
        machine_id TEXT UNIQUE,
        hostname TEXT,
        ip_address TEXT,
		category TEXT,
		description TEXT,
        os TEXT,           
        os_name TEXT,         
        os_version TEXT,      
        os_build TEXT,        
        os_cpe_uri TEXT,
        status TEXT DEFAULT 'active',
        binary_version TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS software (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpe_uri TEXT UNIQUE, name TEXT, version TEXT, vendor TEXT, mapped INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS agent_software (
        agent_id TEXT, software_id INTEGER, install_date TEXT,
        PRIMARY KEY (agent_id, software_id),
        FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
        FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE
    );
	CREATE TABLE IF NOT EXISTS discovered_vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL,
		cve_id TEXT NOT NULL,
		target_type TEXT NOT NULL,    -- 'os' or 'application'
		software_id INTEGER,          -- Links to software table (NULL for OS)
		cpe_uri TEXT,
		severity TEXT,                -- 'CRITICAL', 'HIGH', etc.
		cvss_score REAL,
		exploit_score REAL,
		impact_score REAL,
		published_date DATETIME,
		last_modified DATETIME,
		status TEXT DEFAULT 'open', 
		detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(agent_id, target_type, software_id, cve_id)
	);
	CREATE TABLE IF NOT EXISTS software_mappings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		raw_name TEXT,    
		raw_vendor TEXT,    
		raw_version TEXT, 
		selected_cpe TEXT,  
		mapped_by TEXT,      
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(raw_name, raw_vendor, raw_version)
	);`
	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("Main database initialization failed", "error", err)
		os.Exit(1)
	}
	logs.DB.Info("Main Database schema verified/initialized")
}

func CreateInitialAdmin(user, email, password string) {
	// 1. First, ensure the table exists
	schemaQuery := `
    CREATE TABLE IF NOT EXISTS users (
        "ID" INTEGER NOT NULL UNIQUE,
        "username" TEXT NOT NULL,
        "email" TEXT,
        "password_hash" TEXT NOT NULL,
        "created_on" TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_on" TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY("ID" AUTOINCREMENT)
    );`

	if err := WriteQuery(User_Database, schemaQuery); err != nil {
		logs.Sys.Error("Failed to create users table", "error", err)
		os.Exit(1)
	}

	// 2. Then, insert the admin user
	insertQuery := `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`
	if err := WriteQuery(User_Database, insertQuery, user, email, password); err != nil {
		logs.Sys.Error("Failed to insert initial admin", "error", err)
		os.Exit(1)
	}

	logs.Sys.Info("Initial admin user created successfully")
}

func CleanupOrphans() {
	// Start a transaction on the Main Database
	tx, err := Main_Database.Begin()
	if err != nil {
		logs.DB.Error("Failed to start maintenance transaction", "error", err)
		return
	}

	// Ensure rollback in event of error
	defer tx.Rollback()

	// Remove software mappings for agents that are missing or decommissioned
	cleanMappingsQuery := `
		DELETE FROM agent_software 
		WHERE agent_id NOT IN (SELECT agent_id FROM agents)
		OR agent_id IN (SELECT agent_id FROM agents WHERE status = 'decommissioned');
	`
	if _, err := tx.Exec(cleanMappingsQuery); err != nil {
		logs.DB.Error("Failed to cleanup orphaned agent_software mappings", "error", err)
		return
	}

	// Remove software records that no longer have any associated installations
	cleanSoftwareQuery := `
		DELETE FROM software 
		WHERE id NOT IN (SELECT DISTINCT software_id FROM agent_software);
	`
	if _, err := tx.Exec(cleanSoftwareQuery); err != nil {
		logs.DB.Error("Failed to cleanup orphaned software master records", "error", err)
		return
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		logs.DB.Error("Failed to commit maintenance transaction", "error", err)
		return
	}

	logs.Audit.Info("Database maintenance complete: Stale mappings and orphaned software removed.")
}

// -------------------- ARCHIVE HANDLING --------------------------

var ActiveArchives = make(map[string]*sql.DB)
var archiveMutex sync.Mutex

func RegisterArchive(name string, db *sql.DB) {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()
	ActiveArchives[name] = db
}

func CloseAllArchives() {
	archiveMutex.Lock()
	defer archiveMutex.Unlock()
	for name, db := range ActiveArchives {
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
	dsn := fmt.Sprintf("file:%s?mode=ro", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	ActiveArchives[path] = db
	return db, nil
}
