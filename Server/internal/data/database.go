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
	// Main_Database is the EXCLUSIVE WRITER (SetMaxOpenConns = 1)
	Main_Database *sql.DB

	// Main_Read_Database is the CONCURRENT READER (SetMaxOpenConns = 0)
	Main_Read_Database *sql.DB

	User_Database *sql.DB
	CPE_Database  *sql.DB
	CVE_Database  *sql.DB

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
		// The closure ensures tx.Rollback() clears connection state BEFORE the next retry loop
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
		// Retry if database is locked or driver state is conflicted
		if strings.Contains(err.Error(), "locked") || strings.Contains(err.Error(), "transaction") {
			time.Sleep(time.Duration(i+1) * 50 * time.Millisecond)
			continue
		}
		break
	}
	return lastErr
}

// ReadQuery executes a read operation and returns rows
func ReadQuery(db *sql.DB, query string, params ...interface{}) (*sql.Rows, error) {
	rows, err := db.Query(query, params...)
	if err != nil {
		logs.DB.Error("Failed to execute read query", "query", query, "error", err)
		return nil, err
	}
	return rows, nil
}

// QuerySingleRow simplifies read queries that only return one row
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

	mode := "rwc"
	if readOnly {
		mode = "ro"
	}

	// dsn includes busy_timeout (10s) and WAL mode for concurrent performance
	dsn := fmt.Sprintf("file:%s?mode=%s&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path, mode)

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

	Main_Database = initDB(internal.AppConfig.Database.MainDB, 1, false)
	Main_Read_Database = initDB(internal.AppConfig.Database.MainDB, 0, true)
	User_Database = initDB(internal.AppConfig.Database.UserDB, 1, false)
	CPE_Database = initDB(internal.AppConfig.Database.CpeDB, 1, false)
	CVE_Database = initDB(internal.AppConfig.Database.CveDB, 1, false)
}

func CloseDatabases() {
	logs.Sys.Info("Closing all database connections...")
	dbs := map[string]*sql.DB{
		"Main_Write": Main_Database, "Main_Read": Main_Read_Database,
		"User": User_Database, "CPE": CPE_Database, "CVE": CVE_Database,
	}
	for _, db := range dbs {
		if db != nil {
			db.Close()
		}
	}
	CloseAllArchives()
	logs.Sys.Info("Databases closed successfully")
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
		deprecated INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_cpe_search ON cpe_dictionary(vendor, product, version);
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
		description TEXT, severity TEXT,
		cvss_score REAL, published TEXT
	);
	CREATE TABLE IF NOT EXISTS software_vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cve_id TEXT, cpe_uri TEXT,
		version_start TEXT, version_end TEXT,
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
	logs.DB.Info("Vulnerability Database schema verified/initialized")
}

func setupMainSQL(db *sql.DB) {
	query := `
	PRAGMA foreign_keys = ON;
	CREATE TABLE IF NOT EXISTS agents (
		agent_id TEXT PRIMARY KEY, machine_id TEXT UNIQUE, 
		hostname TEXT, ip_address TEXT, os TEXT, os_version TEXT, os_cpe_uri TEXT,
		status TEXT DEFAULT 'active', last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS software (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		cpe_uri TEXT UNIQUE, name TEXT, version TEXT, vendor TEXT
	);
	CREATE TABLE IF NOT EXISTS agent_software (
		agent_id TEXT, software_id INTEGER, install_date TEXT,
		PRIMARY KEY (agent_id, software_id),
		FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE,
		FOREIGN KEY (software_id) REFERENCES software(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS discovered_vulnerabilities (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL, target_type TEXT NOT NULL,
		software_id INTEGER, cpe_uri TEXT, cve_id TEXT NOT NULL,
		severity TEXT, cvss_score REAL, detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		status TEXT DEFAULT 'open',
		UNIQUE(agent_id, target_type, software_id, cve_id)
	);`
	if err := WriteQuery(db, query); err != nil {
		logs.Sys.Error("Main database initialization failed", "error", err)
		os.Exit(1)
	}
	logs.DB.Info("Main Database schema verified/initialized")
}

func CleanupOrphans() {
	query := `DELETE FROM software WHERE id NOT IN (SELECT DISTINCT software_id FROM agent_software);`
	if err := WriteQuery(Main_Database, query); err != nil {
		logs.DB.Error("Failed to cleanup orphaned database records", "error", err)
	} else {
		logs.Audit.Info("Orphaned software records cleaned up successfully")
	}
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
