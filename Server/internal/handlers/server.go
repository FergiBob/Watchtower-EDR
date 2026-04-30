// server.go initializes the Watchtower EDR server, assigns routes,

package handlers

import (
	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/logs" // Updated to use the tiered logging system
	"crypto/tls"
	"net/http"
	"path/filepath"
	"time"
)

var ShutdownChan = make(chan bool, 1)

// RecoveryMiddleware wraps a server mux in a recovery block to prevent fatal errors breaking server functionality
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Log as a System Error: This represents a bug or unexpected crash in the code logic
				logs.Sys.Error("CRITICAL PANIC RECOVERED", "error", err, "url", r.URL.Path, "method", r.Method)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func HandleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	csrfCookie, err := r.Cookie("csrf_token")
	csrfHeader := r.Header.Get("X-CSRF-Token")

	if err != nil || csrfHeader == "" || csrfCookie.Value != csrfHeader {
		logs.Audit.Warn("Security Alert: CSRF validation failed on shutdown attempt", "remote_addr", r.RemoteAddr, "header_present", csrfHeader != "")
		http.Error(w, "Security validation failed (CSRF)", http.StatusForbidden)
		return
	}

	username, err := GetUsernameFromToken(r)
	if err != nil {
		// Log as an Audit Warning: Someone attempted a shutdown without a valid session
		logs.Audit.Warn("Unauthorized shutdown attempt", "remote_addr", r.RemoteAddr, "error", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Log as a critical Audit event: Tracking which admin is taking the EDR offline
	logs.Audit.Warn("CRITICAL: Server shutdown initiated via Web UI", "user", username)

	// Give the user a response so they don't get a "Connection Reset" error
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Shutdown initiated. Watchtower is going offline..."))

	go func() {
		time.Sleep(1 * time.Second)
		// Push true as a shutdown signal
		ShutdownChan <- true
	}()
}

// BuildServer starts the TLS server on the defined port and initializes endpoints
func BuildServer() (*http.Server, error) {

	// Ensure certificate and key are installed
	err := SetupCertificates(internal.AppConfig.Server.FQDN)
	if err != nil {
		// System Error: The server cannot boot without its identity/encryption
		logs.Sys.Error("Failed to setup TLS certificates", "error", err, "action", "Exiting")
		return nil, err
	}

	// Create shared multiplexer
	mux := http.NewServeMux()

	// --- AGENT API ---
	// Machine-to-machine traffic
	mux.HandleFunc("POST /api/v1/agent/enroll", handleAgentEnrollment)
	mux.HandleFunc("POST /api/v1/agent/heartbeat", HandleHeartbeat)
	mux.HandleFunc("POST /api/v1/agent/telemetry/software", HandleSoftwareTelemetry)
	mux.HandleFunc("POST /api/v1/agent/telemetry/os", HandleOSTelemetry)

	// --- WEB UI PUBLIC ASSETS ---
	publicFolder := filepath.Join(internal.BaseDir, "web", "public")
	fileServer := http.FileServer(http.Dir(publicFolder))
	mux.Handle("/public/", http.StripPrefix("/public/", fileServer))

	// Endpoint for Windows Agent download
	mux.HandleFunc("/api/v1/download/agent-windows", func(w http.ResponseWriter, r *http.Request) {
		// Construct absolute path relative to the binary location
		filePath := filepath.Join(internal.BaseDir, "web", "downloads", "windows", "agent-windows.exe")
		http.ServeFile(w, r, filePath)
	})

	// Endpoint for Linux Agent download
	mux.HandleFunc("/api/v1/download/agent-linux", func(w http.ResponseWriter, r *http.Request) {
		// Construct absolute path relative to the binary location
		filePath := filepath.Join(internal.BaseDir, "web", "downloads", "linux", "agent-linux")
		http.ServeFile(w, r, filePath)
	})

	// --- WEB UI ROUTES ---
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/logout", LogoutHandler)

	// Protected Routes via AuthMiddleware

	mux.Handle("/api/v1/users/{username}", AuthMiddleware(http.HandlerFunc(UserResourceHandler)))

	mux.Handle("/vulnerabilities", AuthMiddleware(http.HandlerFunc(VulnerabilitiesPageHandler)))
	mux.Handle("/api/v1/vulnerabilities/{id}", AuthMiddleware(http.HandlerFunc(VulnerabilityResourceHandler)))
	mux.Handle("/api/v1/vulnerabilities/scan", AuthMiddleware(http.HandlerFunc(ScanCVEs)))

	mux.Handle("/settings", AuthMiddleware(http.HandlerFunc(settingsHandler)))
	mux.Handle("/server/shutdown", AuthMiddleware(http.HandlerFunc(HandleShutdown)))

	// Software web routes
	mux.Handle("/software", AuthMiddleware(http.HandlerFunc(softwareHandler)))
	mux.Handle("/api/cpe/search", AuthMiddleware(http.HandlerFunc(CPESearchHandler)))
	mux.Handle("/api/software/{id}/cpe", AuthMiddleware(http.HandlerFunc(SoftwareCPEHandler)))

	// Agents web routes
	mux.Handle("GET /agents", AuthMiddleware(http.HandlerFunc(AgentsPageHandler)))
	mux.Handle("GET /api/agent/{id}", AuthMiddleware(http.HandlerFunc(GetAgentDetailsHandler)))
	mux.Handle("POST /api/agent/{id}/metadata", AuthMiddleware(http.HandlerFunc(UpdateAgentMetadataHandler)))
	mux.Handle("POST /api/agent/{id}/decommission", AuthMiddleware(http.HandlerFunc(DecommissionAgentHandler)))
	mux.HandleFunc("/api/installer/generate", InstallerGeneratorHandler)

	mux.Handle("/", AuthMiddleware(http.HandlerFunc(homeHandler)))

	// Wrap mux in a recovery handler to prevent server crashes on fatal endpoint errors
	safeHandler := RecoveryMiddleware(mux)

	// Configure TLS
	server := &http.Server{
		Addr:    ":443",
		Handler: safeHandler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	logs.Sys.Info("Watchtower Server configured", "port", "443", "tls", "1.2+")

	return server, nil
}
