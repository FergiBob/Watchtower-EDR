// server.go initializes the Watchtower EDR server, assigns routes,

package handlers

import (
	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/logs" // Updated to use the tiered logging system
	"crypto/tls"
	"net/http"
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
	fileServer := http.FileServer(http.Dir("./web/public"))
	mux.Handle("/public/", http.StripPrefix("/public/", fileServer))

	// --- WEB UI ROUTES ---
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/logout", LogoutHandler)

	// Protected Routes via AuthMiddleware
	mux.Handle("/", AuthMiddleware(http.HandlerFunc(homeHandler)))
	mux.Handle("/settings", AuthMiddleware(http.HandlerFunc(settingsHandler)))
	mux.Handle("/server/shutdown", AuthMiddleware(http.HandlerFunc(HandleShutdown)))

	// Wrap mux in a recovery handler to prevent server crashes on fatal endpoint errors
	safeHandler := RecoveryMiddleware(mux)

	// Configure TLS
	server := &http.Server{
		Addr:    ":443",
		Handler: safeHandler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	logs.Sys.Info("Watchtower Server configured", "port", "443", "tls", "1.2+")

	return server, nil
}
