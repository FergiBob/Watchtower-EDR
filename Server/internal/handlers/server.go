// server.go initializes the Watchtower EDR server, assigns routes,

package handlers

import (
	"Watchtower_EDR/server/internal"
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"
)

var ShutdownChan = make(chan bool, 1)

// Wraps a server mux in a recovery block to prevent fatal errors breaking server functionality
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("CRITICAL PANIC RECOVERED", "error", err, "url", r.URL.Path, "method", r.Method)
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

	username, err := GetUsernameFromToken(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		slog.Error("Shutdown attempted. Failed to verify username", "error", err)
		return
	}
	slog.Warn("CRITICAL: Server shutdown initiated via Web UI", "user", username)

	// Give the user a response so they don't get a "Connection Reset" error
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Shutdown initiated. Watchtower is going offline..."))

	go func() {
		time.Sleep(1 * time.Second)
		// Simply push a 'true' into the channel
		ShutdownChan <- true
	}()
}

// StartServer starts the TLS server on the defined port and initializes endpoints
// Returns an error value through a channel
func BuildServer() (*http.Server, error) {

	// Ensure certificate and key are installed
	err := SetupCertificates(internal.AppConfig.Server.FQDN)
	if err != nil {
		slog.Error("Failed to setup TLS certificates", "error", err, "action", "Exiting")
		return nil, err

	}

	// Create shared multiplexer
	mux := http.NewServeMux()

	// --- AGENT API ---
	// Machine-to-machine traffic
	mux.HandleFunc("POST /api/v1/agent/enroll", AddAgent)
	mux.HandleFunc("POST /api/v1/agent/telemetry", handleTelemetry)

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

	return server, nil
}
