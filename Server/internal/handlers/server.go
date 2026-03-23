// server.go initializes the Watchtower EDR server, assigns routes,

package handlers

import (
	"Watchtower_EDR/server/internal"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
)

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

// StartServer starts the TLS server on the defined port and initializes endpoints
// Returns an error value through a channel
func StartServer(errChan chan<- error) {

	// Ensure certificate and key are installed
	err := SetupCertificates(internal.AppConfig.Server.FQDN)
	if err != nil {
		slog.Error("Failed to setup TLS certificates", "error", err, "action", "Exiting")
		errChan <- err
		return
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

	slog.Info("Watchtower EDR Server starting",
		"port", "443",
		"fqdn", internal.AppConfig.Server.FQDN,
	)

	// Start as HTTPS
	certPath := "./internal/data/server.crt"
	keyPath := "./internal/data/server.key"
	err = server.ListenAndServeTLS(certPath, keyPath)
	if err != nil && err != http.ErrServerClosed {
		slog.Error("Watchtower server crashed", "error", err)
		os.Exit(1)
	}
}
