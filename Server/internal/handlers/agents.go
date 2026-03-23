package handlers

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"

	"Watchtower_EDR/shared"
)

// BuildAgentInstaller builds the script used to install an agent on a system
func BuildAgentInstaller() {
	slog.Info("building agent installer script", "fqdn", "watchtower.local")
}

// AddAgent handles the 'Hello' enrollment request from a new agent.
func AddAgent(w http.ResponseWriter, r *http.Request) {
	var req shared.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Error("failed to decode enrollment request", "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid enrollment data", http.StatusBadRequest)
		return
	}

	// Logic to save agent to your DB goes here
	slog.Info("new agent enrollment request",
		"hostname", req.Hostname,
		"os", req.OS,
		"remote_addr", r.RemoteAddr,
	)

	w.WriteHeader(http.StatusCreated)
}

// RemoveAgent removes an agent from the database using a provided agentID.
func RemoveAgent(agentID string) {
	slog.Warn("removing agent from database", "agent_id", agentID)
}

// handleTelemetry processes the incoming Enveloped data.
func handleTelemetry(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("failed to read telemetry body", "error", err)
		http.Error(w, "Read error", http.StatusInternalServerError)
		return
	}

	var env shared.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		slog.Error("failed to unmarshal envelope", "error", err, "remote_addr", r.RemoteAddr)
		http.Error(w, "Invalid envelope", http.StatusBadRequest)
		return
	}

	// Structured logging with the AgentID and Type
	l := slog.With("agent_id", env.AgentID, "event_type", env.Type)

	switch env.Type {
	case "PROCESS":
		l.Info("telemetry received", "timestamp", env.Timestamp)
		// Process env.Payload...
	case "NETWORK":
		l.Info("telemetry received")
		// Process env.Payload...
	case "SOFTWARE":
		l.Info("software inventory received")
	default:
		l.Warn("unknown telemetry type received")
	}

	w.WriteHeader(http.StatusAccepted)
}

// StartAgentAPIServer initializes all the API endpoints and starts the TLS server.
func StartAgentAPIServer() {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/enroll", AddAgent)
	mux.HandleFunc("POST /api/v1/telemetry", handleTelemetry)

	server := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	slog.Info("Watchtower EDR Agent API starting",
		"addr", server.Addr,
		"protocol", "https",
	)

	// ListenAndServeTLS returns an error; we log it and exit if it fails
	if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil {
		slog.Error("server failed to start", "error", err)
		log.Fatal(err)
	}
}
