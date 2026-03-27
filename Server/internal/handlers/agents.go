package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/shared"

	"github.com/google/uuid"
)

// BuildAgentInstaller builds the script used to install an agent on a system
func BuildAgentInstaller() {
	slog.Info("building agent installer script", "fqdn", internal.AppConfig.Server.FQDN)
}

// --------------------------------------------------------------------------------------------
//
//                            HELPER FUNCTIONS FOR AGENT HANDLERS
//
// --------------------------------------------------------------------------------------------

func EnrollAgent(req shared.RegistrationRequest, remoteAddr string) (string, error) {
	// Generate a new session/agent ID for this specific installation
	id, _ := uuid.NewV7()
	newAgentID := id.String()

	// Insert Agent data, or update if agent already exists and is being re-enrolled
	query := `
    INSERT INTO agents (
        agent_id, machine_id, hostname, ip_address, 
        os, os_version, status, binary_version, first_seen, last_seen
    ) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
    ON CONFLICT(machine_id) DO UPDATE SET
        agent_id = excluded.agent_id,       -- Update to the newest session ID
        ip_address = excluded.ip_address,   -- Update if they moved networks
        hostname = excluded.hostname,       -- Update if they renamed the PC
        os_version = excluded.os_version,   -- Update if they patched the OS
        binary_version = excluded.binary_version,
        status = 'active',
        last_seen = CURRENT_TIMESTAMP;      -- Refresh the timestamp
    `

	// Execute query
	err := data.WriteQuery(data.Main_Database, query,
		newAgentID,
		req.MachineID,
		req.Hostname,
		remoteAddr,
		req.OS,
		req.OSVersion,
		req.BinaryVersion,
	)

	if err != nil {
		return "", err
	}

	return newAgentID, nil
}

func UpdateAgentData(agentID string, hostname string, remoteAddr string) (shared.HeartbeatResponse, error) {
	// Initialize response with default frequency from global config
	resp := shared.HeartbeatResponse{
		TelemetryFrequency: internal.AppConfig.Agents.TelemetryFrequency,
	}

	// Get the current status
	queryStatus := `SELECT status FROM agents WHERE agent_id = ?`
	err := data.QuerySingleRow(data.Main_Database, queryStatus, []any{agentID}, &resp.Status)
	if err != nil {
		return resp, err // Agent likely doesn't exist
	}

	// If decommissioned, stop here
	if resp.Status == "decommissioned" {
		return resp, nil
	}

	// Update metadata for active agents
	queryUpdate := `
        UPDATE agents 
        SET hostname = ?, ip_address = ?, last_seen = CURRENT_TIMESTAMP, status = 'active'
        WHERE agent_id = ?`

	err = data.WriteQuery(data.Main_Database, queryUpdate, hostname, remoteAddr, agentID)

	return resp, err
}

func UpdateAgentDescription(agentID string, description string) error {
	query := `
    UPDATE agents 
    SET 
        description = ?
    WHERE agent_id = ?`

	return data.WriteQuery(data.Main_Database, query, description, agentID)
}

// RemoveAgent removes an agent from the database using a provided agentID.
func RemoveAgent(agentID string) error {
	slog.Warn("decommissioning agent", "agent_id", agentID)

	query := `UPDATE agents SET status = 'decommissioned', last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?`

	return data.WriteQuery(data.Main_Database, query, agentID)
}

// --------------------------------------------------------------------------------------------
//
//	AGENT HANDLERS
//
// --------------------------------------------------------------------------------------------

// Parses and handles an agent enrollment request
func handleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	var req shared.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Verify the enrollment token matches the one in the server config
	if req.Token != internal.AppConfig.Agents.EnrollmentToken {
		slog.Warn("Unauthorized enrollment attempt", "ip", r.RemoteAddr, "hostname", req.Hostname)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Write to database
	agentID, err := EnrollAgent(req, r.RemoteAddr)
	if err != nil {
		slog.Error("Failed to save agent", "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	slog.Info("Agent enrolled successfully", "agent_id", agentID)

	// Respond with the new AgentID
	// The agent MUST save this ID and use it for all future telemetry
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"agent_id": agentID})
}

// Handles updating agent data and replying with any server-side changes to the agent
// Response to agent's heartbeat (ping)
func HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req shared.HeartbeatData

	// 1. Decode JSON into HeartbeatData struct
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		slog.Warn("failed to decode heartbeat", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Update database and get the current config/status for this agent
	resp, err := UpdateAgentData(req.AgentID, req.Hostname, r.RemoteAddr)
	if err != nil {
		slog.Error("Heartbeat update failed", "agent_id", req.AgentID, "error", err)

		// If the agent doesn't exist in the DB, return 404 so it knows to re-enroll
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	// Send the config back to the agent
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("Failed to encode heartbeat response", "agent_id", req.AgentID, "error", err)
	}
}

func HandleSoftwareTelemetry(w http.ResponseWriter, r *http.Request) {

}
