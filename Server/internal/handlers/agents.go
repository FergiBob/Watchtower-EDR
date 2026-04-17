package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/logs" // Use the custom tiered logging package
	"Watchtower_EDR/shared"

	"github.com/google/uuid"
)

// BuildAgentInstaller builds the script used to install an agent on a system
func BuildAgentInstaller() {
	logs.Sys.Info("building agent installer script", "fqdn", internal.AppConfig.Server.FQDN)
}

// --------------------------------------------------------------------------------------------
//
//                            HELPER FUNCTIONS FOR AGENT HANDLERS
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
		logs.DB.Error("Failed to execute EnrollAgent query", "error", err, "machine_id", req.MachineID)
		return "", err
	}

	return newAgentID, nil
}

func UpdateAgentData(agentID string, hostname string, remoteAddr string) (shared.HeartbeatResponse, error) {
	resp := shared.HeartbeatResponse{
		TelemetryFrequency: internal.AppConfig.Agents.TelemetryFrequency,
	}

	// FIX: Use the READ pool for the status check
	queryStatus := `SELECT status FROM agents WHERE agent_id = ?`
	err := data.QuerySingleRow(data.Main_Read_Database, queryStatus, []any{agentID}, &resp.Status)
	if err != nil {
		return resp, err
	}

	if resp.Status == "decommissioned" {
		return resp, nil
	}

	queryUpdate := `
        UPDATE agents 
        SET hostname = ?, ip_address = ?, last_seen = CURRENT_TIMESTAMP, status = 'active'
        WHERE agent_id = ?`

	// WriteQuery now handles the PriorityLock and the Transaction for you
	err = data.WriteQuery(data.Main_Database, queryUpdate, hostname, remoteAddr, agentID)
	return resp, err
}

func UpdateAgentDescription(agentID string, description string) error {
	query := `
    UPDATE agents 
    SET 
        description = ?
    WHERE agent_id = ?`

	err := data.WriteQuery(data.Main_Database, query, description, agentID)
	if err != nil {
		logs.DB.Error("Failed to update agent description", "agent_id", agentID, "error", err)
	}
	return err
}

// RemoveAgent removes an agent from the database using a provided agentID.
func RemoveAgent(agentID string) error {
	logs.Audit.Warn("Agent decommissioning triggered", "agent_id", agentID)

	query := `UPDATE agents SET status = 'decommissioned', last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?`

	err := data.WriteQuery(data.Main_Database, query, agentID)
	if err != nil {
		logs.DB.Error("Failed to mark agent as decommissioned", "agent_id", agentID, "error", err)
	}
	return err
}

// --------------------------------------------------------------------------------------------
//
//  AGENT HANDLERS
//
// --------------------------------------------------------------------------------------------

// handleAgentEnrollment parses and handles an agent enrollment request
func handleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	var req shared.RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logs.Sys.Warn("Failed to decode agent enrollment request", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Verify the enrollment token matches the one in the server config
	if req.Token != internal.AppConfig.Agents.EnrollmentToken {
		logs.Audit.Warn("Unauthorized enrollment attempt", "ip", r.RemoteAddr, "hostname", req.Hostname)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Write to database
	agentID, err := EnrollAgent(req, r.RemoteAddr)
	if err != nil {
		logs.DB.Error("Failed to enroll agent", "hostname", req.Hostname, "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	logs.Audit.Info("Agent enrolled successfully", "agent_id", agentID, "hostname", req.Hostname, "ip", r.RemoteAddr)

	// Respond with the new AgentID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"agent_id": agentID})
}

// HandleHeartbeat handles updating agent data and replying with server-side changes
func HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var env shared.Envelope

	// Decode the standard Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		logs.Sys.Warn("Failed to decode heartbeat envelope", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Decode the HeartbeatData from the Payload
	var hbData shared.HeartbeatData
	if err := json.Unmarshal(env.Payload, &hbData); err != nil {
		logs.Sys.Warn("Failed to decode heartbeat payload", "agent_id", env.AgentID, "error", err)
		http.Error(w, "Invalid Payload", http.StatusBadRequest)
		return
	}

	// Update database using the received envelope
	resp, err := UpdateAgentData(env.AgentID, hbData.Hostname, r.RemoteAddr)
	if err != nil {
		logs.DB.Warn("Heartbeat update failed (Agent likely not enrolled)", "agent_id", env.AgentID, "error", err)
		http.Error(w, "Agent not found", http.StatusNotFound)
		return
	}

	// Send back the configuration response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logs.Sys.Error("Failed to encode heartbeat response", "agent_id", env.AgentID, "error", err)
	}
}

// HandleSoftwareTelemetry receives Client software payload and updates inventory
func HandleSoftwareTelemetry(w http.ResponseWriter, r *http.Request) {
	var env shared.Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var softwareList []shared.Software
	if err := json.Unmarshal(env.Payload, &softwareList); err != nil {
		http.Error(w, "Invalid Payload", http.StatusBadRequest)
		return
	}

	// 1. Manually lock the writer for the duration of this agent's update
	data.PriorityLock.Lock()
	defer data.PriorityLock.Unlock()

	tx, err := data.Main_Database.Begin()
	if err != nil {
		http.Error(w, "DB Busy", 503)
		return
	}
	defer tx.Rollback()

	tx.Exec(`UPDATE agents SET last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?`, env.AgentID)
	tx.Exec("DELETE FROM agent_software WHERE agent_id = ?", env.AgentID)

	for _, s := range softwareList {
		var softwareID int64
		err := tx.QueryRow(`SELECT id FROM software WHERE name=? AND version=? AND vendor=?`,
			s.Name, s.Version, s.Manufacturer).Scan(&softwareID)

		if err == sql.ErrNoRows {
			res, err := tx.Exec(`INSERT INTO software (name, version, vendor) VALUES (?, ?, ?)`,
				s.Name, s.Version, s.Manufacturer)
			if err != nil {
				continue
			}
			softwareID, _ = res.LastInsertId()
		}

		tx.Exec(`INSERT INTO agent_software (agent_id, software_id, install_date) VALUES (?, ?, ?)`,
			env.AgentID, softwareID, s.Date)
	}

	if err := tx.Commit(); err != nil {
		logs.DB.Error("Telemetry commit failed", "error", err)
		http.Error(w, "Retry Later", 500)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleOSTelemetry receives OS details, updates the agent record, and triggers a vulnerability check
func HandleOSTelemetry(w http.ResponseWriter, r *http.Request) {
	var env shared.Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		logs.Sys.Warn("Failed to decode OS telemetry envelope", "remote_addr", r.RemoteAddr, "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var osData shared.OSInfo // Assuming shared.OSInfo exists with OS and OSVersion
	if err := json.Unmarshal(env.Payload, &osData); err != nil {
		logs.Sys.Warn("Failed to decode OS payload", "agent_id", env.AgentID, "error", err)
		http.Error(w, "Invalid Payload", http.StatusBadRequest)
		return
	}

	// Update the agent's OS information
	query := `UPDATE agents SET os = ?, os_version = ?, last_seen = CURRENT_TIMESTAMP WHERE agent_id = ?`
	err := data.WriteQuery(data.Main_Database, query, osData.OS, osData.OSVersion, env.AgentID)
	if err != nil {
		logs.DB.Error("Failed to update agent OS information", "agent_id", env.AgentID, "error", err)
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	logs.Sys.Info("OS telemetry updated", "agent_id", env.AgentID, "os", osData.OS, "version", osData.OSVersion)

	// Trigger vulnerability mapping for the updated OS
	// In a real scenario, you'd likely call your Mapper logic here or queue a job
	// data.MapCVEsForAgent(env.AgentID)

	w.WriteHeader(http.StatusOK)
}
