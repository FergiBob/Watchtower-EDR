package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

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

// StartStatusMonitor kicks off a background goroutine that marks stale agents as offline
func StartStatusMonitor(ctx context.Context) {
	// Run every minute
	ticker := time.NewTicker(1 * time.Minute)

	logs.Sys.Info("Starting background agent status monitor")

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				MonitorAgentStatus()
			case <-ctx.Done():
				logs.Sys.Info("Stopping background agent status monitor...")
				return
			}
		}
	}()
}

// MonitorAgentStatus performs the actual database update logic
func MonitorAgentStatus() {
	// Pull the threshold from your config
	offlineLimit := fmt.Sprintf("-%d minutes", internal.AppConfig.Agents.OfflineTimer)

	query := `
		UPDATE agents 
		SET status = 'offline' 
		WHERE status = 'active' 
		AND last_seen < datetime('now', ?)` // Use 'now' or 'localtime' to match your DB storage

	err := data.WriteQuery(data.Main_Database, query, offlineLimit)
	if err != nil {
		logs.DB.Error("Failed to run background status monitor", "error", err)
	}
}

// --------------------------------------------------------------------------------------------
//
//  AGENT HANDLERS
//
// --------------------------------------------------------------------------------------------

func ToIPv4(remoteAddr string) string {
	// 1. Remove the port
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // Fallback if no port exists
	}

	// 2. Parse the IP
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}

	// 3. Convert to IPv4
	// To4() returns nil if the address is not an IPv4 address
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}

	// Return the original host if it's true IPv6 (and can't be IPv4)
	return host
}

// handleAgentEnrollment parses and handles an agent enrollment request
func handleAgentEnrollment(w http.ResponseWriter, r *http.Request) {
	var req shared.RegistrationRequest

	ipv4Addr := ToIPv4(r.RemoteAddr)

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logs.Sys.Warn("Failed to decode agent enrollment request", "remote_addr", ipv4Addr, "error", err)
		http.Error(w, "Invalid data", http.StatusBadRequest)
		return
	}

	// Verify the enrollment token matches the one in the server config
	if req.Token != internal.AppConfig.Agents.EnrollmentToken {
		logs.Audit.Warn("Unauthorized enrollment attempt", "ip", ipv4Addr, "hostname", req.Hostname)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Write to database
	agentID, err := EnrollAgent(req, ipv4Addr)
	if err != nil {
		logs.DB.Error("Failed to enroll agent", "hostname", req.Hostname, "error", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	logs.Audit.Info("Agent enrolled successfully", "agent_id", agentID, "hostname", req.Hostname, "ip", ipv4Addr)

	// Respond with the new AgentID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"agent_id": agentID})
}

// HandleHeartbeat handles updating agent data and replying with server-side changes
func HandleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var env shared.Envelope

	ipv4Addr := ToIPv4(r.RemoteAddr)

	// Decode the standard Envelope
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		logs.Sys.Warn("Failed to decode heartbeat envelope", "remote_addr", ipv4Addr, "error", err)
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
	resp, err := UpdateAgentData(env.AgentID, hbData.Hostname, ipv4Addr)
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
		logs.Sys.Warn("Failed to decode OS telemetry envelope", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	var osData shared.OSInfo
	if err := json.Unmarshal(env.Payload, &osData); err != nil {
		logs.Sys.Warn("Failed to decode OS payload", "agent_id", env.AgentID, "error", err)
		http.Error(w, "Invalid Payload", http.StatusBadRequest)
		return
	}

	// Updated Query to include os_name and os_build
	query := `
        UPDATE agents 
        SET os = ?, 
            os_name = ?, 
            os_version = ?, 
            os_build = ?, 
            last_seen = CURRENT_TIMESTAMP 
        WHERE agent_id = ?`

	err := data.WriteQuery(data.Main_Database, query,
		osData.OS,
		osData.OSName,
		osData.OSVersion,
		osData.OSBuild,
		env.AgentID,
	)

	if err != nil {
		logs.DB.Error("Failed to update agent OS info", "agent_id", env.AgentID, "error", err)
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}

	logs.Sys.Info("OS telemetry updated",
		"agent_id", env.AgentID,
		"os", osData.OS,
		"build", osData.OSBuild,
	)

	// NEW: Kick off the CPE Generator for the OS
	// This function will take the OSName/Build and turn it into a CPE string
	go data.SearchDictionaryForOSCPE(env.AgentID, osData)

	w.WriteHeader(http.StatusOK)
}

// ---------------- INSTALLATION SCRIPTS -----------------------

func generateWindowsScript(fqdn, token, certPEM string) string {
	encodedCert := base64.StdEncoding.EncodeToString([]byte(certPEM))

	return fmt.Sprintf(`# Watchtower EDR Windows Installer
$ErrorActionPreference = "Stop"

$ServerURL = "https://%s"
$EnrollToken = "%s"
$EncodedCert = "%s"

Write-Host "--- Watchtower EDR Deployment ---" -ForegroundColor Cyan

# 1. Path Setup
$InstallDir = "C:\Program Files\Watchtower"
$InternalDir = "$InstallDir\internal"
$LogDir = "$InternalDir\logs"

if (!(Test-Path $LogDir)) { 
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null 
}

# 2. Decode and Write Cert
$CertPath = "$InternalDir\server.crt"
if ([string]::IsNullOrEmpty($EncodedCert)) {
    Write-Host "ERROR: Certificate data is missing from script!" -ForegroundColor Red
    exit
}

Write-Host "[*] Writing certificate to $CertPath..."
$CertBytes = [System.Convert]::FromBase64String($EncodedCert)
[System.IO.File]::WriteAllBytes($CertPath, $CertBytes)

# 3. Create config.json
$ConfigPath = "$InstallDir\config.json"
if (!(Test-Path $ConfigPath)) {
    Write-Host "[*] Creating config file..."
    $cfg = @{ agent_id = ""; upload_interval_minutes = 5; heartbeat_interval_minutes = 1 } | ConvertTo-Json
    $cfg | Out-File -FilePath $ConfigPath -Encoding ascii
}

# 4. Download Agent
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$AgentPath = "$InstallDir\watchtower-agent.exe"

Write-Host "[*] Downloading agent..."
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("$ServerURL/api/v1/download/agent-windows", $AgentPath)

# 5. Service Management
if (Get-Service "WatchtowerAgent" -ErrorAction SilentlyContinue) {
    Stop-Service "WatchtowerAgent" -Force
    & sc.exe delete WatchtowerAgent | Out-Null
}

$BinPath = '"{0}" -url {1} -token {2}' -f $AgentPath, $ServerURL, $EnrollToken
New-Service -Name "WatchtowerAgent" -BinaryPathName $BinPath -DisplayName "Watchtower EDR Agent" -StartupType Automatic | Out-Null

Start-Service "WatchtowerAgent"
Write-Host "[+] Installation Complete." -ForegroundColor Green
`, fqdn, token, encodedCert)
}

func generateLinuxScript(fqdn, token, certPEM string) string {
	return fmt.Sprintf(`#!/bin/bash
# Watchtower EDR Linux Installer

SERVER_URL="https://%s"
TOKEN="%s"
CERT_PEM='%s'

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "--- Watchtower EDR Deployment ---"

# 1. Cleanup existing instance
if systemctl is-active --quiet watchtower-agent; then
    echo "[*] Stopping existing agent..."
    systemctl stop watchtower-agent
fi

if [ -f "/etc/systemd/system/watchtower-agent.service" ]; then
    systemctl disable watchtower-agent
    rm -f /etc/systemd/system/watchtower-agent.service
fi

# 2. Setup Environment
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/watchtower"
mkdir -p $CONF_DIR
echo "$CERT_PEM" > "$CONF_DIR/server.crt"

# 3. Download Agent Binary
echo "[*] Downloading agent from $SERVER_URL..."
curl -L "$SERVER_URL/api/v1/download/agent-linux" -o "$INSTALL_DIR/watchtower-agent"
chmod +x "$INSTALL_DIR/watchtower-agent"

# 4. Create Systemd Service
cat <<EOF > /etc/systemd/system/watchtower-agent.service
[Unit]
Description=Watchtower EDR Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/watchtower-agent -url $SERVER_URL -token $TOKEN
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 5. Start Service
echo "[*] Starting Watchtower service..."
systemctl daemon-reload
systemctl enable watchtower-agent
systemctl start watchtower-agent

echo "[+] Installation Complete."
`, fqdn, token, certPEM)
}
