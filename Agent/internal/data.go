// data.go provides functions to handle data packaging and transport as well as other helper functions to meet these goals

package internal

import (
	"Watchtower_EDR/shared"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// establishes a secure connection to the server using its self-signed certificate
var SecureClient *http.Client

func InitSecureClient() error {
	certData, err := os.ReadFile("./internal/server.crt")
	if err != nil {
		return err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(certData)

	SecureClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}
	return nil
}

func getMachineID() string {
	var id string
	var err error

	switch runtime.GOOS {
	case "windows":
		id, err = getWindowsUUID()
	case "linux":
		id, err = getLinuxMachineID()
	default:
		id = "unknown-posix-id"
	}

	if err != nil || id == "" {
		// Fallback: If hardware ID fails, use Hostname (less reliable)
		hostname, _ := os.Hostname()
		return "fallback-" + hostname
	}

	return strings.TrimSpace(strings.ToLower(id))
}

// --- Windows: Pulls the BIOS UUID via WMIC ---
func getWindowsUUID() (string, error) {
	// Executes: wmic csproduct get uuid
	out, err := exec.Command("wmic", "csproduct", "get", "uuid").Output()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) > 1 {
		return strings.TrimSpace(lines[1]), nil
	}
	return "", fmt.Errorf("could not parse wmic output")
}

// --- Linux: Pulls the standard machine-id file ---
func getLinuxMachineID() (string, error) {
	// Standard location for unique machine ID on modern Linux distros
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		// Fallback for older systems
		data, err = os.ReadFile("/var/lib/dbus/machine-id")
	}

	if err != nil {
		return "", err
	}
	return string(data), nil
}

func GetDetailedOSInfo() shared.OSInfo {
	switch runtime.GOOS {
	case "windows":
		return getWindowsVersion()
	case "linux":
		return getLinuxVersion()
	default:
		return shared.OSInfo{OS: runtime.GOOS, OSVersion: "unknown"}
	}
}

// --- Windows: Using 'caption' and 'version' from CIM ---
func getWindowsVersion() shared.OSInfo {
	// We use powershell here because 'wmic' is being deprecated in newer Windows builds
	out, err := exec.Command("powershell", "-Command", "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption").Output()
	if err != nil {
		return shared.OSInfo{OS: "windows", OSVersion: "Unknown Windows"}
	}

	// Example output: Microsoft Windows 11 Pro
	caption := strings.TrimSpace(string(out))
	caption = strings.TrimPrefix(caption, "Microsoft ")

	return shared.OSInfo{
		OS:        "windows",
		OSVersion: caption,
	}
}

// --- Linux: Reading /etc/os-release ---
func getLinuxVersion() shared.OSInfo {
	info := shared.OSInfo{OS: "linux", OSVersion: "generic"}

	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return info
	}

	lines := strings.Split(string(data), "\n")
	var name, version string

	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			name = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	if name != "" {
		info.OS = name
	}
	if version != "" {
		info.OSVersion = version
	}

	return info
}

// uploadData is a helper function that receives an endpoint to POST to and formatted data to marshal and upload
// uploadData now uses the global SecureClient for consistent TLS verification
func uploadData(endpoint string, envelope shared.Envelope) error {
	jsonData, err := json.Marshal(envelope)
	if err != nil {
		return err
	}

	// Create the request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// Use the global SecureClient instead of a local one
	resp, err := SecureClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server error: %s", resp.Status)
	}

	return nil
}

// Heartbeat now handles frequency updates and uses the secure client
func Heartbeat(serverURL string, agentID string) {
	// Default to 60 seconds if config is weird
	freq := AppConfig().Get().HeartbeatFreq * 60
	if freq <= 0 {
		freq = 60
	}

	for {
		hostname, _ := os.Hostname()
		hbData := shared.HeartbeatData{
			AgentID:  agentID,
			Hostname: hostname,
		}

		// 1. MUST marshal the data into the payload first
		payload, _ := json.Marshal(hbData)

		// 2. Wrap it in the Envelope (just like you did for Software)
		envelope := shared.Envelope{
			AgentID:   agentID,
			Timestamp: time.Now(),
			Payload:   payload,
		}

		jsonData, _ := json.Marshal(envelope)

		resp, err := SecureClient.Post(serverURL+"/api/v1/agent/heartbeat", "application/json", bytes.NewBuffer(jsonData))

		if err != nil {
			slog.Error("Heartbeat connection failed", "error", err)
			time.Sleep(60 * time.Second)
			continue
		}

		// 3. Check for Server Errors (Prevent slamming the server on 400/500 errors)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			slog.Warn("Heartbeat rejected by server", "status", resp.Status)
			resp.Body.Close()
			time.Sleep(60 * time.Second)
			continue
		}

		var hbRes shared.HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&hbRes); err == nil {
			if hbRes.TelemetryFrequency > 0 {
				freq = hbRes.TelemetryFrequency
			}
		}
		resp.Body.Close()

		time.Sleep(time.Duration(freq) * time.Second)
	}
}

// HelloPacket uses the secure client for initial enrollment
func HelloPacket(serverURL string, enrollmentToken string) (string, error) {
	hostname, _ := os.Hostname()
	osDetails := GetDetailedOSInfo()

	reg := shared.RegistrationRequest{
		MachineID:     getMachineID(),
		Hostname:      hostname,
		OS:            osDetails.OS,
		OSVersion:     osDetails.OSVersion,
		BinaryVersion: "1.0.0",
		Token:         enrollmentToken,
	}

	jsonData, _ := json.Marshal(reg)

	resp, err := SecureClient.Post(serverURL+"/api/v1/agent/enroll", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("transport error during enrollment: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("enrollment rejected by server: %s", resp.Status)
	}

	var result struct {
		AgentID string `json:"agent_id"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode server response: %v", err)
	}

	// --- NEW: Update the local config.json ---

	// 1. Get the current configuration state
	cfg := AppConfig().Get()

	// 2. Update the field with the new ID from the server
	cfg.AgentID = result.AgentID

	// 3. Commit the change to the file and memory
	if err := AppConfig().Update(cfg); err != nil {
		return result.AgentID, fmt.Errorf("agent enrolled but failed to save config: %v", err)
	}

	return result.AgentID, nil
}

// UploadSoftware remains largely the same but calls the updated uploadData
func UploadSoftware(serverURL string, agentID string) error {
	softwareList, err := CollectSoftwareData()
	if err != nil {
		return err
	}

	payload, err := json.Marshal(softwareList)
	if err != nil {
		return err
	}

	envelope := shared.Envelope{
		AgentID:   agentID,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	// This now internally uses SecureClient via the updated uploadData function
	return uploadData(serverURL+"/api/v1/agent/telemetry/software", envelope)
}
