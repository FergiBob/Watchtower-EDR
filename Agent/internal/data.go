// data.go provides functions to handle data packaging and transport as well as other helper functions to meet these goals

package internal

import (
	"Watchtower_EDR/shared"
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// establishes a secure connection to the server using its self-signed certificate
var SecureClient *http.Client

func InitSecureClient() error {
	// Get absolute path to the EXE to prevent Service Working Directory issues
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	basePath := filepath.Dir(exePath)
	certPath := filepath.Join(basePath, "internal", "server.crt")

	certData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read cert at %s: %w", certPath, err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(certData)

	SecureClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
				// CRITICAL: Must match the CN/SAN in your server.crt
				ServerName: "watchtower.local",
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

func getWindowsVersion() shared.OSInfo {
	info := shared.OSInfo{OS: "windows", OSName: "Windows", OSVersion: "Unknown", OSBuild: "Unknown", Vendor: "Microsoft", Architecture: "Unknown"}

	script := `
		$os = Get-CimInstance Win32_OperatingSystem
		$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
		$properties = Get-ItemProperty $regPath
		
		# Combine BuildNumber and UBR to get the full build (e.g., 26200.8246)
		$fullBuild = if ($properties.UBR) { "$($os.BuildNumber).$($properties.UBR)" } else { $os.BuildNumber }

		$obj = [PSCustomObject]@{
			Caption      = [string]$os.Caption
			Build        = [string]$fullBuild
			DisplayVer   = [string]$properties.DisplayVersion
			Vendor       = [string]$os.Manufacturer
			Architecture = [string]$os.OSArchitecture
		}
		$obj | ConvertTo-Json
	`

	out, err := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	if err != nil {
		return info
	}

	var psOut struct {
		Caption      string `json:"Caption"`
		Build        string `json:"Build"`
		DisplayVer   string `json:"DisplayVer"`
		Vendor       string `json:"Vendor"`
		Architecture string `json:"Architecture"`
	}

	if err := json.Unmarshal(out, &psOut); err == nil {
		info.OSName = strings.TrimSpace(psOut.Caption)
		info.OSVersion = strings.TrimSpace(psOut.DisplayVer)
		info.OSBuild = strings.TrimSpace(psOut.Build)
		info.Vendor = strings.TrimSpace(psOut.Vendor)

		// Clean up Architecture string (e.g., "64-bit" -> "x64")
		arch := strings.ToLower(psOut.Architecture)
		if strings.Contains(arch, "64") {
			info.Architecture = "x64"
		} else if strings.Contains(arch, "32") || strings.Contains(arch, "86") {
			info.Architecture = "x86"
		} else if strings.Contains(arch, "arm") {
			info.Architecture = "arm64"
		} else {
			info.Architecture = arch
		}
	}

	return info
}

func getLinuxVersion() shared.OSInfo {
	info := shared.OSInfo{
		OS:           "linux",
		OSName:       "Linux",
		OSVersion:    "Unknown",
		OSBuild:      "Unknown",
		Vendor:       "linux",
		Architecture: "Unknown",
	}

	// 1. Parse /etc/os-release for Name, Version, and Vendor
	file, err := os.Open("/etc/os-release")
	if err == nil {
		defer file.Close()
		releaseData := make(map[string]string)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			key := parts[0]
			val := strings.Trim(parts[1], ` "`)
			releaseData[key] = val
		}

		if val, ok := releaseData["PRETTY_NAME"]; ok {
			info.OSName = val
		} else if val, ok := releaseData["NAME"]; ok {
			info.OSName = val
		}

		if val, ok := releaseData["VERSION_ID"]; ok {
			info.OSVersion = val
		}

		if val, ok := releaseData["ID"]; ok {
			info.Vendor = val
		}
	}

	// 2. Map the Build (Kernel Version)
	// Example: 6.8.0-40-generic
	buildOut, err := exec.Command("uname", "-r").Output()
	if err == nil {
		info.OSBuild = strings.TrimSpace(string(buildOut))
	}

	// 3. Map the Architecture
	// Example: x86_64, aarch64
	archOut, err := exec.Command("uname", "-m").Output()
	if err == nil {
		rawArch := strings.TrimSpace(string(archOut))

		// Normalize architecture to match your Windows logic
		switch rawArch {
		case "x86_64":
			info.Architecture = "x64"
		case "i386", "i686":
			info.Architecture = "x86"
		case "aarch64", "arm64":
			info.Architecture = "arm64"
		default:
			info.Architecture = rawArch
		}
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

func ExecuteSelfUninstall() {
	// Get the path to the current running binary
	exe, err := os.Executable()
	if err != nil {
		slog.Error("Failed to get executable path for uninstallation", "error", err)
		// We don't return here because we still want to try to remove the service/configs
	}

	switch runtime.GOOS {
	case "linux":
		// 1. Stop and Disable Service
		exec.Command("systemctl", "stop", "watchtower-agent").Run()
		exec.Command("systemctl", "disable", "watchtower-agent").Run()

		// 2. Remove Service File and Configs
		os.Remove("/etc/systemd/system/watchtower-agent.service")
		exec.Command("systemctl", "daemon-reload").Run()
		os.Remove("/etc/watchtower/server.crt")
		os.Remove("/etc/watchtower/config.json")

		// 3. Delete Binary
		// Now using the 'exe' variable correctly
		if exe != "" {
			os.Remove(exe)
		}

	case "windows":
		// 1. Remove the Windows Service
		exec.Command("cmd", "/c", "sc stop WatchtowerAgent & sc delete WatchtowerAgent").Run()

		// 2. Delete Configs
		installDir := `C:\Program Files\Watchtower`
		os.Remove(installDir + `\server.crt`)
		os.Remove(installDir + `\config.json`)

		// 3. Self-Delete Binary
		// We use 'exe' here to tell the cmd process exactly what file to delete
		// after the agent process exits.
		if exe != "" {
			script := fmt.Sprintf("timeout /t 5 /nobreak > NUL & del /f /q \"%s\" & rmDir /s /q \"%s\"", exe, installDir)
			exec.Command("cmd", "/c", script).Start()
		}
	}
}

// Heartbeat now handles frequency updates and uses the secure client

func Heartbeat(serverURL string, agentID string, enrollmentToken string) {
	currentID := agentID

	// Initialize frequency from config
	// Assuming HeartbeatFreq in config is stored in minutes
	conf := AppConfig().Get()
	freq := conf.HeartbeatFreq * 60
	if freq <= 0 {
		freq = 60 // Default to 1 minute if unset
	}

	slog.Info("Heartbeat loop started", "initial_freq_seconds", freq)

	for {
		hostname, _ := os.Hostname()
		hbData := shared.HeartbeatData{
			AgentID:  currentID,
			Hostname: hostname,
		}

		payload, _ := json.Marshal(hbData)
		envelope := shared.Envelope{
			AgentID:   currentID,
			Timestamp: time.Now(),
			Payload:   payload,
		}

		jsonData, _ := json.Marshal(envelope)

		// Use a background context for the request
		resp, err := SecureClient.Post(serverURL+"/api/v1/agent/heartbeat", "application/json", bytes.NewBuffer(jsonData))

		if err != nil {
			slog.Error("Heartbeat failed", "error", err)
			// Wait a bit before retrying on network error
			time.Sleep(60 * time.Second)
			continue
		}

		// Handle Status Gone (Decommissioned)
		if resp.StatusCode == http.StatusGone {
			slog.Warn("Agent decommissioned by server (410). Initiating self-uninstall.")
			resp.Body.Close()
			ExecuteSelfUninstall()
			os.Exit(0)
		}

		var hbRes shared.HeartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&hbRes); err == nil {
			// 1. Explicit JSON status check
			if hbRes.Status == "decommissioned" {
				slog.Warn("Decommissioned status received in JSON. Cleaning up...")
				resp.Body.Close()
				ExecuteSelfUninstall()
				os.Exit(0)
			}

			// 2. Update Telemetry Frequency if provided by server
			if hbRes.TelemetryFrequency > 0 && hbRes.TelemetryFrequency != freq {
				slog.Info("Server requested frequency change", "old", freq, "new", hbRes.TelemetryFrequency)

				// Update local loop variable
				freq = hbRes.TelemetryFrequency

				// PERSIST to config.json
				// We divide by 60 because your config stores minutes
				updatedConf := AppConfig().Get()
				updatedConf.HeartbeatFreq = hbRes.TelemetryFrequency / 60

				if err := AppConfig().Update(updatedConf); err != nil {
					slog.Error("Failed to persist new frequency to config", "error", err)
				}
			}
		}

		resp.Body.Close()

		// 3. Sleep for the duration of 'freq'
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

func StartSoftwareScheduler(serverURL string, agentID string) {
	slog.Info("Starting software telemetry scheduler")

	for {
		// 1. Fetch current frequency inside the loop
		// This ensures we catch updates pushed by the Heartbeat goroutine
		conf := AppConfig().Get()
		minutes := conf.UploadFreq
		if minutes <= 0 {
			minutes = 60 // Default to 1 hour
		}

		interval := time.Duration(minutes) * time.Minute

		// 2. Perform the upload
		slog.Info("Executing scheduled software telemetry upload", "interval_minutes", minutes)
		if err := UploadSoftware(serverURL, agentID); err != nil {
			slog.Error("Scheduled software upload failed", "error", err)

			// Exponential backoff or simple retry:
			// We wait 5 minutes, then the loop restarts and re-checks the frequency
			time.Sleep(5 * time.Minute)
			continue
		}

		slog.Info("Software telemetry upload successful", "next_run_in", interval)

		// 3. Sleep until the next interval
		// Note: If the frequency was changed while UploadSoftware was running,
		// it won't be reflected until THIS sleep finishes and the loop restarts.
		time.Sleep(interval)
	}
}

// StartOSScheduler runs a loop that uploads OS telemetry twice a day (every 12 hours).
// StartOSScheduler runs a loop that uploads OS telemetry twice a day (every 12 hours).
func StartOSScheduler(serverURL string, agentID string) {
	slog.Info("Starting OS telemetry scheduler (Interval: 12 hours)")

	for {
		// Gather the OSInfo struct
		osDetails := GetDetailedOSInfo()

		// Wrap it in the standard Envelope
		payload, _ := json.Marshal(osDetails)
		envelope := shared.Envelope{
			AgentID:   agentID,
			Timestamp: time.Now(),
			Payload:   payload,
		}

		// Upload to the OS telemetry endpoint
		slog.Info("Executing scheduled OS telemetry upload")
		if err := uploadData(serverURL+"/api/v1/agent/telemetry/os", envelope); err != nil {
			slog.Error("Scheduled OS upload failed", "error", err)
			// Retry once after 10 minutes if the server was just temporarily down
			time.Sleep(10 * time.Minute)
			continue
		}

		slog.Info("OS telemetry upload successful")

		// Sleep for 12 hours
		time.Sleep(12 * time.Hour)
	}
}
