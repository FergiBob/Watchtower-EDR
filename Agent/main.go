package main

import (
	"fmt"
	"log/slog"
	"os"

	"Watchtower_EDR/agent/internal"
)

func main() {
	internal.InitLogger()

	// Initialize configuration
	err := internal.InitConfig()
	if err != nil {
		slog.Error("Failed to load configuration file", "error", err, "action", "Exiting")
		os.Exit(1)
	}

	if err := internal.InitSecureClient(); err != nil {
		slog.Error("Failed to initialize secure client", "error", err)
		os.Exit(1)
	}

	// Define your server URL (usually this would be in your config.json too)
	serverURL := "https://localhost:443" // Update to your actual server address
	enrollmentToken := "WATCHTOWER_EDR_SECRET_!"

	// Enrollment: Check if we already have an AgentID
	cfg := internal.AppConfig().Get()
	agentIDStr := ""

	if cfg.AgentID == "" {
		slog.Info("No AgentID found. Starting enrollment...")
		newID, err := internal.HelloPacket(serverURL, enrollmentToken)
		if err != nil {
			slog.Error("Enrollment failed", "error", err)
			os.Exit(1)
		}

		// Update local config so we don't re-enroll next time
		// Note: helloPacket returns a string, but your Config struct uses an int.
		// If your server uses UUIDs, you should change Config.AgentID to a string.
		slog.Info("Enrollment successful", "new_id", newID)

		// For this example, we assume your server returns a numeric ID.
		// If it's a UUID, update your internal.Config struct to use a string!
		cfg.AgentID = newID // Replace with parsed newID
		internal.AppConfig().Update(cfg)
		agentIDStr = newID
	} else {
		// Convert int to string for comms functions
		agentIDStr = fmt.Sprintf("%d", cfg.AgentID)
		slog.Info("Agent starting with existing ID", "agent_id", cfg.AgentID)
	}

	// Initial Software Inventory Sync
	slog.Info("Sending initial software telemetry...")
	err = internal.UploadSoftware(serverURL, agentIDStr)
	if err != nil {
		slog.Warn("Initial software sync failed", "error", err)
	}

	// Start the Heartbeat loop (this is a blocking call in your current code)
	slog.Info("Starting heartbeat loop...")
	internal.Heartbeat(serverURL, agentIDStr)
}
