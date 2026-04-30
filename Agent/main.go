package main

import (
	"flag"
	"log/slog"
	"os"
	"path/filepath"

	"Watchtower_EDR/agent/internal"

	"github.com/kardianos/service" // Add this
)

// Define a structure to represent the service
type program struct {
	serverURL string
	token     string
}

// Start is called by the service manager when the service starts
func (p *program) Start(s service.Service) error {
	// Run our agent logic in a background goroutine so Start returns immediately
	go p.runAgent()
	return nil
}

func (p *program) Stop(s service.Service) error {
	return nil
}

func main() {
	// 1. Setup environment
	exePath, _ := os.Executable()
	os.Chdir(filepath.Dir(exePath))

	serverURLFlag := flag.String("url", "", "Server URL")
	tokenFlag := flag.String("token", "", "Enrollment Token")
	flag.Parse()

	internal.InitLogger()

	// 2. Setup Service Config
	svcConfig := &service.Config{
		Name:        "WatchtowerAgent",
		DisplayName: "Watchtower EDR Agent",
		Description: "Watchtower Endpoint Detection and Response Agent",
	}

	prg := &program{
		serverURL: *serverURLFlag,
		token:     *tokenFlag,
	}

	s, err := service.New(prg, svcConfig)
	if err != nil {
		slog.Error("Failed to create service", "error", err)
		os.Exit(1)
	}

	// 3. Run the service (This blocks until the service is stopped)
	err = s.Run()
	if err != nil {
		slog.Error("Service failed to run", "error", err)
	}
}

func (p *program) runAgent() {
	// Initialize internal systems
	if err := internal.InitConfig(); err != nil {
		slog.Error("Config init failed", "error", err)
		return
	}
	if err := internal.InitSecureClient(); err != nil {
		slog.Error("Secure client init failed", "error", err)
		return
	}

	cfg := internal.AppConfig().Get()
	agentIDStr := cfg.AgentID

	if agentIDStr == "" {
		slog.Info("Starting enrollment...")
		newID, err := internal.HelloPacket(p.serverURL, p.token)
		if err != nil {
			slog.Error("Enrollment failed", "error", err)
			return
		}
		agentIDStr = newID
		cfg.AgentID = newID
		internal.AppConfig().Update(cfg)
	}

	// Start your loops
	go internal.Heartbeat(p.serverURL, agentIDStr, p.token)
	go internal.StartSoftwareScheduler(p.serverURL, agentIDStr)
	go internal.StartOSScheduler(p.serverURL, agentIDStr)
}
