package main

import (
	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/handlers"
	"Watchtower_EDR/server/internal/logs"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
)

// watchtowerService implements the svc.Handler interface
type watchtowerService struct{}

func (m *watchtowerService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// 1. Tell Windows immediately that we are attempting to start.
	changes <- svc.Status{State: svc.StartPending}

	// 2. Fundamental Environment Setup
	internal.SetupDirectory()
	if internal.BaseDir == "" {
		// If we can't find our own folder, we can't log or load data.
		return false, 1
	}

	// Initialize logs and config so we have visibility into any failures.
	logs.InitLogger(internal.BaseDir)
	internal.LoadConfig()

	// 3. Start Core Engines
	// We start the databases here because handlers.BuildServer() often requires them.
	data.StartDatabases()
	data.VerifyDatabases()

	// 4. SIGNAL SUCCESSFUL START
	// Crucial: We signal "Running" BEFORE the potentially slow index hydration
	// or orphan cleanup to avoid the SCM 30-second timeout.[cite: 1, 8]
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	// 5. Post-Start Heavy Lifting
	// Now that the service is "officially" up, we do the maintenance.
	data.CleanupOrphans()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// setupBackgroundTasks handles CPE/CVE updates and index hydration.
	setupBackgroundTasks(ctx)

	// 6. Build and Start the Web Server
	srv, err := handlers.BuildServer()
	if err != nil {
		logs.Sys.Error("Failed to initialize server", "error", err)
		return false, 1
	}

	srvErr := make(chan error, 1)
	go func() {
		certPath := filepath.Join(internal.BaseDir, "internal", "data", "server.crt")
		keyPath := filepath.Join(internal.BaseDir, "internal", "data", "server.key")
		logs.Sys.Info("Watchtower EDR Server starting as Service", "port", "443")

		// This call blocks until the server is closed or crashes.
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			srvErr <- err
		}
	}()

	// 7. Main Control Loop
loop:
	for {
		select {
		case err := <-srvErr:
			logs.Sys.Error("Server crashed", "error", err)
			break loop
		case <-handlers.ShutdownChan:
			logs.Audit.Warn("Shutdown signal received from Web UI")
			break loop
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				// Respond with current status as requested by Windows.
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Start the graceful exit.
				logs.Sys.Info("Shutdown signal received from Windows SCM")
				break loop
			default:
				logs.Sys.Error("Unexpected control request", "cmd", c.Cmd)
			}
		}
	}

	// 8. Graceful Shutdown Sequence
	changes <- svc.Status{State: svc.StopPending}

	cancel() // Stops all background tickers and index workers.[cite: 8]

	logs.Sys.Info("Waiting for background workers to exit...")
	data.WG.Wait() // Wait for goroutines that registered with the WaitGroup.

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logs.Sys.Error("Graceful shutdown failed", "error", err)
	}

	data.CloseDatabases()
	logs.Sys.Info("Watchtower is now offline.")

	// Final status update to Windows SCM.
	changes <- svc.Status{State: svc.Stopped}
	return
}

func main() {

	seedCmd := flag.NewFlagSet("seed", flag.ExitOnError)
	user := seedCmd.String("user", "", "Admin username")
	pass := seedCmd.String("pass", "", "Admin password")
	email := seedCmd.String("email", "", "Admin email")
	fqdn := seedCmd.String("fqdn", "", "Server FQDN")
	nist := seedCmd.String("nist", "", "NIST API Key")

	if len(os.Args) > 1 && os.Args[1] == "seed" {
		seedCmd.Parse(os.Args[2:])

		internal.SetupDirectory()
		if internal.BaseDir == "" {
			fmt.Println("Error: Could not determine executable directory.")
			os.Exit(1)
		}

		logs.InitLogger(internal.BaseDir)

		// 1. Dereference the pointers to get the strings
		plainPassword := *pass
		serverFQDN := *fqdn // Ensure you defined this in seedCmd.String
		nistKey := *nist    // Ensure you defined this in seedCmd.String

		if plainPassword == "" {
			fmt.Println("Error: Password cannot be empty for seeding.")
			os.Exit(1)
		}

		// 2. Initialize Data and Config
		internal.LoadConfig()

		// 3. Update the config with values from the installer
		internal.AppConfig.Server.FQDN = serverFQDN
		internal.AppConfig.NVD.APIKey = nistKey

		// Save the updated struct back to internal\data\config.yaml
		internal.SaveConfig(internal.AppConfig)

		// 4. Seed the admin user (hashing happens inside this function)
		data.StartDatabases()
		hashedPassword, _ := handlers.HashPassword(plainPassword)
		data.CreateInitialAdmin(*user, *email, hashedPassword)
		data.CloseDatabases()
		fmt.Println("Watchtower EDR: Provisioning and Database seeding successful.")
		os.Exit(0)
	}

	// Check if we are running as a service or interactively
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Printf("Failed to detect service context: %v\n", err)
		os.Exit(1)
	}

	if isService {
		// Run as Windows Service
		// "WatchtowerEDR" must match the name used in your Inno Setup / sc create command
		err = svc.Run("WatchtowerEDR", &watchtowerService{})
		if err != nil {
			logs.Sys.Error("Service execution failed", "error", err)
		}
	} else {
		// Run in Terminal (Interactive Mode)
		runInteractive()
	}
}

// setupBackgroundTasks contains all your tickers and search engine logic
func setupBackgroundTasks(ctx context.Context) {
	// Daily Maintenance
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				data.CleanupOrphans()
			}
		}
	}()

	// Search Engine Initialization
	indexPath := filepath.Join(internal.BaseDir, "internal", "data", "cpe_index_db")
	CpeEngine := data.NewSearchEngine(indexPath)
	info, err := os.Stat(indexPath)
	if err != nil || !info.IsDir() {
		logs.Sys.Info("Search index missing. Hydrating...")
		data.InitializeCPEIndex(ctx, CpeEngine)
	} else {
		data.RunIndexRepair(ctx, CpeEngine)
	}

	// Hourly Index Repair
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				data.RunIndexRepair(ctx, CpeEngine)
			}
		}
	}()

	// Start all other background managers
	handlers.StartStatusMonitor(ctx)
	data.StartCPEUpdater(ctx, CpeEngine)
	data.StartCVEUpdater(ctx)
	data.StartCPEMapper(ctx, CpeEngine)
	data.StartCVEMapper(ctx)
}

// runInteractive runs the server exactly how you had it before for terminal use
func runInteractive() {
	internal.SetupDirectory()
	logs.InitLogger(internal.BaseDir)
	internal.LoadConfig()
	data.StartDatabases()
	data.VerifyDatabases()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	data.CleanupOrphans()
	setupBackgroundTasks(ctx)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	srv, err := handlers.BuildServer()
	if err != nil {
		slog.Error("Failed to initialize server", "error", err)
		os.Exit(1)
	}

	srvErr := make(chan error, 1)
	go func() {
		certPath := filepath.Join(internal.BaseDir, "internal", "data", "server.crt")
		keyPath := filepath.Join(internal.BaseDir, "internal", "data", "server.key")
		logs.Sys.Info("Watchtower EDR Server starting", "port", "443")
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			srvErr <- err
		}
	}()

	select {
	case err := <-srvErr:
		logs.Sys.Error("Server crashed", "error", err)
	case sig := <-stop:
		logs.Sys.Info("Shutdown signal received", "signal", sig.String())
	case <-handlers.ShutdownChan:
		logs.Audit.Warn("Shutdown signal received from Web UI")
	}

	cancel()
	data.WG.Wait()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
	data.CloseDatabases()
	logs.Sys.Info("Watchtower is now offline.")
}
