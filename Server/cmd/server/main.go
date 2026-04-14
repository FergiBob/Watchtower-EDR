package main

import (
	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/handlers"
	"Watchtower_EDR/server/internal/logs"
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Configures the system logger
	logs.InitLogger()

	// Load the configuration file
	internal.LoadConfig()

	// Establishes connection to databases and updates cpe dictionary
	data.StartDatabases()

	// Ensures database connections are closed when the program shuts down
	// This will now actually run because we are avoiding os.Exit!
	defer data.CloseDatabases()

	// Updates databases and ensures schemas are correct
	data.VerifyDatabases()

	// Create a context to trigger graceful stops of background tasks
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Background Tasks
	data.StartCPEUpdater(ctx) // Updates local NIST CPE dictionary on a schedule

	data.StartCVEUpdater(ctx) // Updates local NIST CVE database on a schedule

	data.StartCPEMapper(ctx) // Attempts to map software catalog to CPE URIs

	data.StartCVEMapper(ctx) // Attempts to map software catalog to CVE entries to capture present vulnerabilities

	// Channel for OS signals (Physical CTRL+C) used to stop the server
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// --------------------------------------------------------
	//                   START SERVER
	//---------------------------------------------------------

	// Get the configured server
	srv, err := handlers.BuildServer()
	if err != nil {
		slog.Error("Failed to initialize server", "error", err)
		os.Exit(1)
	}

	// Run ListenAndServe in a goroutine
	srvErr := make(chan error, 1)
	go func() {
		logs.Sys.Info("Watchtower EDR Server starting", "port", "443")
		certPath := "./internal/data/server.crt"
		keyPath := "./internal/data/server.key"

		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			srvErr <- err
		}
	}()

	// Wait for Shutdown Signal, Web UI Request, or Server Error
	select {
	case err := <-srvErr:
		logs.Sys.Error("Server crashed", "error", err)

	case sig := <-stop:
		logs.Sys.Info("Shutdown signal received from OS", "signal", sig.String())

	case <-handlers.ShutdownChan:
		logs.Audit.Warn("Shutdown signal received from Web UI")
	}

	// Trigger cancellation of background tasks (scheduled taks like CPE Updater, Agent Cleaner, and Agent Status Updater)
	cancel()

	// --------------------------------------------------------
	//                  GRACEFUL SHUTDOWN
	//---------------------------------------------------------
	logs.Sys.Info("Shutting down Watchtower EDR Server and closing connections...")

	// Create a context with a 5-second timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// This gracefully stops the server
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logs.Sys.Error("Graceful shutdown failed", "error", err)
	}

	logs.Sys.Info("Watchtower is now offline.")
}
