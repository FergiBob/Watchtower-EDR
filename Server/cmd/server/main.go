// Initializes server processes via internal functions

package main

import (
	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/handlers"
	"Watchtower_EDR/server/internal/logs"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	// Configures the system logger
	logs.InitLogger()

	// Load the configuration file
	internal.LoadConfig()

	// Establishes connection to databases and updates cpe dictionary
	data.StartDatabases()

	// Ensures database connections are closes when the program shuts down
	defer data.CloseDatabases()

	// Updates databases and ensures schemas are correct
	data.VerifyDatabases()

	// Channel for OS signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Channel for Server Errors
	srvErr := make(chan error, 1)

	go func() {
		handlers.StartServer(srvErr)
	}()

	// Awaits any shutdown signal
	select {
	case err := <-srvErr:
		// CATASTROPHIC FAILURE: The server crashed on its own
		slog.Error("Critical server failure", "error", err)
	case sig := <-stop:
		// GRACEFUL STOP: The user wants to quit or CTRL-C was hit
		slog.Info("Shutdown signal received", "signal", sig.String())
	}

	// Closing message
	slog.Info("Shutting down Watchtower EDR Server and closing connections...")

}
