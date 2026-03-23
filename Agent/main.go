package main

import (
	"log/slog"
	"os"

	"Watchtower_EDR/agent/internal"
)

func main() {

	internal.InitLogger()

	// initialize configuration, exit on failure
	err := internal.InitConfig()
	if err != nil {
		slog.Error("Failed to load configuration file", "error", err, "action", "Exiting")
		os.Exit(1)
	}

}
