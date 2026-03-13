// Initializes server processes via internal functions

package main

import (
	"watchtower_edr/server/internal"
	"watchtower_edr/server/internal/data"
	"watchtower_edr/server/internal/handlers"
	"watchtower_edr/server/internal/logs"
)

func main() {

	// Configures the system logger
	logs.InitLogger()

	// Load the configuration file
	internal.LoadConfig()

	// Establishes connection to databases and updates cpe dictionary
	data.StartDatabases()

	// Updates databases and ensures schemas are correct
	data.VerifyDatabases()

	// Starts web server services
	handlers.StartWebServer()
}
