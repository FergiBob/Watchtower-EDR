// Initializes server processes via internal functions

package main

import (
	"watchtower_edr/internal"
)

func main() {

	// Configures the system logger
	internal.InitLogger()

	// Load the configuration file
	internal.LoadConfig()

	// Establishes connection to databases and updates cpe dictionary
	internal.StartDatabases()

	// Updates databases and ensures schemas are correct
	internal.VerifyDatabases()

	// Starts web server services
	internal.StartWebServer()
}
