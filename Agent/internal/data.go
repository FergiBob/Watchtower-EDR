// data.go provides functions to handle data packaging and transport as well as other helper functions to meet these goals

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// uploadData is a helper function that receives an endpoint to POST to and formatted data to marshal and upload
func uploadData(endpoint string, data any) error {
	// Convert struct slive into JSON bytes using marshalling
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	// built REST API POST request to provided endpoint using the newly formatted jsonData
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("server error: %s", resp.Status)
	}

	return nil
}

// heartbeat makes contact with the Watchtower EDR main server and checks for agent configuration changes
func heartbeat() {

}

// helloPacket makes initial contact with the Watchtower EDR server, conveying key information like hostname, OS, and IP address.
// The response should contain a agent ID to be used moving forward
func helloPacket() {

}
