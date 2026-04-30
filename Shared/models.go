// models.go contains the data models/structs that are used jointly between agents and server

package shared

import (
	"encoding/json"
	"time"
)

// Software defines the data associated with a given software installation.
type Software struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Manufacturer string `json:"manufacturer"`
	Date         string `json:"date"`
}

// Envelope is the common wrapper for all data uploads.
type Envelope struct {
	AgentID   string          `json:"agent_id"`
	Timestamp time.Time       `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
}

// RegistrationRequest is what the agent sends during helloPacket/enrollment
type RegistrationRequest struct {
	MachineID     string `json:"machine_id"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	BinaryVersion string `json:"binary_version"`
	Token         string `json:"token"`
}

type OSInfo struct {
	OS           string `json:"os"`         // "windows"
	OSName       string `json:"os_name"`    // "Windows 11 Pro"
	OSVersion    string `json:"os_version"` // "22H2"
	OSBuild      string `json:"os_build"`   // "22621.2134"
	Architecture string `json:"arch"`       // "x86_64"
	Vendor       string `json:"vendor"`
}

type Agent struct {
	AgentID       string `json:"agent_id"`
	Hostname      string `json:"hostname"`
	IPAddress     string `json:"ip_address"`
	OSName        string `json:"os_name"`
	OSVersion     string `json:"os_version"`
	OSBuild       string `json:"os_build"`
	OSCpeUri      string `json:"os_cpe_uri"`
	BinaryVersion string `json:"binary_version"`
	Category      string `json:"category"`
	Description   string `json:"description"`
	Status        string `json:"status"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen"`
}

// Data received from the agent to the server in a heartbeat
type HeartbeatData struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
}

// Data sent from server to agent in a heartbeat response
type HeartbeatResponse struct {
	Status             string `json:"status"`
	TelemetryFrequency int    `json:"telemetry_freq"`
}
