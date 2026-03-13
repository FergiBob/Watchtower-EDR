// config.go contains all functions necessary to read, write, and otherwise interact with the application configuration

package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Config matches the JSON structure we discussed
type Config struct {
	AgentID       int      `json:"agent_id"`
	OS            string   `json:"system_os"`
	UploadFreq    int      `json:"upload_interval_minutes"`
	HashFreq      int      `json:"hash_interval_minutes"`
	HeartbeatFreq int      `json:"heartbeat_interval_minutes"`
	PathsToHash   []string `json:"files_to_hash"`
}

// SafeConfig allows the config to read/write within the program while safely avoiding problems like race condition
type SafeConfig struct {
	mu   sync.RWMutex
	Data Config
	Path string
}

// globalCfg is a private pointer to the loaded SafeConfig
var globalCfg *SafeConfig

// InitConfig is the "Constructor" called to load the configurtion once for the entire program
func InitConfig() error {
	sc, err := LoadConfig()
	if err != nil {
		return err
	}
	globalCfg = sc
	return nil
}

// AppConfig is the method that the rest of the application uses to reach the config
func AppConfig() *SafeConfig {
	return globalCfg
}

// Get returns a copy of the current config (thread-safe)
func (s *SafeConfig) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Data
}

// Update creates a temporary config to save new data to and swaps it with the old one
func (s *SafeConfig) Update(newCfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(newCfg, "", "  ")
	if err != nil {
		return err
	}

	// Write to a temp file first
	tmpPath := s.Path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}

	// Rename is atomic on most OSs - it either works or it doesn't
	if err := os.Rename(tmpPath, s.Path); err != nil {
		return err
	}

	s.Data = newCfg
	return nil
}

// Initial Load: Finds the file and returns the SafeConfig pointer
func LoadConfig() (*SafeConfig, error) {
	path, err := findConfigPath()
	if err != nil {
		return nil, err
	}

	file, err := os.ReadFile(path)
	if err != nil {
		// If file doesn't exist, return a default config
		return &SafeConfig{Data: Config{UploadFreq: 60}, Path: path}, nil
	}

	var cfg Config
	if err := json.Unmarshal(file, &cfg); err != nil {
		return nil, err
	}

	return &SafeConfig{Data: cfg, Path: path}, nil
}

// Helper to find the absolute path relative to the .exe
func findConfigPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exePath), "config.json"), nil
}

// getAgentID returns the agentID stored in the config file
func getAgentID() int {
	agentID := AppConfig().Get().AgentID
	return agentID
}
