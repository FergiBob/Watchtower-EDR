// handles reading, writing, and processing configuration data from config.yaml

package internal

import (
	"fmt"
	"os"
	"path/filepath"

	"Watchtower_EDR/server/internal/logs" // Import the new logging package

	"github.com/thanhpk/randstr"
	"gopkg.in/yaml.v3"
)

// struct for the configuration to be read from yaml file and used within the program
type Config struct {
	NVD struct {
		APIKey string `yaml:"api_key"`
		CpeURL string `yaml:"cpe_url"`
		CveURL string `yaml:"cve_url"`
	} `yaml:"nvd"`
	Server struct {
		FQDN          string `yaml:"fqdn"`
		ListenAddress string `yaml:"listen_address"`
	} `yaml:"server"`
	UI struct {
		Theme string `yaml:"theme"`
	}
	Database struct {
		MainDB string `yaml:"main_db_path"`
		UserDB string `yaml:"user_db_path"`
		CpeDB  string `yaml:"cpe_db_path"`
		CveDB  string `yaml:"cve_db_path"`
	} `yaml:"database"`
	Agents struct {
		OfflineTimer       int    `yaml:"offline_timer"`
		TelemetryFrequency int    `yaml:"telemetry_freq"`
		EnrollmentToken    string `yaml:"enrollment_token"`
	} `yaml:"agents"`
}

var (
	AppConfig  Config
	BaseDir    string
	configFile string // Don't initialize it here!
)

func SetupDirectory() {
	exePath, err := os.Executable()
	if err != nil {
		os.Exit(1)
	}

	// 1. Set the BaseDir first
	BaseDir = filepath.Dir(exePath)

	// 2. NOW initialize the dependent paths
	configFile = filepath.Join(BaseDir, "internal", "data", "config.yaml")

	// 3. Change working directory
	os.Chdir(BaseDir)
}

// SaveConfig writes config data to the config file (YAML)
func SaveConfig(cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		logs.Sys.Error("Failed to marshal config for saving", "error", err)
		return fmt.Errorf("yaml marshal: %w", err)
	}

	err = os.WriteFile(configFile, data, 0644)
	if err != nil {
		logs.Sys.Error("Failed to write config file to disk", "path", configFile, "error", err)
		return err
	}

	logs.Sys.Info("Configuration saved successfully")
	return nil
}

// LoadConfig reads config data from the config file (YAML)
func LoadConfig() {

	// Check if file exists and creates it if not
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		logs.Sys.Warn("Config file not found, creating default config.yaml", "path", configFile)
		createDefaultConfig(configFile)
	}

	// Read the file
	data, err := os.ReadFile(configFile)
	if err != nil {
		logs.Sys.Error("Failed to read config file", "path", configFile, "error", err)
		return
	}

	// Unmarshal (Parse) YAML into the struct
	err = yaml.Unmarshal(data, &AppConfig)
	if err != nil {
		logs.Sys.Error("Failed to parse config YAML", "path", configFile, "error", err)
		return
	}

	logs.Sys.Info("Configuration loaded successfully", "path", configFile)
}

// createDefaultConfig populates a freshly created config.yaml with default information
func createDefaultConfig(path string) {
	err := os.MkdirAll(filepath.Dir(path), 0755)
	if err != nil {
		logs.Sys.Error("Failed to create data directory", "error", err)
		return
	}

	defaultCfg := Config{}
	defaultCfg.NVD.APIKey = "YOUR_API_KEY_HERE"
	defaultCfg.NVD.CpeURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	defaultCfg.NVD.CveURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultCfg.Server.FQDN = "watchtower.local"
	defaultCfg.Server.ListenAddress = "0.0.0.0"
	defaultCfg.UI.Theme = "orange"
	defaultCfg.Database.MainDB = filepath.Join(BaseDir, "internal", "data", "main.db")
	defaultCfg.Database.UserDB = filepath.Join(BaseDir, "internal", "data", "users.db")
	defaultCfg.Database.CpeDB = filepath.Join(BaseDir, "internal", "data", "cpe.db")
	defaultCfg.Database.CveDB = filepath.Join(BaseDir, "internal", "data", "cve.db")
	defaultCfg.Agents.OfflineTimer = 60
	defaultCfg.Agents.TelemetryFrequency = 5
	defaultCfg.Agents.EnrollmentToken = randstr.String(16)

	data, err := yaml.Marshal(&defaultCfg)
	if err != nil {
		logs.Sys.Error("Failed to marshal default configuration", "error", err)
		return
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		logs.Sys.Error("Failed to create default config file", "path", path, "error", err)
	} else {
		logs.Sys.Info("Default configuration file created", "path", path)
	}
}
