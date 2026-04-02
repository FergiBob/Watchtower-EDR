// handles reading, writing, and processing configuration data from config.yaml

package internal

import (
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

var configFile = "./internal/data/config.yaml"

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
	} `yaml:"database"`
	Agents struct {
		OfflineTimer       int    `yaml:"offline_timer"`
		TelemetryFrequency int    `yaml:"telemetry_freq"`
		EnrollmentToken    string `yaml:"enrollment_token"`
	} `yaml:"agents"`
}

var AppConfig Config

// Writes config data to the config file (YAML)
func SaveConfig(cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("yaml marhsal: %w", err)
	}

	return os.WriteFile(configFile, data, 0644)
}

// Reads config data from the config file (YAML)
func LoadConfig() {

	// Check if file exists and creates it if not
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		slog.Info("Config file not found, creating default config.yaml")
		createDefaultConfig(configFile) // writes a default configuration to the file
	}

	// Read the file
	data, err := os.ReadFile(configFile)
	if err != nil {
		slog.Error("Failed to read config file", "error", err)
		return
	}

	// 3. Unmarshal (Parse) YAML into the struct
	err = yaml.Unmarshal(data, &AppConfig)
	if err != nil {
		slog.Error("Failed to parse config file", "error", err)
	}
}

// used to populate a freshly created config.yaml with defualt configuration information
func createDefaultConfig(path string) {
	defaultCfg := Config{}
	defaultCfg.NVD.APIKey = "YOUR_API_KEY_HERE"
	defaultCfg.NVD.CpeURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	defaultCfg.NVD.CveURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	defaultCfg.Server.FQDN = "watchtower.local"
	defaultCfg.Server.ListenAddress = "0.0.0.0"
	defaultCfg.UI.Theme = "orange"
	defaultCfg.Database.MainDB = "./internal/data/main.db"
	defaultCfg.Database.UserDB = "./internal/data/users.db"
	defaultCfg.Database.CpeDB = "./internal/data/cpe.db"
	defaultCfg.Agents.OfflineTimer = 60
	defaultCfg.Agents.TelemetryFrequency = 5
	defaultCfg.Agents.EnrollmentToken = "WATCHTOWER_EDR_SECRET"

	data, _ := yaml.Marshal(&defaultCfg)
	os.WriteFile(path, data, 0644)
}
