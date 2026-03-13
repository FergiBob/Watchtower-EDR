// handles reading, writing, and processing configuration data from config.yaml

package internal

import (
	"log/slog"
	"os"

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
		WebPort string `yaml:"web_port"`
	} `yaml:"server"`
	UI struct {
		Theme string `yaml:"theme"`
	}
	Database struct {
		MainDB string `yaml:"main_db_path"`
		CpeDB  string `yaml:"cpe_db_path"`
	} `yaml:"database"`
}

var AppConfig Config

func LoadConfig() {
	configFile := "config.yaml"

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
	defaultCfg.Server.WebPort = "8080"
	defaultCfg.UI.Theme = "theme-orange"
	defaultCfg.Database.MainDB = "./internal/data/sql-data.db"
	defaultCfg.Database.CpeDB = "./internal/data/cpe.db"

	data, _ := yaml.Marshal(&defaultCfg)
	os.WriteFile(path, data, 0644)
}
