// defines functions relating to the web server and its data paths

package handlers

import (
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/logs"
)

// Variable to hold parse html templates
var templates *template.Template

type BaseData struct {
	Username    string
	Theme       string
	CurrentPath string
}

// Holds data that will be passed to the dashboard upon load
type DashboardData struct {
	BaseData           BaseData
	AgentCount         int
	StaleCount         int
	VulnerabilityCount int
	SoftwareCount      int
}

type SettingsData struct {
	BaseData      BaseData
	AppConfig     internal.Config
	StatusMessage string
	IsSuccess     bool
	Logs          string
}

type AgentsData struct {
}

//-----------------------------------------------------------------
//                          HELPER FUNCTIONS
//-----------------------------------------------------------------

// Create an initialization function
func LoadLoginTemplate() {
	var err error
	// Use the correct path relative to where you run the server
	templates, err = template.ParseFiles(
		"./web/public/login.html",
	)
	if err != nil {
		// Fatal error: if templates don't load, the app cannot work
		slog.Error("Fatal error loading login template", "error", err)
		panic(err)
	}
}

// getDashboardData collects all necessary data for the dashboard page, except for the username
func getDashboardData() (DashboardData, error) {
	const baseQuery = `
        SELECT
            (SELECT COUNT(*) FROM agents) AS agent_count,
            (SELECT COUNT(*) FROM agents WHERE last_seen < datetime('now', '%s')) AS stale_count,
            (SELECT COUNT(*) FROM vulnerabilities) AS vulnerability_count,
            (SELECT COUNT(DISTINCT name) FROM software) AS software_count
    `

	modifier := fmt.Sprintf("%d minutes", internal.AppConfig.Agents.OfflineTimer)
	query := fmt.Sprintf(baseQuery, modifier) // Simpler than strings.ReplaceAll

	var d DashboardData

	err := data.QuerySingleRow(data.Main_Database, query, nil,
		&d.AgentCount, &d.StaleCount, &d.VulnerabilityCount, &d.SoftwareCount)

	if err != nil {
		return DashboardData{}, fmt.Errorf("failed to query dashboard counts: %w", err)
	}

	return d, nil
}

// Updates a temporary config with the values from the settings form. Returns a message (either error or success), and bool value to tell the handler if the operation was successful
func updateConfigFromForm(cfg *internal.Config, form url.Values) (string, bool) {
	// UI Theme -------------------
	theme := strings.TrimSpace(form.Get("ui.theme"))
	if theme == "" {
		return "Theme selection is required.", false
	}

	validThemes := []string{"blue", "lightblue", "green", "yellow", "red", "pink", "orange"}
	isValid := false
	for _, t := range validThemes {
		if t == theme {
			isValid = true
			break
		}
	}
	if !isValid {
		return "Invalid theme selection.", false
	}
	cfg.UI.Theme = theme

	// Agent Settings -------------

	// Agent Telemetry Frequency
	telemetryFreqStr := strings.TrimSpace(form.Get("agents.telemetry_freq"))
	if telemetryFreqStr == "" {
		return "Telemetry Frequency is required.", false
	}

	telemetryFreq, err := strconv.Atoi(telemetryFreqStr)
	if err != nil || telemetryFreq < 1 || telemetryFreq > 30 {
		return "Agent Telemetry Frequency must be a number between 1 and 30.", false
	}
	cfg.Agents.TelemetryFrequency = telemetryFreq

	// Agent Unresponsive Timer
	offlineStr := strings.TrimSpace(form.Get("agents.unresponsive_timer"))
	if offlineStr == "" {
		return "Unresponsive Agent Timer is required.", false
	}

	offline, err := strconv.Atoi(offlineStr)
	if err != nil || offline < 2 || offline > 1440 {
		return "Unresponsive Agent Timer must be a number between 2 and 1440.", false
	}
	cfg.Agents.OfflineTimer = offline

	// Agent Enrollment Token
	enrollmentToken := strings.TrimSpace(form.Get("agents.enrollment_token"))

	if enrollmentToken == "" {
		return "Agent Enrollment Token is required.", false
	}

	enrollCount := utf8.RuneCountInString(enrollmentToken)
	if enrollCount < 16 || enrollCount > 40 {
		return "Invalid Agent Enrollment Key format.", false
	}
	cfg.Agents.EnrollmentToken = enrollmentToken

	// NVD Settings ----------------
	apikey := strings.TrimSpace(form.Get("nvd.api_key"))

	if apikey == "" {
		return "NVD API Key is required to sync vulnerability data.", false
	}

	// NVD Keys are typically UUIDs (36 chars), but we allow up to 40 for buffer
	apiCount := utf8.RuneCountInString(apikey)
	if apiCount != 36 {
		return "Invalid API Key format. Please check your NIST NVD key.", false
	}

	cfg.NVD.APIKey = apikey

	return "Settings updated successfully!", true
}

// renderPage dynamically renders the base template with the provided html content template and custom data
// renders each template per request
func renderPage(w http.ResponseWriter, page string, data any) {
	t, err := template.ParseFiles(
		"web/templates/base.html",
		"web/templates/"+page,
	)
	if err != nil {
		http.Error(w, "template parse error", http.StatusInternalServerError)
		slog.Error("failed to parse html templates", "error", err, "page", page)
		return
	}
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "template exec error", http.StatusInternalServerError)
		slog.Error("failed to execute html templates", "error", err, "page", page)
		return
	}
}

func handleSettingsGET(w http.ResponseWriter, r *http.Request, username string) {
	// Pick up flash message from URL query params
	msg := r.URL.Query().Get("msg")
	successStr := r.URL.Query().Get("success")
	isSuccess := successStr == "true"

	logData, err := logs.GetTailLogs(100)
	if err != nil {
		slog.Error("Failed to read log file", "error", err)
		logData = "Error: Could not load system logs." // pass an error message to the log viewer so the whole page doesn't break
	}

	data := SettingsData{
		BaseData: BaseData{
			Username:    username,
			Theme:       internal.AppConfig.UI.Theme,
			CurrentPath: "/settings",
		},
		AppConfig:     internal.AppConfig,
		StatusMessage: msg,
		IsSuccess:     isSuccess,
		Logs:          logData,
	}
	renderPage(w, "settings.html", data)
}

func handleSettingsPOST(w http.ResponseWriter, r *http.Request, username string) {
	if err := r.ParseForm(); err != nil {
		slog.Error("form parse failed", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Work on a local copy to prevent corrupting global state on validation failure
	tempConfig := internal.AppConfig
	message, isSuccess := updateConfigFromForm(&tempConfig, r.Form)

	if isSuccess {
		if err := internal.SaveConfig(tempConfig); err != nil {
			slog.Error("config save failed", "error", err)
			message = "System error: could not write to config file."
			isSuccess = false
		} else {
			// Only update the live global config if the file save worked
			internal.LoadConfig()
		}
	}

	// Prevent form resubmission by redirecting with variables stored in url
	redirectURL := fmt.Sprintf("/settings?msg=%s&success=%t",
		url.QueryEscape(message),
		isSuccess,
	)

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

//----------------------------------------------------------------------------
//                              HANDLER FUNCTIONS
//----------------------------------------------------------------------------

// homeHandler gathers relevant data and serves the main dashboard to the user
func homeHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetUsernameFromToken(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data, err := getDashboardData()
	if err != nil {
		slog.Error("failed to fetch dashboard data", "error", err, "user", username)
		http.Error(w, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}
	data.BaseData.Theme = internal.AppConfig.UI.Theme
	data.BaseData.Username = username
	data.BaseData.CurrentPath = r.URL.Path

	renderPage(w, "dashboard.html", data)
}

// settingsHandler gathers relevant data and servers the settings page to the user
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetUsernameFromToken(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		handleSettingsPOST(w, r, username) // No return needed for void functions
		return
	}

	handleSettingsGET(w, r, username)
}
