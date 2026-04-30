// defines functions relating to the web server and its data paths

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/logs"
	"Watchtower_EDR/shared"
)

// Variable to hold parse html templates
var templates *template.Template

type BaseData struct {
	Username    string
	UserID      string
	Email       string
	Theme       string
	CurrentPath string
}

// Holds data that will be passed to the dashboard upon load
type DashboardData struct {
	BaseData              BaseData
	AgentCount            int
	ActiveCount           int
	OfflineCount          int
	VulnerabilityOpen     int
	VulnerabilityProgress int
	VulnerabilityCount    int
	SoftwareCount         int
}

type SettingsData struct {
	BaseData      BaseData
	AppConfig     internal.Config
	StatusMessage string
	IsSuccess     bool
	Logs          string
}

type AgentMetadataPayload struct {
	Category    string `json:"category"`
	Description string `json:"description"`
}

// SoftwarePageData holds all information required to render software.html
type SoftwarePageData struct {
	BaseData       BaseData
	SoftwareList   []SoftwareEntry
	Vendors        []string
	SearchTerm     string
	SelectedVendor string
	SortBy         string // "name", "vendor", or "installs"
	SortDir        string // "asc" or "desc"
}

// SoftwareEntry represents a unique software package across the fleet.
type SoftwareEntry struct {
	ID             int    `sql:"id"`
	Name           string `sql:"name"`
	Vendor         string `sql:"vendor"`
	Version        string `sql:"version"`
	InstallCount   int    `sql:"install_count"`
	CPE            string `sql:"cpe_uri"`
	ManuallyMapped int    `sql:"manually_mapped"`
}

// SoftwareDetails represents the specific data for the "Details" drill-down page.
type SoftwareDetails struct {
	Software SoftwareEntry
	Agents   []AgentSummary // List of agents that have this specific software
}

// AgentSummary is a lightweight struct for listing agents in the software table.
type AgentSummary struct {
	AgentID  string
	Hostname string
	Version  string // Version of the software on this specific agent
}

type VulnerabilityEntry struct {
	CVEID           string `json:"cve_id"`
	CPE_URI         string `json:"cpe_uri"`
	SoftwareName    string `json:"software_name"`
	SoftwareVersion string `json:"software_version"`
	SoftwareVendor  string `json:"software_vendor"`
	Severity        string `json:"severity"`
	BaseScore       string `json:"base_score"`
	TargetType      string `json:"targety_type"`
	Status          string `json:"status"`
	AssetCount      int    `json:"asset_count"`
}

// Vulnerability represents the full detail of a CVE for the Modal/Detail view
type Vulnerability struct {
	CVEID          string   `json:"cve_id"`
	SoftwareName   string   `json:"software_name"`
	SoftwareVendor string   `json:"software_vendor"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	BaseScore      float64  `json:"base_score"`
	Exploitability float64  `json:"exploit_score"`
	ImpactScore    float64  `json:"impact_score"`
	PublishedDate  string   `json:"published_date"`
	LastModified   string   `json:"last_modified"`
	Solution       string   `json:"solution,omitempty"`
	AffectedAgents []string `json:"affected_agents,omitempty"`
}

type VulnerabilityPageData struct {
	Vulnerabilities  []Vulnerability
	SearchTerm       string
	SelectedSeverity string
	SortBy           string
	SortDir          string
}

//-----------------------------------------------------------------
//                          HELPER FUNCTIONS
//-----------------------------------------------------------------

// Create an initialization function
func LoadLoginTemplate() {
	var err error

	// Construct the absolute path using BaseDir
	loginTemplatePath := filepath.Join(internal.BaseDir, "web", "public", "login.html")

	// Use the absolute path to parse the file[cite: 11]
	templates, err = template.ParseFiles(loginTemplatePath)

	if err != nil {
		// Fatal error: if templates don't load, the app cannot work
		logs.Sys.Error("Fatal error loading login template", "path", loginTemplatePath, "error", err)
		panic(err)
	}
}

// getDashboardData collects all necessary data for the dashboard page, except for the username
func getDashboardData() (DashboardData, error) {
	const query = `
        SELECT
            (SELECT COUNT(*) FROM agents WHERE status <> 'decomissioned') AS agent_count,
			(SELECT COUNT(*) FROM agents WHERE status = 'active') AS active_count,
            (SELECT COUNT(*) FROM agents WHERE status = 'offline') AS offline_count,
            (SELECT COUNT(*) FROM discovered_vulnerabilities WHERE status = 'open') AS vulnerability_open,
			(SELECT COUNT(*) FROM discovered_vulnerabilities WHERE status = 'in-progress') AS vulnerability_progress,
			(SELECT COUNT(*) FROM discovered_vulnerabilities) AS vulnerability_count,
            (SELECT COUNT(DISTINCT name) FROM software) AS software_count
    `

	modifier := fmt.Sprintf("-%d minutes", internal.AppConfig.Agents.OfflineTimer)

	var d DashboardData

	err := data.QuerySingleRow(data.Main_Read_Database, query, []any{modifier},
		&d.AgentCount, &d.ActiveCount, &d.OfflineCount, &d.VulnerabilityOpen, &d.VulnerabilityProgress, &d.VulnerabilityCount, &d.SoftwareCount)

	if err != nil {
		logs.DB.Error("failed to query dashboard counts", "error", err)
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
	offlineStr := strings.TrimSpace(form.Get("agents.offline_timer"))
	if offlineStr == "" {
		return "Offline Agent Timer is required.", false
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
		logs.Sys.Error("failed to parse html templates", "error", err, "page", page)
		return
	}
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		http.Error(w, "template exec error", http.StatusInternalServerError)
		logs.Sys.Error("failed to execute html templates", "error", err, "page", page)
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
		logs.Sys.Error("Failed to read log file", "error", err)
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
		logs.Sys.Error("form parse failed", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// Work on a local copy to prevent corrupting global state on validation failure
	tempConfig := internal.AppConfig
	message, isSuccess := updateConfigFromForm(&tempConfig, r.Form)

	if isSuccess {
		if err := internal.SaveConfig(tempConfig); err != nil {
			logs.Sys.Error("config save failed", "error", err)
			message = "System error: could not write to config file."
			isSuccess = false
		} else {
			logs.Audit.Info("System configuration updated", "user", username)
			// Only update the live global config if the file save worked
			internal.LoadConfig()
		}
	} else {
		logs.Audit.Warn("Failed system configuration update attempt", "user", username, "reason", message)
	}

	// Prevent form resubmission by redirecting with variables stored in url
	redirectURL := fmt.Sprintf("/settings?msg=%s&success=%t",
		url.QueryEscape(message),
		isSuccess,
	)

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func getUserInformation(w http.ResponseWriter, r *http.Request, username string) {
	// 1. Fetch user from DB (pseudo-code)
	user, err := GetUserByUsername(username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// 2. Map to a safe struct (omit sensitive fields)
	response := struct {
		ID        string `json:"id"`
		Username  string `json:"username"`
		Email     string `json:"email"`
		UpdatedAt string `json:"updated_at"`
	}{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		UpdatedAt: user.UpdatedAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

//----------------------------------------------------------------------------
//                              HANDLER FUNCTIONS
//----------------------------------------------------------------------------

// homeHandler gathers relevant data and serves the main dashboard to the user
func homeHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetUsernameFromToken(r)
	if err != nil {
		logs.Audit.Warn("Unauthorized dashboard access attempt", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data, err := getDashboardData()
	if err != nil {
		logs.Sys.Error("failed to fetch dashboard data", "error", err, "user", username)
		http.Error(w, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}
	data.BaseData.Theme = internal.AppConfig.UI.Theme
	data.BaseData.Username = username
	data.BaseData.CurrentPath = r.URL.Path

	renderPage(w, "dashboard.html", data)
}

func UserResourceHandler(w http.ResponseWriter, r *http.Request) {

	userReq := r.PathValue("username")
	username, err := GetUsernameFromToken(r)
	if err != nil {
		logs.Audit.Warn("Unauthorized user information access attempt", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if userReq != username {
		logs.Audit.Warn("Unauthorized user information access attempt", "ip", r.RemoteAddr, "user_request", userReq, "user", username)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	switch r.Method {
	case http.MethodGet:
		getUserInformation(w, r, userReq)
	case http.MethodPatch:
		updateUserInformation(w, r, userReq)
	default:
		w.Header().Set("Allow", "GET, PATCH")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}

}

func softwareHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate the user session
	username, err := GetUsernameFromToken(r)
	if err != nil {
		logs.Audit.Warn("Unauthorized software inventory access attempt", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 2. Parse Query Parameters
	searchTerm := r.URL.Query().Get("search")
	selectedVendor := r.URL.Query().Get("vendor")
	sortBy := r.URL.Query().Get("sort")
	sortDir := strings.ToLower(r.URL.Query().Get("dir"))

	// 3. Define the Whitelist
	// Maps the UI 'sort' key to the actual SQL logic
	sortWhitelist := map[string]string{
		"name":     "b.name COLLATE NOCASE",
		"vendor":   "b.vendor COLLATE NOCASE",
		"installs": "install_count",
		"version":  "b.version",
	}

	// 4. Validate Sort Inputs
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}

	orderCol, ok := sortWhitelist[sortBy]
	if !ok {
		orderCol = "install_count" // Default sort
		sortBy = "installs"        // Ensure template knows the default
	}

	// 5. Fetch unique vendors for the filter dropdown
	vendorRows, _ := data.ReadQuery(data.Main_Read_Database, "SELECT DISTINCT vendor FROM software WHERE vendor != '' ORDER BY vendor ASC")
	var vendors []string
	if vendorRows != nil {
		for vendorRows.Next() {
			var v string
			if err := vendorRows.Scan(&v); err == nil {
				vendors = append(vendors, v)
			}
		}
		vendorRows.Close()
	}

	// 6. Build WHERE clause
	baseWhere := "WHERE (s.name LIKE ? OR s.vendor LIKE ? OR s.cpe_uri LIKE ?)"
	params := []any{"%" + searchTerm + "%", "%" + searchTerm + "%", "%" + searchTerm + "%"}

	if selectedVendor != "" {
		baseWhere += " AND s.vendor = ?"
		params = append(params, selectedVendor)
	}

	// 7. Build full the Query
	// We use the CTE to handle the complex aggregation, then join m in the final select
	query := fmt.Sprintf(`
		WITH baseQuery AS (
			SELECT 
				s.id,
				s.name, 
				s.vendor, 
				s.version, 
				COALESCE(s.cpe_uri, '') as cpe_uri,
				COUNT(asw.agent_id) as install_count
			FROM software s
			LEFT JOIN agent_software asw ON s.id = asw.software_id
			%s
			GROUP BY s.id, s.name, s.vendor, s.version, s.cpe_uri
		)
		SELECT 
			b.id,
			b.name,
			b.vendor,
			b.version,
			b.install_count,
			b.cpe_uri,
			CASE WHEN m.id IS NOT NULL THEN 1 ELSE 0 END as is_mapped
		FROM baseQuery b
		LEFT JOIN software_mappings m 
			ON b.name = m.raw_name 
			AND b.vendor = m.raw_vendor 
			AND b.version = m.raw_version
		ORDER BY %s %s`, baseWhere, orderCol, strings.ToUpper(sortDir))

	// 8. Execute
	rows, err := data.ReadQuery(data.Main_Read_Database, query, params...)
	if err != nil {
		logs.Sys.Error("Failed to fetch software inventory", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var softwareList []SoftwareEntry
	for rows.Next() {
		var s SoftwareEntry
		if err := rows.Scan(&s.ID, &s.Name, &s.Vendor, &s.Version, &s.InstallCount, &s.CPE, &s.ManuallyMapped); err == nil {
			softwareList = append(softwareList, s)
		}
	}

	// 9. Prepare and Render
	pageData := SoftwarePageData{
		BaseData: BaseData{
			Username:    username,
			Theme:       internal.AppConfig.UI.Theme,
			CurrentPath: "/software",
		},
		SoftwareList:   softwareList,
		Vendors:        vendors,
		SearchTerm:     searchTerm,
		SelectedVendor: selectedVendor,
		SortBy:         sortBy,
		SortDir:        sortDir,
	}

	renderPage(w, "software.html", pageData)
}

func CPESearchHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the three distinct parameters from the URL
	product := r.URL.Query().Get("product")
	vendor := r.URL.Query().Get("vendor")
	version := r.URL.Query().Get("version")

	// Pass them to the updated ManualSearch function
	results, err := data.GlobalSearchEngine.ManualSearch(product, vendor, version, 20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func SoftwareCPEHandler(w http.ResponseWriter, r *http.Request) {
	// Identify the software asset by ID from the URL path
	softwareID := r.PathValue("id")

	username, err := GetUsernameFromToken(r)
	if err != nil {
		logs.Audit.Warn("Unauthorized CPE access attempt", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch r.Method {
	case http.MethodPut:
		// HANDLE SAVING/UPDATING MAPPING
		var req struct {
			CPE string `json:"cpe"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Resolve the global context (Name, Vendor, Version) from this ID
		name, vendor, version, err := getSoftwareMetadata(softwareID)
		if err != nil {
			http.Error(w, "Software not found", http.StatusNotFound)
			return
		}

		// Apply global mapping and update the database
		applyMappingLogic(name, vendor, version, req.CPE, username)

		// Trigger background re-scan for all affected agents
		go data.RescanCVECorrelation(name, vendor, version, req.CPE)

		w.WriteHeader(http.StatusNoContent) // 204 Success

	case http.MethodDelete:
		// HANDLE UNBINDING MAPPING
		name, vendor, version, err := getSoftwareMetadata(softwareID)
		if err != nil {
			http.Error(w, "Software not found", http.StatusNotFound)
			return
		}

		// Clear global mapping (Set to NULL)
		applyMappingLogic(name, vendor, version, "", username)

		// Remove all discovered vulnerabilities for this specific software version fleet-wide
		data.WriteQuery(data.Main_Database, `
				DELETE FROM discovered_vulnerabilities 
				WHERE software_id IN (SELECT id FROM software WHERE name = ? AND vendor = ? AND version = ?)`,
			name, vendor, version)

		w.WriteHeader(http.StatusNoContent) // 204 Success

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Helper: Get Name/Vendor/Version from a single ID to establish global context
func getSoftwareMetadata(id string) (name, vendor, version string, err error) {
	err = data.QuerySingleRow(data.Main_Read_Database,
		"SELECT name, vendor, version FROM software WHERE id = ?",
		[]any{id}, &name, &vendor, &version)
	return
}

// Helper: The "Ground Truth" logic from your original HandleManualCPEMatch
func applyMappingLogic(name, vendor, version, cpe, username string) {

	var cpeValue any = cpe
	if cpe == "" {
		cpeValue = nil
	}

	// 1. Update Ground Truth (for future discovery)
	data.WriteQuery(data.Main_Database,
		"INSERT OR REPLACE INTO software_mappings (raw_name, raw_vendor, raw_version, selected_cpe, mapped_by) VALUES (?, ?, ?, ?, ?)",
		name, vendor, version, cpeValue, username)

	// 2. Update existing software records in the fleet
	data.WriteQuery(data.Main_Database,
		"UPDATE software SET cpe_uri = ?, mapped = 1 WHERE name = ? AND vendor = ? AND version = ?",
		cpeValue, name, vendor, version)
}

func AgentsPageHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate
	username, err := GetUsernameFromToken(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 2. Get Query Params
	searchTerm := r.URL.Query().Get("search")
	selectedCategory := r.URL.Query().Get("category")
	selectedStatus := r.URL.Query().Get("status")
	softwareID := r.URL.Query().Get("software_id") // Grab the ID

	// 5. Fetch Unique Categories
	catRows, _ := data.ReadQuery(data.Main_Read_Database, "SELECT DISTINCT category FROM agents WHERE category IS NOT NULL AND category != '' ORDER BY category ASC")
	var categories []string
	if catRows != nil {
		for catRows.Next() {
			var c string
			if err := catRows.Scan(&c); err == nil {
				categories = append(categories, c)
			}
		}
		catRows.Close()
	}

	// 6. Build the SQL Query
	query := `SELECT agent_id, hostname, ip_address, os_name, status, IFNULL(category, '')
          FROM agents 
          WHERE 1=1`

	params := []any{}

	if searchTerm != "" {
		query += " AND (hostname LIKE ? OR ip_address LIKE ? OR os_name LIKE ?)"
		wildcard := "%" + searchTerm + "%"
		params = append(params, wildcard, wildcard, wildcard)
	}

	if selectedCategory != "" {
		query += " AND category = ?"
		params = append(params, selectedCategory)
	}

	// --- SOFTWARE FILTER LOGIC ---
	var filteredSoftwareDisplay string
	if softwareID != "" {
		var sName, sVer string
		// Query the software table for details
		err := data.Main_Read_Database.QueryRow("SELECT name, version FROM software WHERE id = ?", softwareID).Scan(&sName, &sVer)
		if err == nil {
			// Return as a single string (name " @ " version)
			filteredSoftwareDisplay = fmt.Sprintf("%s @ %s", sName, sVer)

			// Apply the subquery filter to the main agents query
			query += ` AND agent_id IN (SELECT agent_id FROM agent_software WHERE software_id = ?)`
			params = append(params, softwareID)
		}
	}

	if selectedStatus != "" {
		query += " AND status = ?"
		params = append(params, selectedStatus)
	} else {
		query += " AND status != 'decommissioned'"
	}

	// 7. Finalize Sort
	query += " ORDER BY hostname ASC"

	// 8. Execute
	rows, err := data.ReadQuery(data.Main_Read_Database, query, params...)
	if err != nil {
		logs.Sys.Error("Failed to fetch agent inventory", "error", err)
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	var agents []shared.Agent
	for rows.Next() {
		var a shared.Agent
		if err := rows.Scan(&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSName, &a.Status, &a.Category); err == nil {
			agents = append(agents, a)
		}
	}

	// 9. Render
	renderPage(w, "agents.html", map[string]any{
		"BaseData": BaseData{
			Username:    username,
			Theme:       internal.AppConfig.UI.Theme,
			CurrentPath: "/agents",
		},
		"Agents":           agents,
		"Categories":       categories,
		"SearchTerm":       searchTerm,
		"SelectedCategory": selectedCategory,
		"SelectedStatus":   selectedStatus,
		"SoftwareName":     filteredSoftwareDisplay,
		"SoftwareID":       softwareID,
	})
}

func GetAgentDetailsHandler(w http.ResponseWriter, r *http.Request) {
	// Standard Go 1.22+ way to get the {id} from the path
	agentID := r.PathValue("id")

	var a shared.Agent
	err := data.QuerySingleRow(data.Main_Read_Database,
		`SELECT agent_id, hostname, ip_address, os_name, os_version, os_build, 
                IFNULL(os_cpe_uri, ''), binary_version, IFNULL(category, ''), 
                IFNULL(description, ''), status, first_seen, last_seen 
         FROM agents WHERE agent_id = ?`,
		[]any{agentID},
		&a.AgentID, &a.Hostname, &a.IPAddress, &a.OSName, &a.OSVersion, &a.OSBuild,
		&a.OSCpeUri, &a.BinaryVersion, &a.Category, &a.Description, &a.Status,
		&a.FirstSeen, &a.LastSeen)

	if err != nil {
		http.Error(w, "Agent not found", 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(a)
}

func UpdateAgentMetadataHandler(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	var payload AgentMetadataPayload

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	err := data.WriteQuery(data.Main_Database,
		"UPDATE agents SET category = ?, description = ? WHERE agent_id = ?",
		payload.Category, payload.Description, agentID)

	if err != nil {
		http.Error(w, "Update failed", 500)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func DecommissionAgentHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the ID from the path segment {id}
	agentID := r.PathValue("id")

	if agentID == "" {
		logs.Sys.Error("Decommission attempt with missing Agent ID")
		http.Error(w, "Agent ID is required", http.StatusBadRequest)
		return
	}

	// Update the agent status to 'decommissioned'
	// This status ensures they are filtered out of your main AgentsPageHandler query
	err := data.WriteQuery(data.Main_Database,
		"UPDATE agents SET status = 'decommissioned' WHERE agent_id = ?",
		agentID)

	if err != nil {
		logs.Sys.Error("Database failure during agent decommission", "agent_id", agentID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	logs.Audit.Warn("Agent successfully decommissioned", "agent_id", agentID)
	w.WriteHeader(http.StatusOK)
}

func InstallerGeneratorHandler(w http.ResponseWriter, r *http.Request) {
	osType := r.URL.Query().Get("os")

	// 1. Get credentials from internal config
	fqdn := internal.AppConfig.Server.FQDN
	token := internal.AppConfig.Agents.EnrollmentToken
	certFilepath := filepath.Join(internal.BaseDir, "internal", "data", "server.crt")
	certBytes, _ := os.ReadFile(certFilepath)

	var filename string
	var content string

	switch osType {
	case "windows":
		filename = "install-watchtower.ps1"
		content = generateWindowsScript(fqdn, token, string(certBytes))
		w.Header().Set("Content-Type", "application/octet-stream")
	case "linux":
		filename = "install-watchtower.sh"
		content = generateLinuxScript(fqdn, token, string(certBytes))
		w.Header().Set("Content-Type", "text/x-sh")
	default:
		http.Error(w, "Unsupported OS", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Write([]byte(content))
}

// settingsHandler gathers relevant data and servers the settings page to the user
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetUsernameFromToken(r)
	if err != nil {
		logs.Audit.Warn("Unauthorized settings access attempt", "ip", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		handleSettingsPOST(w, r, username) // No return needed for void functions
		return
	}

	handleSettingsGET(w, r, username)
}

func VulnerabilitiesPageHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetUsernameFromToken(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// 1. Get Sort Parameters
	searchTerm := r.URL.Query().Get("search")
	selectedSeverity := r.URL.Query().Get("severity")
	selectedStatus := r.URL.Query().Get("status")
	sortBy := r.URL.Query().Get("sort")
	sortDir := strings.ToLower(r.URL.Query().Get("dir"))

	// 2. Validate Sort Direction
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc" // Default to descending
	}

	// 3. Define Sort Whitelist (Mapping UI names to SQL columns)
	// Note: We use the aliases defined in the SELECT clause
	sortWhitelist := map[string]string{
		"cve_id":          "dv.cve_id",
		"display_name":    "display_name",
		"display_version": "display_version",
		"asset_count":     "asset_count",
		"cvss_score":      "dv.cvss_score",
		"severity": `CASE dv.severity 
                        WHEN 'CRITICAL' THEN 1 
                        WHEN 'HIGH' THEN 2 
                        WHEN 'MEDIUM' THEN 3 
                        WHEN 'LOW' THEN 4 
                        ELSE 5 END`,
	}

	// Determine target sort column
	orderBy, ok := sortWhitelist[sortBy]
	if !ok {
		// Default sorting if no valid param provided
		orderBy = "dv.cvss_score"
		sortBy = "cvss_score" // For template highlighting
	}

	// 4. Build the Query
	query := `
        SELECT 
            dv.cve_id, 
			CASE
				WHEN dv.target_type = 'os' THEN COALESCE(a.os_cpe_uri, 'N/A')
				ELSE COALESCE(s.cpe_uri, 'Unknown CPE')
			END AS display_cpe,
            CASE 
                WHEN dv.target_type = 'os' THEN COALESCE(a.os_name, 'Operating System')
                ELSE COALESCE(s.name, 'Unknown Application')
            END AS display_name,
            CASE 
                WHEN dv.target_type = 'os' THEN 
                    COALESCE(a.os_version || ' ' || a.os_build, a.os_version, a.os_build, 'N/A')
                ELSE 
                    COALESCE(s.version, 'N/A')
            END AS display_version,
            CASE 
                WHEN dv.target_type = 'os' THEN 
                    TRIM(substr(dv.cpe_uri, 11, instr(substr(dv.cpe_uri, 11), ':') - 1))
                ELSE COALESCE(s.vendor, 'Unknown Vendor')
            END AS display_vendor,
            dv.severity, 
            dv.cvss_score, 
            dv.target_type,
			dv.status,
            COUNT(DISTINCT dv.agent_id) as asset_count
        FROM discovered_vulnerabilities dv
        LEFT JOIN software s ON dv.software_id = s.id
        LEFT JOIN agents a ON dv.agent_id = a.agent_id
        WHERE 1=1`

	params := []any{}

	// Handles if a status filter has been passed or not
	if selectedStatus != "all" && data.IsValidStatus(selectedStatus) {
		query += " AND dv.status = ?"
		params = append(params, selectedStatus)
	}

	// Filter Logic
	if searchTerm != "" {
		term := "%" + searchTerm + "%"
		query += " AND (dv.cve_id LIKE ? OR s.name LIKE ? OR a.os_name LIKE ? OR s.version LIKE ? OR a.os_version LIKE ? OR a.os_build LIKE ?)"
		for i := 0; i < 6; i++ {
			params = append(params, term)
		}
	}

	if selectedSeverity != "" {
		query += " AND dv.severity = ?"
		params = append(params, selectedSeverity)
	}

	// Finalize Groups and Dynamic Sort
	query += fmt.Sprintf(` GROUP BY dv.cve_id, dv.target_type, display_cpe, display_name, display_version, display_vendor, dv.severity, dv.cvss_score, dv.status
                           ORDER BY %s %s`, orderBy, strings.ToUpper(sortDir))

	// 5. Execution
	rows, err := data.ReadQuery(data.Main_Read_Database, query, params...)
	if err != nil {
		logs.Sys.Error("Failed to fetch vulnerabilities", "error", err)
		http.Error(w, "Database error", 500)
		return
	}
	defer rows.Close()

	var vulnerabilities []VulnerabilityEntry
	for rows.Next() {
		var v VulnerabilityEntry
		if err := rows.Scan(&v.CVEID, &v.CPE_URI, &v.SoftwareName, &v.SoftwareVersion, &v.SoftwareVendor, &v.Severity, &v.BaseScore, &v.TargetType, &v.Status, &v.AssetCount); err == nil {
			vulnerabilities = append(vulnerabilities, v)
		}
	}

	renderPage(w, "vulnerabilities.html", map[string]any{
		"BaseData": BaseData{
			Username:    username,
			Theme:       internal.AppConfig.UI.Theme,
			CurrentPath: "/vulnerabilities",
		},
		"Vulnerabilities":  vulnerabilities,
		"SearchTerm":       searchTerm,
		"SelectedSeverity": selectedSeverity,
		"SelectedStatus":   selectedStatus,
		"SortBy":           sortBy,
		"SortDir":          sortDir,
	})
}

func VulnerabilityResourceHandler(w http.ResponseWriter, r *http.Request) {
	// PathValue retrieves the content of the {id} wildcard from the registered route
	cveID := r.PathValue("id")

	if cveID == "" {
		http.Error(w, "Missing Identifier", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		getVulnerabilityDetails(w, r, cveID)
	case http.MethodPatch:
		updateVulnerabilityStatus(w, r, cveID)
	default:
		w.Header().Set("Allow", "GET, PATCH")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func getVulnerabilityDetails(w http.ResponseWriter, r *http.Request, cveID string) {
	cpeURI := r.URL.Query().Get("cpe_uri")

	// 1. Ensure the Intelligence DB is attached to the connection
	attachQuery := fmt.Sprintf("ATTACH DATABASE '%s' AS intel", internal.AppConfig.Database.CveDB)
	_ = data.WriteQuery(data.Main_Read_Database, attachQuery)
	defer data.WriteQuery(data.Main_Read_Database, "DETACH DATABASE intel")

	// 2. Expand struct to include technical metrics
	var details struct {
		CVEID        string  `json:"cve_id"`
		Severity     string  `json:"severity"`
		Status       string  `json:"status"`
		TargetType   string  `json:"target_type"`
		Description  string  `json:"description"`
		CVSSScore    float64 `json:"cvss_score"`
		ExploitScore float64 `json:"exploit_score"`
		ImpactScore  float64 `json:"impact_score"`
		Published    string  `json:"publish_date"`
		Modified     string  `json:"last_modified"`
		DetectedAt   string  `json:"detected_at"`
		AgentCount   int     `json:"agent_count"`
		SoftwareID   int     `json:"software_id"`
	}

	// 3. Updated Query:
	// - Joins with local 'discovered_vulnerabilities' for counts and detection times
	// - Joins with 'intel.vulnerabilities' for NVD metadata (scores/dates)
	query := `
		SELECT 
			dv.cve_id, 
			dv.severity, 
			dv.status,
			dv.target_type,
			COALESCE(intel.vulnerabilities.description, 'No description available.'),
			dv.cvss_score,
			IFNULL(dv.exploit_score, 0.0),
			IFNULL(dv.impact_score, 0.0),
			IFNULL(dv.published_date, 'N/A'),
			IFNULL(dv.last_modified, 'N/A'),
			dv.detected_at,
			(SELECT COUNT(*) FROM discovered_vulnerabilities WHERE cve_id = dv.cve_id AND cpe_uri = dv.cpe_uri),
			dv.software_id
		FROM discovered_vulnerabilities dv
		LEFT JOIN intel.vulnerabilities ON dv.cve_id = intel.vulnerabilities.cve_id
		WHERE dv.cve_id = ? AND dv.cpe_uri = ? 
		LIMIT 1`

	err := data.QuerySingleRow(data.Main_Read_Database, query, []any{cveID, cpeURI},
		&details.CVEID, &details.Severity, &details.Status, &details.TargetType,
		&details.Description, &details.CVSSScore, &details.ExploitScore,
		&details.ImpactScore, &details.Published, &details.Modified,
		&details.DetectedAt, &details.AgentCount, &details.SoftwareID)

	if err != nil {
		logs.Sys.Error("Vulnerability fetch failed", "cve", cveID, "uri", cpeURI, "error", err)
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(details)
}

func updateVulnerabilityStatus(w http.ResponseWriter, r *http.Request, cveID string) {
	// 1. Decode the update request
	var updateReq struct {
		Status string `json:"status"`
		CPE    string `json:"cpe_uri"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 2. Normalize to lowercase and validate/default
	// We convert to lowercase first so comparison is case-insensitive
	requestedStatus := strings.ToLower(strings.TrimSpace(updateReq.Status))

	// Use the helper from nvd.go: func IsValidStatus(status string) bool
	if !data.IsValidStatus(requestedStatus) {
		logs.Map.Warn("Invalid status received, defaulting to open", "received", requestedStatus)
		requestedStatus = "open"
	}

	// 3. Perform the targeted update
	err := data.WriteQuery(data.Main_Database, `
        UPDATE discovered_vulnerabilities 
        SET status = ? 
        WHERE cve_id = ? AND cpe_uri = ?`,
		requestedStatus, cveID, updateReq.CPE)

	if err != nil {
		logs.DB.Error("Failed to patch vulnerability status", "cve", cveID, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	logs.Audit.Info("Vulnerability status updated", "cve", cveID, "status", requestedStatus)

	// Standard response for successful update
	w.WriteHeader(http.StatusNoContent)
}

// Global state to track if a scan is currently active

func ScanCVEs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Check if a scan is already in progress
	data.ScanMutex.Lock()
	if data.IsScanning {
		data.ScanMutex.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "A vulnerability scan is already running. Please wait for it to complete.",
		})
		return
	}

	data.IsScanning = true
	data.ScanMutex.Unlock()
	// 4. Fire off the scan in a background goroutine
	go func() {
		// Reset scanning flag when done
		defer func() {
			data.ScanMutex.Lock()
			data.IsScanning = false
			data.ScanMutex.Unlock()
		}()

		logs.Map.Info("Manual rescan triggered via WebUI")

		// MapCVEs is the core logic from your nvd.go file
		// It handles software correlation, OS checks, and cleanup
		ctx := context.Background()
		data.MapCVEs(ctx)

		logs.Map.Info("Manual rescan completed successfully")
	}()

	// 5. Send immediate response to the UI
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Global scan initiated. Results will populate the dashboard shortly.",
	})
}
