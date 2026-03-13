// defines routes and initializes the web server

package handlers

import (
	"html/template"
	"log/slog"
	"net/http"
	"watchtower_edr/server/internal"
)

// Variable to hold parse html templates
var templates *template.Template

// ---------------------------- Structs for web page data --------------------------------
type DashboardData struct {
	Username   string
	AgentCount int
	Theme      string
}

//
//
//
//
//
//
// ----------------------------------- Web Functions -------------------------------------

// Create an initialization function
func LoadTemplates() {
	var err error
	// Use the correct path relative to where you run the server
	templates, err = template.ParseFiles(
		"./web/templates/base.html",
		"./web/templates/dashboard.html",
	)
	if err != nil {
		// Fatal error: if templates don't load, the app cannot work
		slog.Error("Fatal error loading templates", "error", err)
		panic(err)
	}
	slog.Info("Templates loaded successfully")
}

// Now your handler is clean
func homeHandler(w http.ResponseWriter, r *http.Request) {
	username, err := GetUsernameFromToken(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Now populate struct with this username
	data := DashboardData{
		Username:   username,
		AgentCount: 15, // Example
		Theme:      internal.AppConfig.UI.Theme,
	}

	templates.ExecuteTemplate(w, "base", data)
}

func StartWebServer() {

	LoadTemplates() // load html templates

	mux := http.NewServeMux()

	// Public Routes
	fileServer := http.FileServer(http.Dir("./web/public"))
	mux.Handle("/public/", http.StripPrefix("/public/", fileServer))

	// ----------------------------------------- Route Handlers ----------------------------------------
	mux.HandleFunc("/login", LoginHandler)

	// Note: You can move homeHandler to this file or auth.go
	mux.Handle("/", AuthMiddleware(http.HandlerFunc(homeHandler)))

	mux.Handle("/logout", http.HandlerFunc(LogoutHandler))

	webPort := internal.AppConfig.Server.WebPort
	slog.Info("Starting Watchtower EDR web server", "port", webPort)

	// Using a named port string like ":8080"
	err := http.ListenAndServe(":"+webPort, mux)
	if err != nil && err != http.ErrServerClosed {
		slog.Error("Web server crashed", "error", err)
	} else {
		slog.Info("Web server was shut down") // handles graceful shutdowns
	}
}
