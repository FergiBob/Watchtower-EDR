package handlers

// auth.go provides the authentication logic for the web UI.
// This includes hashing passwords, protecting routes, generating JWT tokens, etc.

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"Watchtower_EDR/server/internal"
	"Watchtower_EDR/server/internal/data"
	"Watchtower_EDR/server/internal/logs"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("YOUR_SECRET_KEY") // In production, use an environment variable!

// Any data that has to be passed along to the login page
type LoginPageData struct {
	Theme string
}

// Claims struct for JWT
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Takes a string (password) and returns a string (hashed password) and an error code
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Takes a string (password) and a string (hashed password) and returns a boolean (are the hashes equal?)
func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Serves the login page content, receives username and password, calls functions to verify credentials, assigns JWT token
func LoginHandler(w http.ResponseWriter, r *http.Request) {

	// Loads the "static" template for the login page
	LoadLoginTemplate()

	//sends the login page to the browser
	if r.Method == http.MethodGet {
		data := LoginPageData{
			Theme: internal.AppConfig.UI.Theme,
		}
		templates.ExecuteTemplate(w, "login", data)
		return
	}

	// Logic for checking credentials (will connect to SQLite later)
	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedHash string
	// Searches for password hash tied to provided username and stores it in "storedHash"
	err := data.User_Database.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)

	// Handles errors for password hash query involving the username
	if err != nil {
		if err == sql.ErrNoRows {
			logs.Audit.Warn("Login failed: user not found", "username", username) //warning message for invalid usernames
		} else {
			logs.DB.Error("Database query error during login", "error", err)
		}
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	// Verify password matches stored password hash
	if !CheckPasswordHash(password, storedHash) {
		logs.Audit.Warn("Login failed: incorrect password", "username", username)
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	logs.Audit.Info("User logged in successfully", "username", username)

	// Create JWT
	expirationTime := time.Now().Add(24 * time.Hour) //sets token to automatically expire in 24 hours
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		logs.Sys.Error("Failed to sign JWT", "error", err, "username", username)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	// Set Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    tokenString,
		Expires:  expirationTime,
		Path:     "/",  // Makes cookies accessible on all other requests
		HttpOnly: true, // Prevents JavaScript access (XSS protection)
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := GetUsernameFromToken(r)

	cookie := &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Expires:  time.Unix(0, 0),
	}

	http.SetCookie(w, cookie)
	logs.Audit.Info("User logged out successfully", "username", user)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// GetUsernameFromToken parses the JWT and returns the username
func GetUsernameFromToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		// Securely log the absence of session
		logs.Sys.Debug("No session cookie found", "remote_addr", r.RemoteAddr)
		return "", err
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Ensure secret key matches global variable
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		logs.Audit.Warn("Failed to parse or validate token", "error", err, "remote_addr", r.RemoteAddr)
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		username, ok := claims["username"].(string)
		if !ok {
			logs.Sys.Error("Token claims missing username string")
			return "", fmt.Errorf("invalid claims")
		}
		return username, nil
	}

	logs.Sys.Warn("Invalid token claims structure", "remote_addr", r.RemoteAddr)
	return "", fmt.Errorf("invalid claims")
}

// authMiddleware checks for a valid JWT in cookies
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")

		//handles redirect to login if user not authenticated
		if err != nil {
			if err == http.ErrNoCookie {
				// We don't log this at Audit level to avoid spamming logs for guests/bots
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			logs.Sys.Warn("Bad request in auth middleware", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tknStr := c.Value
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		//catch-all redirect for expired or tampered tokens
		if err != nil || !tkn.Valid {
			logs.Audit.Warn("Auth middleware: invalid or expired token", "remote_addr", r.RemoteAddr)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
