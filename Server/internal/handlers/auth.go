package handlers

// auth.go provides the authentication logic for the web UI.
// This includes hashing passwords, protecting routes, generating JWT tokens, etc.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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

type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	UpdatedAt string `json:"updated_at"`
}

// Helper function to generate a secure random string
func generateRandomString(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
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
	err := data.User_Database.QueryRow("SELECT password_hash FROM users WHERE LOWER(username) = LOWER(?)", username).Scan(&storedHash)

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

	// Set JWT Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    tokenString,
		Expires:  expirationTime,
		Path:     "/",  // Makes cookies accessible on all other requests
		HttpOnly: true, // Prevents JavaScript access (XSS protection)
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	// Generate a random CSRF token
	csrfToken, err := generateRandomString(32)
	if err != nil {
		logs.Sys.Error("Failed to generate CSRF token", "error", err)
		// We can proceed with login, but shutdown might fail later
	}

	// Set CSRF Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  expirationTime,
		Path:     "/",
		HttpOnly: false, // Must be false so JS can read it
		Secure:   true,
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

func GetUserByUsername(username string) (User, error) {
	var user User
	user.Username = username

	// Use & (pointers) so the DB driver can modify the struct fields
	err := data.QuerySingleRow(
		data.User_Database,
		"SELECT id, IFNULL(email, ''), updated_on FROM users WHERE username = ?",
		[]any{username},
		&user.ID,
		&user.Email,
		&user.UpdatedAt,
	)

	if err != nil {
		// It is better to return an error so the handler knows if the user exists
		return user, err
	}

	return user, nil
}

func updateUserInformation(w http.ResponseWriter, r *http.Request, username string) {
	var updateReq struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		logs.Sys.Error("Failed to decode user update JSON", "error", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// --- VALIDATION ---
	if updateReq.Email == "" {
		http.Error(w, "Email cannot be empty", http.StatusBadRequest)
		return
	}

	if len(updateReq.Username) < 4 || len(updateReq.Username) > 16 {
		http.Error(w, "Username must be between 4 and 16 characters long", http.StatusBadRequest)
	}

	var query string
	var args []any

	if updateReq.Password != "" {
		// Enforce a minimum password length before hashing
		if len(updateReq.Password) < 8 {
			http.Error(w, "Password must be at least 8 characters", http.StatusBadRequest)
			return
		}

		hashedPassword, err := HashPassword(updateReq.Password)
		if err != nil {
			logs.Sys.Error("Failed to hash password", "error", err)
			http.Error(w, "Internal error", 500)
			return
		}
		query = "UPDATE users SET username = ?, email = ?, password_hash = ?, updated_on = CURRENT_TIMESTAMP WHERE username = ?"
		args = []any{updateReq.Username, updateReq.Email, hashedPassword, username}
	} else {
		query = "UPDATE users SET username = ?, email = ?, updated_on = CURRENT_TIMESTAMP WHERE username = ?"
		args = []any{updateReq.Username, updateReq.Email, username}
	}

	result, err := data.User_Database.Exec(query, args...)
	if err != nil {
		logs.DB.Error("Update failed", "error", err, "username", username)
		http.Error(w, "Database error", 500)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		http.Error(w, "No changes made", http.StatusNotFound)
		return
	}

	if updateReq.Username != username {
		// 1. Clear the session token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Expires:  time.Unix(0, 0),
		})

		// 2. Clear the CSRF token cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: false,
			Expires:  time.Unix(0, 0),
		})

		// 3. Return redirect header for frontend to handle
		w.Header().Set("X-Redirect", "/login")
		w.WriteHeader(http.StatusOK) // Use 200 so the frontend fetch is 'ok'
		return
	}

	logs.Audit.Info("User profile updated", "username", username)
	w.WriteHeader(http.StatusNoContent)
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
