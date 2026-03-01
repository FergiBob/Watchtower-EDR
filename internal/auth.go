package internal

// auth.go provides the authentication logic for the web UI.
// This includes hashing passwords, protecting routes, generating JWT tokens, etc.

import (
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("YOUR_SECRET_KEY") // In production, use an environment variable!

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

	//sends the login page to the browser
	if r.Method == http.MethodGet {
		http.ServeFile(w, r, "./web/public/login.html")
		return
	}

	// Logic for checking credentials (will connect to SQLite later)
	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedHash string
	// Searches for password hash tied to provided username and stores it in "storedHash"
	err := Main_Database.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)

	// Handles errors for password hash query involving the username
	if err != nil {
		if err == sql.ErrNoRows {
			slog.Warn("Login failed: user not found", "username", username) //warning message for invalid usernames
		} else {
			slog.Error("Database query error during login", "error", err)
		}
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	// Verify password matches stored password hash
	if !CheckPasswordHash(password, storedHash) {
		slog.Warn("Login failed: incorrect password", "username", username)
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	slog.Info("User logged in successfully", "username", username)

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
		slog.Error("Failed to sign JWT", "error", err)
		http.Error(w, "Internal Server Error", 500)
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
	slog.Info("User logged out successfully", "username", user)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// GetUsernameFromToken parses the JWT and returns the username
func GetUsernameFromToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		// Log the lack of a cookie securely
		slog.Info("No session cookie found")
		return "", err
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("YOUR_SECRET_KEY"), nil
	})

	if err != nil || !token.Valid {
		// Log the specific parsing error securely
		slog.Warn("Failed to parse token", "error", err)
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		username := claims["username"].(string)
		return username, nil
	}

	slog.Warn("Invalid token claims structure")
	return "", fmt.Errorf("invalid claims")
}

// authMiddleware checks for a valid JWT in cookies
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")

		//handles redirect to login if user not authenticated
		if err != nil {
			if err == http.ErrNoCookie {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tknStr := c.Value
		claims := &Claims{}

		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		//catch-all redirect
		if err != nil || !tkn.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
