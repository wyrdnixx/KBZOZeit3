package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func homeHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling home request from %s", r.RemoteAddr)

	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get authentication status
	auth, _ := session.Values["authenticated"].(bool)
	username, ok := session.Values["username"].(string)
	if !ok {
		username = ""
	}

	log.Printf("Home page requested, auth: %v, username: %q", auth, username)

	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok {
		isAdmin = false
	}

	data := map[string]interface{}{
		"Authenticated": auth,
		"Username":      username,
		"IsAdmin":       isAdmin,
		"Page":          "home",
	}

	err = templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// If user is already authenticated, redirect to dashboard
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Authenticated": false,
		"Page":          "login",
	}

	err = templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var (
		storedPassword string
		userID         int
		isAdmin        bool
	)

	err := db.QueryRow("SELECT id, password, is_admin FROM users WHERE username = $1", username).Scan(&userID, &storedPassword, &isAdmin)
	if err != nil {
		log.Printf("Error querying user: %v", err)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		log.Printf("Invalid password for user %s: %v", username, err)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	session.Values["authenticated"] = true
	session.Values["username"] = username
	session.Values["user_id"] = userID
	session.Values["is_admin"] = isAdmin

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	log.Printf("User %s successfully logged in", username)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		log.Printf("Error getting username from session")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	userID, ok := session.Values["user_id"].(int)
	if !ok {
		log.Printf("Error getting user_id from session")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok {
		isAdmin = false
	}

	// Get current active contract
	var contract struct {
		ID            int
		StartDate     time.Time
		EndDate       *time.Time
		HoursPerMonth int
	}

	err = db.QueryRow(`
		SELECT id, start_date, end_date, hours_per_month 
		FROM contracts 
		WHERE user_id = $1 
		AND (end_date IS NULL OR end_date >= CURRENT_DATE)
		AND start_date <= CURRENT_DATE
		ORDER BY start_date DESC 
		LIMIT 1`, userID).Scan(&contract.ID, &contract.StartDate, &contract.EndDate, &contract.HoursPerMonth)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error querying contract: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get current clock-in status
	var currentClockIn *time.Time
	err = db.QueryRow(`
		SELECT clock_in 
		FROM time_entries 
		WHERE user_id = $1 
		AND clock_out IS NULL 
		ORDER BY clock_in DESC 
		LIMIT 1`, userID).Scan(&currentClockIn)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error querying current clock-in: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Username":      username,
		"Authenticated": true,
		"IsAdmin":       isAdmin,
		"Page":          "dashboard",
		"Contract":      contract,
		"IsClockedIn":   currentClockIn != nil,
		"ClockInTime":   currentClockIn,
	}

	err = templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values = map[interface{}]interface{}{}
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Auth middleware checking request from %s for path: %s", r.RemoteAddr, r.URL.Path)
		session, err := store.Get(r, "session-name")
		if err != nil {
			log.Printf("Error getting session in middleware: %v", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			log.Printf("User not authenticated")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func adminRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		isAdmin, ok := session.Values["is_admin"].(bool)
		if !ok || !isAdmin {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}
