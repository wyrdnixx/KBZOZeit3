package main

import (
	"encoding/json"
	"log"
	"net/http"

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

	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok {
		isAdmin = false
	}

	data := map[string]interface{}{
		"Username":      username,
		"Authenticated": true,
		"IsAdmin":       isAdmin,
		"Page":          "dashboard",
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

func getNamesHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT name FROM names ORDER BY name")
	if err != nil {
		log.Printf("Error querying names: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var namesList []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		namesList = append(namesList, name)
	}

	response := map[string]interface{}{
		"names": namesList,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
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

		// Debug session values
		log.Printf("Session values: %+v", session.Values)

		auth, ok := session.Values["authenticated"].(bool)
		if !ok {
			log.Printf("No auth value in session or wrong type")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if !auth {
			log.Printf("User not authenticated (auth value is false)")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		username, ok := session.Values["username"].(string)
		log.Printf("Username from session: %q (valid: %v)", username, ok)

		log.Printf("User authenticated in middleware, proceeding with request")
		next.ServeHTTP(w, r)
	}
}

func adminRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session-name")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		isAdmin, ok := session.Values["is_admin"].(bool)
		if !ok || !isAdmin {
			http.Error(w, "Unauthorized - Admin access required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}
