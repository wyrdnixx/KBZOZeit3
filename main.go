package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	store     *sessions.CookieStore
	templates *template.Template
	host      = getEnvOrDefault("DB_HOST", "localhost")
	port      = getEnvOrDefaultInt("DB_PORT", 5432)
	user      = getEnvOrDefault("DB_USER", "postgres")
	password  = getEnvOrDefault("DB_PASSWORD", "postgres")
	dbname    = getEnvOrDefault("DB_NAME", "kbzozeit")
)

// Helper function to get environment variable with default value
func getEnvOrDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Helper function to get environment variable as integer with default value
func getEnvOrDefaultInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func createDatabase() error {
	// Connect to postgres database first
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
		host, port, user, password)

	tempDB, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		return err
	}
	defer tempDB.Close()

	// Check if our database exists
	var exists bool
	err = tempDB.QueryRow("SELECT EXISTS(SELECT datname FROM pg_catalog.pg_database WHERE datname = $1)", dbname).Scan(&exists)
	if err != nil {
		return err
	}

	// Create database if it doesn't exist
	if !exists {
		_, err = tempDB.Exec(fmt.Sprintf("CREATE DATABASE %s", dbname))
		if err != nil {
			return err
		}
	}

	return nil
}

func initDB() error {
	// First ensure database exists
	err := createDatabase()
	if err != nil {
		return fmt.Errorf("failed to create database: %v", err)
	}

	// Now connect to our database
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		return err
	}

	// Create tables if they don't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(50) UNIQUE NOT NULL,
			password VARCHAR(100) NOT NULL,
			is_admin BOOLEAN NOT NULL DEFAULT false
		);

		CREATE TABLE IF NOT EXISTS names (
			id SERIAL PRIMARY KEY,
			name VARCHAR(100) NOT NULL
		);
	`)
	if err != nil {
		return err
	}

	// Insert example names if the table is empty
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM names").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		exampleNames := []string{
			"John", "Jane", "Michael", "Emma", "William", "Olivia", "James", "Sophia",
			"Alexander", "Isabella", "Benjamin", "Mia", "Lucas", "Charlotte", "Henry",
			"Amelia", "Sebastian", "Harper", "Jack", "Evelyn", "Daniel", "Abigail",
			"Matthew", "Emily", "David", "Elizabeth", "Joseph", "Sofia", "Samuel",
			"Avery", "Gabriel", "Ella", "Carter", "Scarlett", "Owen", "Victoria",
			"Wyatt", "Madison", "Oliver", "Luna", "Elijah", "Grace", "Liam", "Chloe",
			"Jacob", "Penelope", "Ethan", "Layla", "Noah", "Riley", "Aiden",
		}

		for _, name := range exampleNames {
			_, err := db.Exec("INSERT INTO names (name) VALUES ($1)", name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func initTemplates() (*template.Template, error) {
	// Create a new template
	tmpl := template.New("layout")

	// Get all template files
	pattern := "templates/*.html"
	templateFiles, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("error finding templates: %v", err)
	}

	// Parse all templates at once
	tmpl, err = tmpl.ParseFiles(templateFiles...)
	if err != nil {
		return nil, fmt.Errorf("error parsing templates: %v", err)
	}

	// Verify required templates exist
	required := []string{"layout", "dashboard-content", "login-content", "home-content"}
	for _, name := range required {
		if tmpl.Lookup(name) == nil {
			return nil, fmt.Errorf("required template %q not found", name)
		}
	}

	log.Printf("Successfully loaded templates: %v", required)
	return tmpl, nil
}

func main() {
	log.Println("Initializing application...")

	// Initialize session store with secure configuration
	store = sessions.NewCookieStore([]byte("super-secret-key"))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
	}
	log.Println("Session store initialized with custom options")

	// Initialize templates
	log.Println("Loading templates...")
	var err error
	templates, err = initTemplates()
	if err != nil {
		log.Fatal("Failed to load templates:", err)
	}
	log.Println("Templates loaded successfully")

	// Initialize database
	log.Println("Initializing database...")
	if err := initDB(); err != nil {
		log.Fatal("Database initialization failed:", err)
	}
	log.Println("Database initialized successfully")

	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Routes
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET")
	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/dashboard", authMiddleware(dashboardHandler)).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	// API routes
	r.HandleFunc("/api/names", authMiddleware(getNamesHandler)).Methods("GET")

	// Admin API routes
	r.HandleFunc("/api/users", authMiddleware(adminRequired(getUsersHandler))).Methods("GET")
	r.HandleFunc("/api/users", authMiddleware(adminRequired(createUserHandler))).Methods("POST")
	r.HandleFunc("/api/users/{id}/make-admin", authMiddleware(adminRequired(makeAdminHandler))).Methods("POST")
	r.HandleFunc("/api/users/{id}", authMiddleware(adminRequired(deleteUserHandler))).Methods("DELETE")

	log.Println("Routes configured, server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", r))
}

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

	data := struct {
		Username string
		Page     string
	}{
		Username: username,
		Page:     "home",
	}

	log.Printf("Executing home template with data: %+v", data)
	err = templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Println("Home template executed successfully")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling login GET request from %s", r.RemoteAddr)
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Check if user is already authenticated
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		log.Printf("User already authenticated, redirecting to dashboard")
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		username = ""
	}

	data := struct {
		Username string
		Page     string
	}{
		Username: username,
		Page:     "login",
	}

	log.Printf("Login page requested, username from session: %q", username)
	err = templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Println("Login template executed successfully")
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling login POST request from %s", r.RemoteAddr)
	username := r.FormValue("username")
	password := r.FormValue("password")

	log.Printf("Login attempt for username: %s", username)

	var (
		storedPassword string
		isAdmin        bool
	)
	err := db.QueryRow("SELECT password, is_admin FROM users WHERE username = $1", username).Scan(&storedPassword, &isAdmin)
	if err != nil {
		if err == sql.ErrNoRows {
			// Create new user
			log.Printf("Creating new user: %s", username)
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				log.Printf("Error hashing password: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// First user in the system becomes an admin
			var userCount int
			err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount)
			if err != nil {
				log.Printf("Error counting users: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			isAdmin = userCount == 0 // First user becomes admin

			_, err = db.Exec("INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)",
				username, string(hashedPassword), isAdmin)
			if err != nil {
				log.Printf("Error creating user: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			log.Printf("New user created successfully: %s (admin: %v)", username, isAdmin)
		} else {
			log.Printf("Database error: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		// Verify password
		err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
		if err != nil {
			log.Printf("Invalid password for user: %s", username)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		log.Printf("Password verified for user: %s (admin: %v)", username, isAdmin)
	}

	// Get a new session or existing one
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set session values
	session.Values["authenticated"] = true
	session.Values["username"] = username
	session.Values["is_admin"] = isAdmin

	// Save session
	err = session.Save(r, w)
	if err != nil {
		log.Printf("Error saving session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	log.Printf("Session saved successfully for user: %s with values: %+v", username, session.Values)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling dashboard request from %s", r.RemoteAddr)
	session, err := store.Get(r, "session-name")
	if err != nil {
		log.Printf("Error getting session in dashboard: %v", err)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	auth, ok := session.Values["authenticated"].(bool)
	if !ok || !auth {
		log.Printf("User not authenticated, redirecting to login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		log.Printf("No username in session, redirecting to login")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok {
		isAdmin = false
	}

	log.Printf("Rendering dashboard for user: %s (admin: %v)", username, isAdmin)
	data := struct {
		Username string
		IsAdmin  bool
		Page     string
	}{
		Username: username,
		IsAdmin:  isAdmin,
		Page:     "dashboard",
	}

	err = templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Template error in dashboard: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	log.Printf("Dashboard rendered successfully for user: %s", username)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Values["username"] = nil
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func getNamesHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT name FROM names")
	if err != nil {
		log.Printf("Error querying names: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			log.Printf("Error scanning name: %v", err)
			http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
			return
		}
		names = append(names, name)
	}

	// Use proper JSON marshaling
	response := struct {
		Names []string `json:"names"`
	}{
		Names: names,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	log.Printf("Successfully returned %d names", len(names))
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

// Add a new function to check if a user is admin
func isUserAdmin(username string) (bool, error) {
	var isAdmin bool
	err := db.QueryRow("SELECT is_admin FROM users WHERE username = $1", username).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin, nil
}

// Add adminRequired middleware
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

// Add these structs for JSON responses
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	IsAdmin  bool   `json:"is_admin"`
}

type APIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Add these new handler functions
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, username, is_admin FROM users")
	if err != nil {
		log.Printf("Error querying users: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.IsAdmin); err != nil {
			log.Printf("Error scanning user: %v", err)
			http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(users); err != nil {
		log.Printf("Error encoding JSON: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
}

func makeAdminHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// Don't allow users to modify their own admin status
	session, _ := store.Get(r, "session-name")
	currentUsername := session.Values["username"].(string)

	var targetUsername string
	err := db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&targetUsername)
	if err != nil {
		http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
		return
	}

	if currentUsername == targetUsername {
		http.Error(w, `{"error":"Cannot modify your own admin status"}`, http.StatusForbidden)
		return
	}

	_, err = db.Exec("UPDATE users SET is_admin = true WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "User successfully made admin",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// Don't allow users to delete themselves
	session, _ := store.Get(r, "session-name")
	currentUsername := session.Values["username"].(string)

	var targetUsername string
	err := db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&targetUsername)
	if err != nil {
		http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
		return
	}

	if currentUsername == targetUsername {
		http.Error(w, `{"error":"Cannot delete your own account"}`, http.StatusForbidden)
		return
	}

	_, err = db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "User successfully deleted",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"is_admin"`
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"Username and password are required"}`, http.StatusBadRequest)
		return
	}

	// Check if username already exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", req.Username).Scan(&exists)
	if err != nil {
		log.Printf("Error checking username existence: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, `{"error":"Username already exists"}`, http.StatusConflict)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Create user
	_, err = db.Exec("INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)",
		req.Username, string(hashedPassword), req.IsAdmin)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := APIResponse{
		Success: true,
		Message: "User created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
