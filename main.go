package main

import (
	"database/sql"
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
	required := []string{"layout", "dashboard-content", "login-content", "home-content", "users-content"}
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

	// Initialize user handler
	userHandler := NewUserHandler(db, store, templates)

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Routes
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET")
	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/dashboard", authMiddleware(dashboardHandler)).Methods("GET")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")
	r.HandleFunc("/users", authMiddleware(adminRequired(userHandler.HandleUsers))).Methods("GET")

	// API routes
	r.HandleFunc("/api/names", authMiddleware(getNamesHandler)).Methods("GET")

	// Admin API routes
	r.HandleFunc("/api/users", authMiddleware(adminRequired(userHandler.HandleGetUsers))).Methods("GET")
	r.HandleFunc("/api/users", authMiddleware(adminRequired(userHandler.HandleCreateUser))).Methods("POST")
	r.HandleFunc("/api/users/{id}/make-admin", authMiddleware(adminRequired(userHandler.HandleMakeAdmin))).Methods("POST")
	r.HandleFunc("/api/users/{id}", authMiddleware(adminRequired(userHandler.HandleDeleteUser))).Methods("DELETE")

	log.Println("Routes configured, server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", r))
}
