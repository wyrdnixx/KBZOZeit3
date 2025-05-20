package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"html/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

// UserHandler handles all user-related HTTP endpoints
type UserHandler struct {
	db        *sql.DB
	store     *sessions.CookieStore
	templates *template.Template
}

// NewUserHandler creates a new UserHandler instance
func NewUserHandler(db *sql.DB, store *sessions.CookieStore, templates *template.Template) *UserHandler {
	return &UserHandler{
		db:        db,
		store:     store,
		templates: templates,
	}
}

// HandleUsers handles the user management page
func (h *UserHandler) HandleUsers(w http.ResponseWriter, r *http.Request) {
	session, err := h.store.Get(r, "session-name")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok {
		isAdmin = false
	}

	data := struct {
		Username string
		IsAdmin  bool
		Page     string
	}{
		Username: username,
		IsAdmin:  isAdmin,
		Page:     "users",
	}

	err = h.templates.ExecuteTemplate(w, "layout", data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// HandleGetUsers handles the GET /api/users endpoint
func (h *UserHandler) HandleGetUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, username, is_admin FROM users")
	if err != nil {
		log.Printf("Error querying users: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		IsAdmin  bool   `json:"is_admin"`
	}

	for rows.Next() {
		var user struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
			IsAdmin  bool   `json:"is_admin"`
		}
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

// HandleCreateUser handles the POST /api/users endpoint
func (h *UserHandler) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		IsAdmin  bool   `json:"is_admin"`
	}
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
	err := h.db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", req.Username).Scan(&exists)
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
	_, err = h.db.Exec("INSERT INTO users (username, password, is_admin) VALUES ($1, $2, $3)",
		req.Username, string(hashedPassword), req.IsAdmin)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "User created successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleMakeAdmin handles the POST /api/users/{id}/make-admin endpoint
func (h *UserHandler) HandleMakeAdmin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// Don't allow users to modify their own admin status
	session, _ := h.store.Get(r, "session-name")
	currentUsername := session.Values["username"].(string)

	var targetUsername string
	err := h.db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&targetUsername)
	if err != nil {
		http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
		return
	}

	if currentUsername == targetUsername {
		http.Error(w, `{"error":"Cannot modify your own admin status"}`, http.StatusForbidden)
		return
	}

	_, err = h.db.Exec("UPDATE users SET is_admin = true WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error updating user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "User successfully made admin",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleDeleteUser handles the DELETE /api/users/{id} endpoint
func (h *UserHandler) HandleDeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// Don't allow users to delete themselves
	session, _ := h.store.Get(r, "session-name")
	currentUsername := session.Values["username"].(string)

	var targetUsername string
	err := h.db.QueryRow("SELECT username FROM users WHERE id = $1", userID).Scan(&targetUsername)
	if err != nil {
		http.Error(w, `{"error":"User not found"}`, http.StatusNotFound)
		return
	}

	if currentUsername == targetUsername {
		http.Error(w, `{"error":"Cannot delete your own account"}`, http.StatusForbidden)
		return
	}

	_, err = h.db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "User successfully deleted",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleChangePassword handles the POST /api/users/change-password endpoint
func (h *UserHandler) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	session, _ := h.store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	var req struct {
		OldPassword     string `json:"old_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate input
	if req.NewPassword != req.ConfirmPassword {
		http.Error(w, `{"error":"New passwords do not match"}`, http.StatusBadRequest)
		return
	}

	// Get current password hash
	var currentPasswordHash string
	err := h.db.QueryRow("SELECT password FROM users WHERE id = $1", userID).Scan(&currentPasswordHash)
	if err != nil {
		log.Printf("Error querying user: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Verify old password
	err = bcrypt.CompareHashAndPassword([]byte(currentPasswordHash), []byte(req.OldPassword))
	if err != nil {
		http.Error(w, `{"error":"Current password is incorrect"}`, http.StatusUnauthorized)
		return
	}

	// Hash new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Update password
	_, err = h.db.Exec("UPDATE users SET password = $1 WHERE id = $2", string(newPasswordHash), userID)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Clear session to force re-login
	session.Values = map[interface{}]interface{}{}
	session.Save(r, w)

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "Password changed successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
