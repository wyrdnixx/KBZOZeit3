package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// handleDeleteTimeEntry handles the DELETE /api/time-entries/{id} endpoint
func handleDeleteTimeEntry(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	timeEntryID := vars["id"]

	// Get user ID from session
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	// Delete the time entry
	_, err := db.Exec("DELETE FROM time_entries WHERE id = $1 AND user_id = $2", timeEntryID, userID)
	if err != nil {
		log.Printf("Error deleting time entry: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	response := struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{
		Success: true,
		Message: "Time entry deleted successfully",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
