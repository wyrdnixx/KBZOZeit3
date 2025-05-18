package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

type Contract struct {
	ID            int        `json:"id"`
	UserID        int        `json:"user_id"`
	StartDate     time.Time  `json:"start_date"`
	EndDate       *time.Time `json:"end_date,omitempty"`
	HoursPerMonth int        `json:"hours_per_month"`
	CreatedAt     time.Time  `json:"created_at"`
}

type TimeEntry struct {
	ID        int        `json:"id"`
	UserID    int        `json:"user_id"`
	ClockIn   time.Time  `json:"clock_in"`
	ClockOut  *time.Time `json:"clock_out,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// handleClockIn handles the POST /api/clock-in endpoint
func handleClockIn(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	// Check if user is already clocked in
	var existingClockIn time.Time
	err := db.QueryRow(`
		SELECT clock_in 
		FROM time_entries 
		WHERE user_id = $1 
		AND clock_out IS NULL
	`, userID).Scan(&existingClockIn)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Error checking existing clock-in: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		http.Error(w, "Already clocked in", http.StatusBadRequest)
		return
	}

	// Create new time entry
	_, err = db.Exec(`
		INSERT INTO time_entries (user_id, clock_in)
		VALUES ($1, CURRENT_TIMESTAMP)
	`, userID)
	if err != nil {
		log.Printf("Error creating time entry: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleClockOut handles the POST /api/clock-out endpoint
func handleClockOut(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	// Find the active time entry
	var entryID int
	err := db.QueryRow(`
		SELECT id 
		FROM time_entries 
		WHERE user_id = $1 
		AND clock_out IS NULL
	`, userID).Scan(&entryID)
	if err == sql.ErrNoRows {
		http.Error(w, "No active clock-in found", http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("Error finding active time entry: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Update the time entry with clock-out time
	_, err = db.Exec(`
		UPDATE time_entries 
		SET clock_out = CURRENT_TIMESTAMP 
		WHERE id = $1
	`, entryID)
	if err != nil {
		log.Printf("Error updating time entry: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetTimeEntries handles the GET /api/time-entries endpoint
func handleGetTimeEntries(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	// Get month from query parameters, default to current month
	monthOffset, _ := strconv.Atoi(r.URL.Query().Get("month_offset"))

	// Calculate start and end of month
	now := time.Now()
	currentMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, monthOffset, 0)
	startOfMonth := currentMonth
	endOfMonth := currentMonth.AddDate(0, 1, 0).Add(-time.Second)

	// Query time entries for the month
	rows, err := db.Query(`
		SELECT id, clock_in, clock_out, created_at, updated_at
		FROM time_entries
		WHERE user_id = $1
		AND clock_in >= $2
		AND clock_in < $3
		ORDER BY clock_in ASC
	`, userID, startOfMonth, endOfMonth)
	if err != nil {
		log.Printf("Error querying time entries: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var entries []TimeEntry
	for rows.Next() {
		var entry TimeEntry
		err := rows.Scan(&entry.ID, &entry.ClockIn, &entry.ClockOut, &entry.CreatedAt, &entry.UpdatedAt)
		if err != nil {
			log.Printf("Error scanning time entry: %v", err)
			continue
		}
		entry.UserID = userID
		entries = append(entries, entry)
	}

	// Calculate monthly totals
	var totalWorkedMinutes int
	for _, entry := range entries {
		if entry.ClockOut != nil {
			duration := entry.ClockOut.Sub(entry.ClockIn)
			totalWorkedMinutes += int(duration.Minutes())
		}
	}

	response := map[string]interface{}{
		"entries": entries,
		"month": map[string]interface{}{
			"start":       startOfMonth,
			"end":         endOfMonth,
			"total_hours": float64(totalWorkedMinutes) / 60.0,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleUpdateTimeEntry handles the PUT /api/time-entries/{id} endpoint
func handleUpdateTimeEntry(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)
	entryID := mux.Vars(r)["id"]

	var req struct {
		ClockIn  time.Time  `json:"clock_in"`
		ClockOut *time.Time `json:"clock_out,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify the time entry belongs to the user
	var exists bool
	err := db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 
			FROM time_entries 
			WHERE id = $1 
			AND user_id = $2
		)
	`, entryID, userID).Scan(&exists)
	if err != nil {
		log.Printf("Error checking time entry ownership: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Time entry not found", http.StatusNotFound)
		return
	}

	// Update the time entry
	_, err = db.Exec(`
		UPDATE time_entries 
		SET clock_in = $1, clock_out = $2 
		WHERE id = $3
	`, req.ClockIn, req.ClockOut, entryID)
	if err != nil {
		log.Printf("Error updating time entry: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleCreateContract handles the POST /api/contracts endpoint
func handleCreateContract(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID        int    `json:"user_id"`
		StartDate     string `json:"start_date"`
		EndDate       string `json:"end_date,omitempty"`
		HoursPerMonth int    `json:"hours_per_month"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Parse start date
	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		log.Printf("Error parsing start date: %v", err)
		http.Error(w, "Invalid start date format", http.StatusBadRequest)
		return
	}

	// Parse end date if provided
	var endDate *time.Time
	if req.EndDate != "" {
		parsed, err := time.Parse("2006-01-02", req.EndDate)
		if err != nil {
			log.Printf("Error parsing end date: %v", err)
			http.Error(w, "Invalid end date format", http.StatusBadRequest)
			return
		}
		endDate = &parsed
	}

	// Validate input
	if req.HoursPerMonth <= 0 {
		http.Error(w, "Hours per month must be positive", http.StatusBadRequest)
		return
	}

	// Create the contract
	_, err = db.Exec(`
		INSERT INTO contracts (user_id, start_date, end_date, hours_per_month)
		VALUES ($1, $2, $3, $4)
	`, req.UserID, startDate, endDate, req.HoursPerMonth)
	if err != nil {
		log.Printf("Error creating contract: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// handleDeleteContract handles the DELETE /api/contracts/{id} endpoint
func handleDeleteContract(w http.ResponseWriter, r *http.Request) {
	contractID := mux.Vars(r)["id"]

	_, err := db.Exec("DELETE FROM contracts WHERE id = $1", contractID)
	if err != nil {
		log.Printf("Error deleting contract: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleGetContracts handles the GET /api/contracts endpoint
func handleGetContracts(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	query := `
		SELECT id, user_id, start_date, end_date, hours_per_month, created_at
		FROM contracts
		WHERE user_id = $1
		ORDER BY start_date DESC
	`

	rows, err := db.Query(query, userID)
	if err != nil {
		log.Printf("Error querying contracts: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var contracts []Contract
	for rows.Next() {
		var c Contract
		err := rows.Scan(&c.ID, &c.UserID, &c.StartDate, &c.EndDate, &c.HoursPerMonth, &c.CreatedAt)
		if err != nil {
			log.Printf("Error scanning contract: %v", err)
			continue
		}
		contracts = append(contracts, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(contracts)
}

// handleGetTotalHours handles the GET /api/time-entries/total endpoint
func handleGetTotalHours(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")

	var query string
	var args []interface{}

	if endDate != "" {
		query = `
			SELECT COALESCE(SUM(
				EXTRACT(EPOCH FROM (COALESCE(clock_out, CURRENT_TIMESTAMP) - clock_in)) / 3600
			), 0) as total_hours
			FROM time_entries
			WHERE user_id = $1
			AND clock_in >= $2
			AND clock_in <= $3
		`
		args = []interface{}{userID, startDate, endDate}
	} else {
		query = `
			SELECT COALESCE(SUM(
				EXTRACT(EPOCH FROM (COALESCE(clock_out, CURRENT_TIMESTAMP) - clock_in)) / 3600
			), 0) as total_hours
			FROM time_entries
			WHERE user_id = $1
			AND clock_in >= $2
		`
		args = []interface{}{userID, startDate}
	}

	var totalHours float64
	err := db.QueryRow(query, args...).Scan(&totalHours)
	if err != nil {
		log.Printf("Error querying total hours: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"total_hours": totalHours,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleManualTimeEntry handles the POST /api/time-entries/manual endpoint
func handleManualTimeEntry(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	userID := session.Values["user_id"].(int)

	var req struct {
		ClockIn  time.Time `json:"clock_in"`
		ClockOut time.Time `json:"clock_out"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate times
	if !req.ClockOut.After(req.ClockIn) {
		http.Error(w, "Clock out time must be after clock in time", http.StatusBadRequest)
		return
	}

	// Create the time entry
	_, err := db.Exec(`
		INSERT INTO time_entries (user_id, clock_in, clock_out)
		VALUES ($1, $2, $3)
	`, userID, req.ClockIn, req.ClockOut)
	if err != nil {
		log.Printf("Error creating manual time entry: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}
