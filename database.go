package main

import (
	"database/sql"
	"fmt"
)

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

		CREATE TABLE IF NOT EXISTS contracts (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			start_date DATE NOT NULL,
			end_date DATE,
			hours_per_month INTEGER NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT valid_dates CHECK (end_date IS NULL OR end_date >= start_date)
		);

		CREATE TABLE IF NOT EXISTS time_entries (
			id SERIAL PRIMARY KEY,
			user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
			clock_in TIMESTAMP WITH TIME ZONE NOT NULL,
			clock_out TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
			CONSTRAINT valid_times CHECK (clock_out IS NULL OR clock_out >= clock_in)
		);

		-- Function to update updated_at timestamp
		CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = CURRENT_TIMESTAMP;
			RETURN NEW;
		END;
		$$ language 'plpgsql';

		-- Trigger to automatically update updated_at
		DROP TRIGGER IF EXISTS update_time_entries_updated_at ON time_entries;
		CREATE TRIGGER update_time_entries_updated_at
			BEFORE UPDATE ON time_entries
			FOR EACH ROW
			EXECUTE FUNCTION update_updated_at_column();
	`)
	if err != nil {
		return err
	}

	return nil
}
