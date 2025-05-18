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
