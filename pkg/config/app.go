package config

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB
const (
	schemaName  = "kk"
	localDSN    = "root:root@tcp(db:3306)/mydb?parseTime=true"
)
func Connect() {
	var err error

	// Try connecting to local MySQL
	DB, err = sql.Open("mysql", localDSN)
	if err == nil && DB.Ping() == nil {
		fmt.Println("✅ Connected to local MySQL successfully!")
	} else {
		fmt.Println("❌ Local MySQL unavailable. Switching to Cloudflared tunnel...")

	}
	err = createTables(DB)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(25)
	DB.SetConnMaxLifetime(5 * time.Minute)
}



// createTables ensures tables exist in the database
func createTables(db *sql.DB) error {
	tableStatements := []string{
		`CREATE TABLE IF NOT EXISTS Login (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(100) NOT NULL,
			email VARCHAR(255) NOT NULL UNIQUE,
			number VARCHAR(255) NOT NULL UNIQUE,
			password BLOB NOT NULL,
			is_admin BOOLEAN NOT NULL DEFAULT FALSE,
			no_of_files INT NOT NULL,
			branch VARCHAR(100) NOT NULL,
			role VARCHAR(100) NOT NULL,
			salary VARCHAR(255) NOT NULL,
    		appointed_members TEXT DEFAULT NULL,
			reportTo INT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS CaseName (
			Pfile VARCHAR(400) NOT NULL,
			PIV VARCHAR(400) NOT NULL,
			Name VARCHAR(100) NOT NULL,
			status VARCHAR(255) NOT NULL,
			agentId VARCHAR(255) NOT NULL,
			pindex VARCHAR(255) NOT NULL PRIMARY KEY UNIQUE, 
			coustomerDetails VARCHAR(500) NOT NULL,
			unknown1 TEXT NOT NULL,
			caseDate TEXT NOT NULL,
			caseId TEXT NOT NULL

		);`,
		`CREATE TABLE IF NOT EXISTS CaseFiles (
			id INT AUTO_INCREMENT PRIMARY KEY,
			pindex VARCHAR(255) NOT NULL,
			case_name TEXT NOT NULL,
			file_name TEXT NOT NULL,
			file_content LONGBLOB NOT NULL,
			FOREIGN KEY (pindex) REFERENCES CaseName(pindex) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS Notification (
			id INT AUTO_INCREMENT PRIMARY KEY,
			fromUser INT NOT NULL,
			toUser INT NOT NULL,
			tousername TEXT NOT NULL,
			note TEXT NOT NULL,
			casePfile VARCHAR(255) NOT NULL,
			mark BOOLEAN NOT NULL DEFAULT FALSE,
			readStatus BOOLEAN NOT NULL DEFAULT FALSE

		);`,
		`CREATE TABLE IF NOT EXISTS EncryptedMessages (
			eindex VARCHAR(255) NOT NULL UNIQUE PRIMARY KEY,
			emessage TEXT NOT NULL,
			iv TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS EncryptedPFile (
			eindex VARCHAR(255) NOT NULL UNIQUE PRIMARY KEY,
			pfile TEXT NOT NULL,
			pfileiv TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS EncryptedLogPFile (
			eindex VARCHAR(255) NOT NULL UNIQUE PRIMARY KEY,
			pfile TEXT NOT NULL,
			pfileiv TEXT NOT NULL,
			version INT NOT NULL
		);`,
	}

	for _, stmt := range tableStatements {
		_, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("failed to create table: %v", err)
		}
	}
	return nil
}

// GetDB returns the database instance
func GetDB() *sql.DB {
	return DB
}
