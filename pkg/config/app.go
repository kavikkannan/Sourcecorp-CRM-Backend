package config

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

// ensureParseTime ensures that parseTime=true is in the DSN string
func ensureParseTime(dsn string) string {
	if strings.Contains(dsn, "parseTime=true") {
		return dsn
	}

	// Check if DSN already has query parameters
	if strings.Contains(dsn, "?") {
		// Append parseTime=true to existing parameters
		return dsn + "&parseTime=true"
	}
	// Add parseTime=true as first parameter
	return dsn + "?parseTime=true"
}

func Connect() {
	var err error

	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		log.Fatal("DB_DSN environment variable is not set")
	}

	// Ensure parseTime=true is in the DSN to properly parse DATE/DATETIME columns
	dsn = ensureParseTime(dsn)

	// Try connecting to MySQL using DSN from environment
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Printf("❌ Failed to open database connection: %v\n", err)
		log.Fatal("Exiting due to database connection error")
	}

	// Test the connection
	err = DB.Ping()
	if err != nil {
		log.Printf("❌ Failed to ping database: %v\n", err)
		log.Fatal("Exiting due to database connection error")
	}

	log.Println("✅ Connected to MySQL successfully!")

	err = createTables(DB)
	if err != nil {
		log.Fatalf("❌ Failed to create tables: %v\n", err)
	}

	DB.SetMaxOpenConns(25)
	DB.SetMaxIdleConns(25)
	DB.SetConnMaxLifetime(5 * time.Minute)
	log.Println("✅ Database connection pool configured successfully")
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
			caseId VARCHAR(255) NOT NULL UNIQUE

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
			readStatus BOOLEAN NOT NULL DEFAULT FALSE,
			caseAgentId INT NOT NULL,
			caseName VARCHAR(255) NOT NULL

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
		`CREATE TABLE IF NOT EXISTS CaseAmount (
		pindex VARCHAR(255) NOT NULL PRIMARY KEY,
		caseId VARCHAR(255) NOT NULL,
		amount DECIMAL(12,2) NOT NULL,
		FOREIGN KEY (pindex) REFERENCES CaseName(pindex) ON DELETE CASCADE
	) ENGINE=InnoDB;`,
		`CREATE TABLE IF NOT EXISTS LeaveRequests (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			leave_type VARCHAR(50) NOT NULL,
			from_date DATE NOT NULL,
			to_date DATE NOT NULL,
			number_of_days INT NOT NULL,
			reason TEXT NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'Pending',
			remarks TEXT DEFAULT NULL,
			approved_by INT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			FOREIGN KEY (user_id) REFERENCES Login(id) ON DELETE CASCADE,
			FOREIGN KEY (approved_by) REFERENCES Login(id) ON DELETE SET NULL
		) ENGINE=InnoDB;`,
		`CREATE TABLE IF NOT EXISTS LeaveBalances (
			id INT AUTO_INCREMENT PRIMARY KEY,
			user_id INT NOT NULL,
			leave_type VARCHAR(50) NOT NULL,
			total_leaves INT NOT NULL DEFAULT 0,
			used_leaves INT NOT NULL DEFAULT 0,
			remaining_leaves INT NOT NULL DEFAULT 0,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			UNIQUE KEY user_leave_type (user_id, leave_type),
			FOREIGN KEY (user_id) REFERENCES Login(id) ON DELETE CASCADE
		) ENGINE=InnoDB;`,
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
