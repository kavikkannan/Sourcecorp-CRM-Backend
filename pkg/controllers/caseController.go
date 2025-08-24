package controllers

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/config"
)

type CaseAmountRequest struct {
	PIndex string  `json:"pindex"`
	CaseID string  `json:"caseId"`
	Amount float64 `json:"amount"`
}

// AddOrUpdateAmount handles adding or updating case amount
func AddOrUpdateAmount(c *fiber.Ctx) error {
	db := config.GetDB()
	var req CaseAmountRequest

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate pindex exists in CaseName table
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM CaseName WHERE pindex = ?)", req.PIndex).Scan(&exists)
	if err != nil {
		log.Printf("Error checking if case exists: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to validate case",
		})
	}

	if !exists {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Case not found",
		})
	}

	// Insert or update the amount
	_, err = db.Exec(`
		INSERT INTO CaseAmount (pindex, caseId, amount) 
		VALUES (?, ?, ?) 
		ON DUPLICATE KEY UPDATE amount = ?`,
		req.PIndex, req.CaseID, req.Amount, req.Amount)

	if err != nil {
		log.Printf("Error updating case amount: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update case amount",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Amount updated successfully",
	})
}

// GetAmount retrieves the amount for a specific case
func GetAmount(c *fiber.Ctx) error {
	db := config.GetDB()

	var amount float64
	var caseID string
	err := db.QueryRow("SELECT caseId, amount FROM CaseAmount").Scan(&caseID, &amount)

	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error": "No amount found",
			})
		}
		log.Printf("Error fetching case amount: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch case amount",
		})
	}

	return c.JSON(fiber.Map{
		"caseId": caseID,
		"amount": amount,
	})
}

// CaseForDecryption represents case data needed for frontend decryption
type CaseForDecryption struct {
	PIndex    string `json:"pindex"`
	CaseID    string `json:"caseId"`
	Encrypted string `json:"encryptedData"`
	AgentId string `json:"agentId"`
}

// GetCasesForDecryption returns cases with encrypted data for frontend processing
func GetCasesForDecryption(c *fiber.Ctx) error {
	db := config.GetDB()

	rows, err := db.Query(`
		SELECT cn.pindex, cn.caseId, cn.coustomerDetails, cn.agentId
		FROM CaseName cn
	`)
	if err != nil {
		log.Printf("Error fetching cases for decryption: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch cases",
		})
	}
	defer rows.Close()

	var cases []CaseForDecryption
	for rows.Next() {
		var cfd CaseForDecryption
		if err := rows.Scan(&cfd.PIndex, &cfd.CaseID, &cfd.Encrypted, &cfd.AgentId); err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		cases = append(cases, cfd)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Error processing cases",
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   cases,
	})
}
