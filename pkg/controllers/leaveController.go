package controllers

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/config"
)

// Helper function to get user ID from JWT token
func getUserIDFromToken(c *fiber.Ctx) (int, error) {
	cookie := c.Cookies("jwt")
	if cookie == "" {
		return 0, fmt.Errorf("no JWT token found")
	}

	token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		return 0, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["Issuer"] == nil {
		return 0, fmt.Errorf("invalid claims in token")
	}

	userID, err := strconv.Atoi(claims["Issuer"].(string))
	if err != nil {
		return 0, fmt.Errorf("invalid user ID in token")
	}

	return userID, nil
}

// Helper function to get user role and admin status from JWT token
func getUserRoleFromToken(c *fiber.Ctx) (int, bool, string, error) {
	cookie := c.Cookies("jwt")
	if cookie == "" {
		return 0, false, "", fmt.Errorf("no JWT token found")
	}

	token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		return 0, false, "", fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["Issuer"] == nil {
		return 0, false, "", fmt.Errorf("invalid claims in token")
	}

	userID, err := strconv.Atoi(claims["Issuer"].(string))
	if err != nil {
		return 0, false, "", fmt.Errorf("invalid user ID in token")
	}

	// Get IsAdmin from JWT if available
	isAdminFromJWT := false
	if isAdminVal, ok := claims["IsAdmin"]; ok {
		if isAdminBool, ok := isAdminVal.(bool); ok {
			isAdminFromJWT = isAdminBool
		}
	}

	// Get role from database (source of truth)
	var isAdmin bool
	var role string
	err = config.DB.QueryRow("SELECT is_admin, role FROM Login WHERE id = ?", userID).Scan(&isAdmin, &role)
	if err != nil {
		// If database query fails, use JWT values as fallback
		if err == sql.ErrNoRows {
			return userID, isAdminFromJWT, "", nil
		}
		return userID, isAdminFromJWT, "", err
	}

	return userID, isAdmin, role, nil
}

// Helper function to check if user is HR or Admin
func isHROrAdmin(userID int) (bool, error) {
	var isAdmin bool
	var role string
	err := config.DB.QueryRow("SELECT is_admin, role FROM Login WHERE id = ?", userID).Scan(&isAdmin, &role)
	if err != nil {
		return false, err
	}
	return isAdmin || role == "HR", nil
}

// Calculate number of days between two dates
func calculateDays(fromDate, toDate time.Time) int {
	days := int(toDate.Sub(fromDate).Hours()/24) + 1
	if days < 1 {
		return 1
	}
	return days
}

// CreateLeaveRequest creates a new leave request
func CreateLeaveRequest(c *fiber.Ctx) error {
	userID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid input data",
		})
	}

	// Parse dates
	fromDateStr, ok := data["from_date"].(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "from_date is required",
		})
	}

	toDateStr, ok := data["to_date"].(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "to_date is required",
		})
	}

	fromDate, err := time.Parse("2006-01-02", fromDateStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid from_date format. Use YYYY-MM-DD",
		})
	}

	toDate, err := time.Parse("2006-01-02", toDateStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid to_date format. Use YYYY-MM-DD",
		})
	}

	if toDate.Before(fromDate) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "to_date must be after from_date",
		})
	}

	numberOfDays := calculateDays(fromDate, toDate)

	leaveType, ok := data["leave_type"].(string)
	if !ok || leaveType == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "leave_type is required",
		})
	}

	reason, ok := data["reason"].(string)
	if !ok || reason == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "reason is required",
		})
	}

	// Check leave balance
	var balance struct {
		RemainingLeaves int
		TotalLeaves     int
		UsedLeaves      int
	}
	err = config.DB.QueryRow(
		"SELECT remaining_leaves, total_leaves, used_leaves FROM LeaveBalances WHERE user_id = ? AND leave_type = ?",
		userID, leaveType,
	).Scan(&balance.RemainingLeaves, &balance.TotalLeaves, &balance.UsedLeaves)

	if err == sql.ErrNoRows {
		// No balance record exists, create one with default values
		_, err = config.DB.Exec(
			"INSERT INTO LeaveBalances (user_id, leave_type, total_leaves, used_leaves, remaining_leaves) VALUES (?, ?, 0, 0, 0)",
			userID, leaveType,
		)
		if err != nil {
			log.Printf("Error creating leave balance: %v", err)
		}
		balance.RemainingLeaves = 0
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
		})
	}

	// Balance validation removed - all leave/permission requests are allowed regardless of balance

	// Insert leave request
	result, err := config.DB.Exec(
		"INSERT INTO LeaveRequests (user_id, leave_type, from_date, to_date, number_of_days, reason, status) VALUES (?, ?, ?, ?, ?, ?, 'Pending')",
		userID, leaveType, fromDate, toDate, numberOfDays, reason,
	)
	if err != nil {
		log.Printf("Error creating leave request: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to create leave request",
		})
	}

	requestID, _ := result.LastInsertId()

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Leave request created successfully",
		"id":      requestID,
	})
}

// GetLeaveRequests retrieves leave requests
func GetLeaveRequests(c *fiber.Ctx) error {
	// Get user ID from JWT token (the logged-in user making the request)
	requestingUserID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	// Get userId from URL parameter (the user whose requests we want to fetch)
	targetUserIdStr := c.Params("userId")
	if targetUserIdStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "User ID is required",
		})
	}

	// Convert target userId to integer
	targetUserId, err := strconv.Atoi(targetUserIdStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid user ID",
		})
	}

	// Check if requesting user is HR or Admin (similar to GetUserByID pattern)
	var isAdmin bool
	var role string
	err = config.DB.QueryRow("SELECT is_admin, role FROM Login WHERE id = ?", requestingUserID).Scan(&isAdmin, &role)
	if err != nil {
		log.Printf("Error checking user role: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
		})
	}

	isHRAdmin := isAdmin || role == "HR"

	// Determine which user's requests to fetch
	var fetchUserId int
	if isHRAdmin {
		// Admin/HR can fetch requests for the target userId
		fetchUserId = targetUserId
		log.Printf("Admin/HR user %d fetching requests for user %d", requestingUserID, targetUserId)
	} else {
		// Regular users can only fetch their own requests (ignore targetUserId)
		fetchUserId = requestingUserID
		log.Printf("Regular user %d fetching their own requests (ignoring targetUserId %d)", requestingUserID, targetUserId)
	}

	// Build query
	query := `SELECT id, user_id, leave_type, from_date, to_date, 
	          number_of_days, reason, status, remarks, approved_by, 
	          created_at, updated_at
	          FROM LeaveRequests
	          WHERE user_id = ?
	          ORDER BY created_at DESC`

	log.Printf("Query: %s, fetchUserId: %d", query, fetchUserId)
	
	var rows *sql.Rows
	rows, err = config.DB.Query(query, fetchUserId)
	if err != nil {
		log.Printf("Query execution error: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch leave requests",
		})
	}
	defer rows.Close()

	// Initialize as empty slice to ensure JSON returns [] instead of null
	requests := make([]map[string]interface{}, 0)
	
	rowCount := 0
	for rows.Next() {
		rowCount++
		var req struct {
			ID           int
			UserID       int
			LeaveType    string
			FromDate     time.Time
			ToDate       time.Time
			NumberOfDays int
			Reason       string
			Status       string
			Remarks      sql.NullString
			ApprovedBy   sql.NullInt64
			CreatedAt    time.Time
			UpdatedAt    time.Time
		}

		err := rows.Scan(
			&req.ID, &req.UserID, &req.LeaveType, &req.FromDate, &req.ToDate,
			&req.NumberOfDays, &req.Reason, &req.Status, &req.Remarks,
			&req.ApprovedBy, &req.CreatedAt, &req.UpdatedAt,
		)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		// Get user name
		var userName string
		config.DB.QueryRow("SELECT name FROM Login WHERE id = ?", req.UserID).Scan(&userName)

		// Get approver name if exists
		var approverName string
		if req.ApprovedBy.Valid {
			config.DB.QueryRow("SELECT name FROM Login WHERE id = ?", req.ApprovedBy.Int64).Scan(&approverName)
		}

		requestMap := map[string]interface{}{
			"id":             req.ID,
			"user_id":        req.UserID,
			"user_name":      userName,
			"leave_type":     req.LeaveType,
			"from_date":      req.FromDate.Format("2006-01-02"),
			"to_date":        req.ToDate.Format("2006-01-02"),
			"number_of_days": req.NumberOfDays,
			"reason":         req.Reason,
			"status":         req.Status,
			"created_at":     req.CreatedAt.Format(time.RFC3339),
			"updated_at":     req.UpdatedAt.Format(time.RFC3339),
		}

		if req.Remarks.Valid {
			requestMap["remarks"] = req.Remarks.String
		} else {
			requestMap["remarks"] = nil
		}

		if req.ApprovedBy.Valid {
			requestMap["approved_by"] = req.ApprovedBy.Int64
		} else {
			requestMap["approved_by"] = nil
		}

		if approverName != "" {
			requestMap["approver_name"] = approverName
		} else {
			requestMap["approver_name"] = nil
		}

		requests = append(requests, requestMap)
		log.Printf("Processed request ID: %d, User ID: %d, Status: %s", req.ID, req.UserID, req.Status)
	}

	log.Printf("Total rows processed: %d", rowCount)

	// Check for errors from iterating over rows
	if err = rows.Err(); err != nil {
		log.Printf("Error iterating rows: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Error processing leave requests",
		})
	}

	// Ensure we return an empty array, not null
	if requests == nil {
		requests = make([]map[string]interface{}, 0)
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"data":    requests,
		"count":   len(requests),
	})
}

// GetLeaveRequestById retrieves a single leave request by ID
func GetLeaveRequestById(c *fiber.Ctx) error {
	userID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	requestIDStr := c.Params("id")
	if requestIDStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Request ID is required",
		})
	}

	// Convert request ID to integer
	requestID, err := strconv.Atoi(requestIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid request ID",
		})
	}

	var req struct {
		ID           int
		UserID       int
		LeaveType    string
		FromDate     time.Time
		ToDate       time.Time
		NumberOfDays int
		Reason       string
		Status       string
		Remarks      sql.NullString
		ApprovedBy   sql.NullInt64
		CreatedAt    time.Time
		UpdatedAt    time.Time
	}

	// Simplified query without JOINs
	err = config.DB.QueryRow(
		`SELECT id, user_id, leave_type, from_date, to_date, 
		 number_of_days, reason, status, remarks, approved_by, 
		 created_at, updated_at
		 FROM LeaveRequests
		 WHERE id = ?`,
		requestID,
	).Scan(
		&req.ID, &req.UserID, &req.LeaveType, &req.FromDate, &req.ToDate,
		&req.NumberOfDays, &req.Reason, &req.Status, &req.Remarks,
		&req.ApprovedBy, &req.CreatedAt, &req.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "Leave request not found",
		})
	} else if err != nil {
		log.Printf("Error fetching leave request: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
		})
	}

	// Check if user is authorized to view this request
	var isAdmin bool
	var role string
	err = config.DB.QueryRow("SELECT is_admin, role FROM Login WHERE id = ?", userID).Scan(&isAdmin, &role)
	if err != nil {
		log.Printf("Error checking user role: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
		})
	}

	isHRAdmin := isAdmin || role == "HR"
	if !isHRAdmin && req.UserID != userID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthorized to view this request",
		})
	}

	// Get user name
	var userName string
	config.DB.QueryRow("SELECT name FROM Login WHERE id = ?", req.UserID).Scan(&userName)

	// Get approver name if exists
	var approverName string
	if req.ApprovedBy.Valid {
		config.DB.QueryRow("SELECT name FROM Login WHERE id = ?", req.ApprovedBy.Int64).Scan(&approverName)
	}

	requestMap := map[string]interface{}{
		"id":             req.ID,
		"user_id":        req.UserID,
		"user_name":      userName,
		"leave_type":     req.LeaveType,
		"from_date":      req.FromDate.Format("2006-01-02"),
		"to_date":        req.ToDate.Format("2006-01-02"),
		"number_of_days": req.NumberOfDays,
		"reason":         req.Reason,
		"status":         req.Status,
		"created_at":     req.CreatedAt.Format(time.RFC3339),
		"updated_at":     req.UpdatedAt.Format(time.RFC3339),
	}

	if req.Remarks.Valid {
		requestMap["remarks"] = req.Remarks.String
	} else {
		requestMap["remarks"] = nil
	}

	if req.ApprovedBy.Valid {
		requestMap["approved_by"] = req.ApprovedBy.Int64
	} else {
		requestMap["approved_by"] = nil
	}

	if approverName != "" {
		requestMap["approver_name"] = approverName
	} else {
		requestMap["approver_name"] = nil
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   requestMap,
	})
}

// UpdateLeaveStatus updates the status of a leave request (HR only)
func UpdateLeaveStatus(c *fiber.Ctx) error {
	userID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	// Verify user is admin/HR
	isHRAdmin, err := isHROrAdmin(userID)
	if err != nil || !isHRAdmin {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "error",
			"message": "Only HR or Admin can update leave status",
		})
	}

	requestID := c.Params("id")
	if requestID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Request ID is required",
		})
	}

	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid input data",
		})
	}

	status, ok := data["status"].(string)
	if !ok || (status != "Approved" && status != "Rejected") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "status must be 'Approved' or 'Rejected'",
		})
	}

	remarks, _ := data["remarks"].(string)

	// Get the leave request to update balances
	var leaveReq struct {
		UserID       int
		LeaveType    string
		NumberOfDays int
		Status       string
	}

	err = config.DB.QueryRow(
		"SELECT user_id, leave_type, number_of_days, status FROM LeaveRequests WHERE id = ?",
		requestID,
	).Scan(&leaveReq.UserID, &leaveReq.LeaveType, &leaveReq.NumberOfDays, &leaveReq.Status)

	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "Leave request not found",
		})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
		})
	}

	// Update leave request status
	_, err = config.DB.Exec(
		"UPDATE LeaveRequests SET status = ?, remarks = ?, approved_by = ?, updated_at = NOW() WHERE id = ?",
		status, remarks, userID, requestID,
	)
	if err != nil {
		log.Printf("Error updating leave request: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to update leave request",
		})
	}

	// If approved, update leave balances
	if status == "Approved" && leaveReq.Status != "Approved" {
		// Check if balance record exists
		var exists bool
		err = config.DB.QueryRow(
			"SELECT EXISTS(SELECT 1 FROM LeaveBalances WHERE user_id = ? AND leave_type = ?)",
			leaveReq.UserID, leaveReq.LeaveType,
		).Scan(&exists)

		if !exists {
			// Create balance record
			_, err = config.DB.Exec(
				"INSERT INTO LeaveBalances (user_id, leave_type, total_leaves, used_leaves, remaining_leaves) VALUES (?, ?, 0, ?, 0)",
				leaveReq.UserID, leaveReq.LeaveType, leaveReq.NumberOfDays,
			)
		} else {
			// Update balance
			_, err = config.DB.Exec(
				`UPDATE LeaveBalances 
				 SET used_leaves = used_leaves + ?, 
				     remaining_leaves = total_leaves - (used_leaves + ?),
				     updated_at = NOW()
				 WHERE user_id = ? AND leave_type = ?`,
				leaveReq.NumberOfDays, leaveReq.NumberOfDays, leaveReq.UserID, leaveReq.LeaveType,
			)
		}

		if err != nil {
			log.Printf("Error updating leave balance: %v", err)
		}
	}

	// If previously approved but now rejected, reverse the balance
	if status == "Rejected" && leaveReq.Status == "Approved" {
		_, err = config.DB.Exec(
			`UPDATE LeaveBalances 
			 SET used_leaves = used_leaves - ?, 
			     remaining_leaves = remaining_leaves + ?,
			     updated_at = NOW()
			 WHERE user_id = ? AND leave_type = ?`,
			leaveReq.NumberOfDays, leaveReq.NumberOfDays, leaveReq.UserID, leaveReq.LeaveType,
		)
		if err != nil {
			log.Printf("Error reversing leave balance: %v", err)
		}
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Leave request status updated successfully",
	})
}

// GetLeaveBalances retrieves leave balances for the current user
func GetLeaveBalances(c *fiber.Ctx) error {
	userID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	rows, err := config.DB.Query(
		"SELECT leave_type, total_leaves, used_leaves, remaining_leaves FROM LeaveBalances WHERE user_id = ? ORDER BY leave_type",
		userID,
	)
	if err != nil {
		log.Printf("Error fetching leave balances: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch leave balances",
		})
	}
	defer rows.Close()

	var balances []map[string]interface{}
	for rows.Next() {
		var balance struct {
			LeaveType      string
			TotalLeaves    int
			UsedLeaves     int
			RemainingLeaves int
		}

		err := rows.Scan(&balance.LeaveType, &balance.TotalLeaves, &balance.UsedLeaves, &balance.RemainingLeaves)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		balances = append(balances, map[string]interface{}{
			"leave_type":      balance.LeaveType,
			"total_leaves":    balance.TotalLeaves,
			"used_leaves":     balance.UsedLeaves,
			"remaining_leaves": balance.RemainingLeaves,
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   balances,
	})
}

// GetLeaveBalancesByUserId retrieves leave balances for a specific user (HR only)
func GetLeaveBalancesByUserId(c *fiber.Ctx) error {
	userID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	// Verify user is admin/HR
	isHRAdmin, err := isHROrAdmin(userID)
	if err != nil || !isHRAdmin {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "error",
			"message": "Only HR or Admin can view other users' balances",
		})
	}

	targetUserID := c.Params("userId")
	if targetUserID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "User ID is required",
		})
	}

	rows, err := config.DB.Query(
		"SELECT leave_type, total_leaves, used_leaves, remaining_leaves FROM LeaveBalances WHERE user_id = ? ORDER BY leave_type",
		targetUserID,
	)
	if err != nil {
		log.Printf("Error fetching leave balances: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch leave balances",
		})
	}
	defer rows.Close()

	var balances []map[string]interface{}
	for rows.Next() {
		var balance struct {
			LeaveType      string
			TotalLeaves    int
			UsedLeaves     int
			RemainingLeaves int
		}

		err := rows.Scan(&balance.LeaveType, &balance.TotalLeaves, &balance.UsedLeaves, &balance.RemainingLeaves)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		balances = append(balances, map[string]interface{}{
			"leave_type":      balance.LeaveType,
			"total_leaves":    balance.TotalLeaves,
			"used_leaves":     balance.UsedLeaves,
			"remaining_leaves": balance.RemainingLeaves,
		})
	}

	return c.JSON(fiber.Map{
		"status": "success",
		"data":   balances,
	})
}

