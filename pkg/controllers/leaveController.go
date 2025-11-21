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

	if balance.RemainingLeaves < numberOfDays {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Insufficient leave balance. Available: %d, Requested: %d", balance.RemainingLeaves, numberOfDays),
		})
	}

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
	userID, err := getUserIDFromToken(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthenticated",
		})
	}

	// Check if user is admin/HR
	isHRAdmin, err := isHROrAdmin(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
		})
	}

	var rows *sql.Rows
	query := `SELECT lr.id, lr.user_id, lr.leave_type, lr.from_date, lr.to_date, 
	          lr.number_of_days, lr.reason, lr.status, lr.remarks, lr.approved_by, 
	          lr.created_at, lr.updated_at, u.name as user_name, 
	          COALESCE(approver.name, '') as approver_name
	          FROM LeaveRequests lr
	          JOIN Login u ON lr.user_id = u.id
	          LEFT JOIN Login approver ON lr.approved_by = approver.id`

	if isHRAdmin {
		// HR can see all requests with filters
		status := c.Query("status")
		userIdFilter := c.Query("user_id")
		fromDateFilter := c.Query("from_date")
		toDateFilter := c.Query("to_date")

		conditions := []string{}
		args := []interface{}{}

		if status != "" {
			conditions = append(conditions, "lr.status = ?")
			args = append(args, status)
		}
		if userIdFilter != "" {
			conditions = append(conditions, "lr.user_id = ?")
			args = append(args, userIdFilter)
		}
		if fromDateFilter != "" {
			conditions = append(conditions, "lr.from_date >= ?")
			args = append(args, fromDateFilter)
		}
		if toDateFilter != "" {
			conditions = append(conditions, "lr.to_date <= ?")
			args = append(args, toDateFilter)
		}

		if len(conditions) > 0 {
			query += " WHERE " + fmt.Sprintf("%s", conditions[0])
			for i := 1; i < len(conditions); i++ {
				query += " AND " + conditions[i]
			}
		}

		query += " ORDER BY lr.created_at DESC"

		rows, err = config.DB.Query(query, args...)
	} else {
		// Employees see only their own requests
		query += " WHERE lr.user_id = ? ORDER BY lr.created_at DESC"
		rows, err = config.DB.Query(query, userID)
	}

	if err != nil {
		log.Printf("Error fetching leave requests: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to fetch leave requests",
		})
	}
	defer rows.Close()

	var requests []map[string]interface{}
	for rows.Next() {
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
			UserName     string
			ApproverName sql.NullString
		}

		err := rows.Scan(
			&req.ID, &req.UserID, &req.LeaveType, &req.FromDate, &req.ToDate,
			&req.NumberOfDays, &req.Reason, &req.Status, &req.Remarks,
			&req.ApprovedBy, &req.CreatedAt, &req.UpdatedAt, &req.UserName,
			&req.ApproverName,
		)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		requestMap := map[string]interface{}{
			"id":             req.ID,
			"user_id":        req.UserID,
			"user_name":      req.UserName,
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

		if req.ApproverName.Valid {
			requestMap["approver_name"] = req.ApproverName.String
		} else {
			requestMap["approver_name"] = nil
		}

		requests = append(requests, requestMap)
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

	requestID := c.Params("id")
	if requestID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Request ID is required",
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
		UserName     string
		ApproverName sql.NullString
	}

	err = config.DB.QueryRow(
		`SELECT lr.id, lr.user_id, lr.leave_type, lr.from_date, lr.to_date, 
		 lr.number_of_days, lr.reason, lr.status, lr.remarks, lr.approved_by, 
		 lr.created_at, lr.updated_at, u.name as user_name, 
		 COALESCE(approver.name, '') as approver_name
		 FROM LeaveRequests lr
		 JOIN Login u ON lr.user_id = u.id
		 LEFT JOIN Login approver ON lr.approved_by = approver.id
		 WHERE lr.id = ?`,
		requestID,
	).Scan(
		&req.ID, &req.UserID, &req.LeaveType, &req.FromDate, &req.ToDate,
		&req.NumberOfDays, &req.Reason, &req.Status, &req.Remarks,
		&req.ApprovedBy, &req.CreatedAt, &req.UpdatedAt, &req.UserName,
		&req.ApproverName,
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
	isHRAdmin, err := isHROrAdmin(userID)
	if err == nil && !isHRAdmin && req.UserID != userID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"status":  "error",
			"message": "Unauthorized to view this request",
		})
	}

	requestMap := map[string]interface{}{
		"id":             req.ID,
		"user_id":        req.UserID,
		"user_name":      req.UserName,
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

	if req.ApproverName.Valid {
		requestMap["approver_name"] = req.ApproverName.String
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

