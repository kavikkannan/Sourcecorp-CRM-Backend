package controllers

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/config"
	"golang.org/x/crypto/bcrypt"
)

const SecretKey = "secret"

// UpdateUser updates user details (name, email, role, password, etc.)
func UpdateUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request body"})
	}

	// If password change requested, verify old password or admin key
	if data["Password"] != nil && data["Password"] != "" {
		// AuthMode: "old-password" or "admin-key"
		authMode, _ := data["AuthMode"].(string)
		if authMode == "old-password" {
			var hashedPassword []byte
			err := config.DB.QueryRow("SELECT password FROM Login WHERE id = ?", id).Scan(&hashedPassword)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "User not found"})
			}
			if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(data["OldPassword"].(string))); err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Old password incorrect"})
			}
		} else if authMode == "admin-key" {
			if data["AdminKey"] != "your_admin_key" { // Replace with your admin key logic
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Admin key incorrect"})
			}
		}
		// Hash new password
		password, _ := bcrypt.GenerateFromPassword([]byte(data["Password"].(string)), 14)
		_, err := config.DB.Exec("UPDATE Login SET password = ? WHERE id = ?", password, id)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to update password"})
		}
	}
	// Update other fields
	_, err := config.DB.Exec("UPDATE Login SET name=?, email=?, role=? WHERE id=?",
		data["Name"], data["Email"], data["Role"], id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to update user"})
	}
	return c.JSON(fiber.Map{"message": "User updated successfully"})
}

// DeleteUser removes a user by ID
func DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	_, err := config.DB.Exec("DELETE FROM Login WHERE id = ?", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to delete user"})
	}
	return c.JSON(fiber.Map{"message": "User deleted successfully"})
}

// ListCasesWithFilter returns cases filtered by id, name, or status
func ListCasesWithFilter(c *fiber.Ctx) error {
	q := "SELECT pindex,caseId , Name, status FROM CaseName WHERE 1=1"
	params := []interface{}{}
	if id := c.Query("id"); id != "" {
		q += " AND pindex = ?"
		params = append(params, id)
	}
	if name := c.Query("name"); name != "" {
		q += " AND Name LIKE ?"
		params = append(params, "%"+name+"%")
	}
	if caseid := c.Query("caseid"); caseid != "" {
		q += " AND caseId LIKE ?"
		params = append(params, "%"+caseid+"%")
	}
	if status := c.Query("status"); status != "" {
		q += " AND status = ?"
		params = append(params, status)
	}
	rows, err := config.DB.Query(q, params...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to fetch cases"})
	}
	defer rows.Close()
	var cases []map[string]interface{}
	for rows.Next() {
		var pindex, name, status, caseid string
		if err := rows.Scan(&pindex, &caseid, &name, &status); err != nil {
			continue
		}
		cases = append(cases, map[string]interface{}{"id": pindex, "name": name, "status": status , "caseid": caseid})
	}
	return c.JSON(cases)
}

// DeleteCase deletes a single case by pindex
func DeleteCase(c *fiber.Ctx) error {
	id := c.Params("id")
	_, err := config.DB.Exec("DELETE FROM CaseName WHERE pindex = ?", id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to delete case"})
	}
	return c.JSON(fiber.Map{"message": "Case deleted successfully"})
}

// DeleteCasesBulk deletes multiple cases by pindex array
func DeleteCasesBulk(c *fiber.Ctx) error {
	var body struct { Ids []string `json:"ids"` }
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request body"})
	}
	if len(body.Ids) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "No IDs provided"})
	}
	print(body.Ids)
	q := "DELETE FROM CaseName WHERE pindex IN (" + strings.TrimRight(strings.Repeat("?,", len(body.Ids)), ",") + ")"
	params := make([]interface{}, len(body.Ids))
	for i, v := range body.Ids { params[i] = v }
	_, err := config.DB.Exec(q, params...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to delete cases"})
	}
	return c.JSON(fiber.Map{"message": "Cases deleted successfully"})
}

// DownloadCaseReport returns a CSV or PDF report for selected cases
func DownloadCaseReport(c *fiber.Ctx) error {
	ids := c.Query("ids")
	format := c.Query("format")
	if ids == "" || format == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Missing ids or format"})
	}
	idArr := strings.Split(ids, ",")
	q := "SELECT pindex, Name, status FROM CaseName WHERE pindex IN (" + strings.TrimRight(strings.Repeat("?,", len(idArr)), ",") + ")"
	params := make([]interface{}, len(idArr))
	for i, v := range idArr { params[i] = v }
	rows, err := config.DB.Query(q, params...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to fetch cases"})
	}
	defer rows.Close()
	var csvData strings.Builder
	csvData.WriteString("ID,Name,Status\n")
	for rows.Next() {
		var id, name, status string
		if err := rows.Scan(&id, &name, &status); err != nil { continue }
		csvData.WriteString(id + "," + name + "," + status + "\n")
	}
	if format == "csv" {
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", "attachment; filename=cases.csv")
		return c.SendString(csvData.String())
	} else if format == "pdf" {
		// For demo: just send CSV as PDF (real PDF: use a PDF lib)
		c.Set("Content-Type", "application/pdf")
		c.Set("Content-Disposition", "attachment; filename=cases.pdf")
		return c.SendString(csvData.String())
	}
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid format"})
}

// Register function
func Register(c *fiber.Ctx) error {
    var data map[string]interface{} 

    if err := c.BodyParser(&data); err != nil {
        return err
    }

    // Validate and hash password
    passwordStr, ok := data["password"].(string)
    if !ok || passwordStr == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Password is required"})
    }
    password, _ := bcrypt.GenerateFromPassword([]byte(passwordStr), 14)

    // Convert is_admin
    isAdmin := false
    if val, ok := data["is_admin"].(bool); ok {
        isAdmin = val
    } else if val, ok := data["is_admin"].(string); ok && val == "true" {
        isAdmin = true
    }

    // Convert no_of_files
    noOfFiles := 0
    switch v := data["no_of_files"].(type) {
    case string:
        noOfFiles, _ = strconv.Atoi(v)
    case float64:
        noOfFiles = int(v)
    }

    // Validate role
    role, ok := data["role"].(string)
    if !ok || role == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Role is required"})
    }

	    // Validate role
    branch, ok := data["branch"].(string)
    if !ok || branch == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Branch is required"})
    }


    // Store appointed_members as an empty string ("")
    appointedMembersStr := ""

	reportto :=1
    
    // Execute SQL Insert
    _, err := config.DB.Exec(
        "INSERT INTO Login (name, email, password, number, is_admin, no_of_files, branch, role, salary, appointed_members, reportTo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        data["name"], data["email"], password, data["number"], isAdmin, noOfFiles, branch, role, data["salary"], appointedMembersStr,reportto )

    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register user", "error": err.Error()})
    }

    return c.JSON(fiber.Map{"message": "User registered successfully"})
}

// Login an existing user
func Login(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid input data",
		})
	}

	var id int
	var hashedPassword []byte
	var isAdmin bool
	var number string

	// Query to retrieve user information
	err := config.DB.QueryRow("SELECT id, password, number, is_admin FROM Login WHERE email = ?", data["email"]).Scan(&id, &hashedPassword, &number, &isAdmin)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "error",
			"message": "User not found",
			"code":    "USER_NOT_FOUND",
		})
	} else if err != nil {
		fmt.Println("Database error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Database error",
			"code":    "DB_ERROR",
		})
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword(hashedPassword, []byte(data["password"])); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Incorrect password",
			"code":    "INVALID_PASSWORD",
		})
	}

	// Create JWT claims
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"Issuer":  strconv.Itoa(id),
		"Expires": time.Now().Add(time.Hour * 24).Unix(),
		"IsAdmin": isAdmin,
	})
	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		fmt.Println("JWT signing error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Could not login",
			"code":    "JWT_ERROR",
		})
	}

	// Set cookie
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    token,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
		SameSite: "Lax",
	}
	if c.Protocol() == "https" {
		cookie.Secure = true
	}
	c.Cookie(&cookie)

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Login successful",
		"code":    "LOGIN_SUCCESS",
		"user": fiber.Map{
			"id":      id,
			"email":   data["email"],
			"number":  number,
			"isAdmin": isAdmin,
		},
	})
}



// Get User details based on JWT
func User(c *fiber.Ctx) error {
    cookie := c.Cookies("jwt")
	
    token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte(SecretKey), nil
    })
    if err != nil {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "Unauthenticated"})
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok || claims["Issuer"] == nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid claims in token"})
    }

    userId, err := strconv.Atoi(claims["Issuer"].(string))
    if err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid user ID in token"})
    }

    var user struct {
		ID    int
		Name  string
		Email string
		Number string
		IsAdmin bool
		PPass string
		NoOfFiles int
		Role string
	}

    err = config.DB.QueryRow("SELECT id, name, email, number, is_admin, password ,no_of_files ,role FROM Login WHERE id = ?", userId).Scan(&user.ID, &user.Name, &user.Email, &user.Number, &user.IsAdmin, &user.PPass, &user.NoOfFiles, &user.Role)
    if err == sql.ErrNoRows {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
    } else if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
    }

    return c.JSON(user)
}

func GetUserByID(c *fiber.Ctx) error {
	userID := c.Params("userId")
	var user struct {
		ID    int
		Name  string
		Email string
		Number string
		IsAdmin bool
		PPass string
		NoOfFiles int
		Role string
	}

	err := config.DB.QueryRow("SELECT id, name, email, number, is_admin, password ,no_of_files ,role FROM Login WHERE id = ?", userID).
		Scan(&user.ID, &user.Name, &user.Email, &user.Number, &user.IsAdmin, &user.PPass, &user.NoOfFiles, &user.Role)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(user)
}
func GetAppointedMembers(c *fiber.Ctx) error {
	userID := c.Params("userId")

	var appointedMembersJSON []byte
	err := config.DB.QueryRow("SELECT appointed_members FROM Login WHERE id = ?", userID).Scan(&appointedMembersJSON)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	var appointedMembers []int
	if appointedMembersJSON != nil {
		json.Unmarshal(appointedMembersJSON, &appointedMembers)
	}

	return c.JSON(fiber.Map{"appointed_members": appointedMembers})
}
type AppointRequest struct {
	UserID          int 
	AppointedUserID int 
}
func AppointMember(c *fiber.Ctx) error {
	var data map[string]string

	if err := c.BodyParser(&data); err != nil {
		log.Println("Error parsing request body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request format"})
	}

	// Extract  from the map
	userID, userIDErr := strconv.Atoi(data["UserID"])
	appointedMembersStr := data["AppointedMembers"] // Expecting a comma-separated string

	if userIDErr != nil || appointedMembersStr == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid UserID or AppointedMembers format"})
	}

	// Convert the appointed members string into a slice of integers
	appointedMembersIDs := strings.Split(appointedMembersStr, ",")
	var appointedMembers []string

	for _, idStr := range appointedMembersIDs {
		id, err := strconv.Atoi(strings.TrimSpace(idStr))
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid AppointedMembers format"})
		}
		appointedMembers = append(appointedMembers, strconv.Itoa(id))
	}

	// Get current appointed members from the database
	var currentAppointedMembers string
	err := config.DB.QueryRow("SELECT appointed_members FROM Login WHERE id = ?", userID).Scan(&currentAppointedMembers)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
	} else if err != nil {
		log.Println("Database error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	// Convert the comma-separated string to a slice
	var existingAppointedMembers []string
	if currentAppointedMembers != "" {
		existingAppointedMembers = strings.Split(currentAppointedMembers, ",")
	}

	// Merge new appointed members while avoiding duplicates
	appointedSet := make(map[string]bool)
	for _, id := range existingAppointedMembers {
		appointedSet[id] = true
	}
	for _, id := range appointedMembers {
		if !appointedSet[id] {
			existingAppointedMembers = append(existingAppointedMembers, id)
			appointedSet[id] = true
		}
	}

	// Convert back to a comma-separated string
	updatedAppointedMembers := strings.Join(existingAppointedMembers, ",")

	// Update database: set appointed_members for userID
	_, err = config.DB.Exec("UPDATE Login SET appointed_members = ? WHERE id = ?", updatedAppointedMembers, userID)
	if err != nil {
		log.Println("Error updating database:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error updating appointed members"})
	}

	// Update reportTo for each appointed user
	for _, appointedUserID := range appointedMembers {
		_, err := config.DB.Exec("UPDATE Login SET reportTo = ? WHERE id = ?", userID, appointedUserID)
		if err != nil {
			log.Println("Error updating reportTo for user", appointedUserID, ":", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error updating reportTo for appointed members"})
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Members appointed successfully"})
}
func RemoveAppointedMember(c *fiber.Ctx) error {
    var data map[string]string

    if err := c.BodyParser(&data); err != nil {
        log.Println("Error parsing request body:", err)
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request format"})
    }

    userID, userIDErr := strconv.Atoi(data["UserID"])
    memberID, memberIDErr := strconv.Atoi(data["MemberID"])

    if userIDErr != nil || memberIDErr != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid UserID or MemberID format"})
    }

    // Get current appointed members from the database
    var currentAppointedMembers string
    err := config.DB.QueryRow("SELECT appointed_members FROM Login WHERE id = ?", userID).Scan(&currentAppointedMembers)
    if err == sql.ErrNoRows {
        return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
    } else if err != nil {
        log.Println("Database error:", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
    }

    // Remove the memberID from the appointed members list
    var updatedMembers []string
    for _, id := range strings.Split(currentAppointedMembers, ",") {
        id = strings.TrimSpace(id)
        if id != "" && id != strconv.Itoa(memberID) {
            updatedMembers = append(updatedMembers, id)
        }
    }
    updatedMembersStr := strings.Join(updatedMembers, ",")

    // Update database: set appointed_members for userID
    _, err = config.DB.Exec("UPDATE Login SET appointed_members = ? WHERE id = ?", updatedMembersStr, userID)
    if err != nil {
        log.Println("Error updating appointed_members:", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error updating appointed members"})
    }

    // Set reportTo of the removed member to NULL (or 0 if you prefer)
    _, err = config.DB.Exec("UPDATE Login SET reportTo = NULL WHERE id = ?", memberID)
    if err != nil {
        log.Println("Error updating reportTo for user", memberID, ":", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error updating reportTo for removed member"})
    }

    return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Appointed member removed successfully"})
}
/* 
func GetUserHierarchy(c *fiber.Ctx) error {
	userID := c.Params("userId")
	var hierarchy string
	var reportTo int

	for {
		var appointedMembers string
		err := config.DB.QueryRow("SELECT appointed_members, reportTo FROM Login WHERE id = ?", userID).Scan(&appointedMembers, &reportTo)
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
		} else if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
		}

		// Append data to hierarchy string
		if hierarchy == "" {
			hierarchy = appointedMembers
		} else {
			hierarchy += "," + appointedMembers
		}

		// Append reportTo
		hierarchy += "," + strconv.Itoa(reportTo)

		// Stop if reportTo is 0
		if reportTo == 1 {
			break
		}

		// Update userID for next iteration
		userID = strconv.Itoa(reportTo)
	}

	return c.JSON(fiber.Map{"hierarchy": hierarchy})
}

 */
 func GetUserHierarchy(c *fiber.Ctx) error {
    userID := c.Params("userId")
    var hierarchy string
    var reportTo sql.NullInt64  // Use sql.NullInt64 to handle NULL values
    visited := make(map[string]bool) // Track visited users to prevent loops

    // Call GetAppointedUser to get appointed user IDs
    hierarchySet := make(map[string]bool)
    getAppointedMembers(config.DB, userID, hierarchySet, make(map[string]bool)) // Pass visited map

    // Convert map to a comma-separated string
    var hierarchyList []string
    for member := range hierarchySet {
        hierarchyList = append(hierarchyList, member)
    }
    hierarchy = strings.Join(hierarchyList, ",")

    // Now, find the reportTo hierarchy
    currentUserID := userID
    for {
        // Check for infinite loop
        if visited[currentUserID] {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "message": "Circular reference detected in user hierarchy",
            })
        }
        visited[currentUserID] = true

        // Query with proper NULL handling
        err := config.DB.QueryRow("SELECT reportTo FROM Login WHERE id = ?", currentUserID).Scan(&reportTo)
        if err == sql.ErrNoRows {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
        } else if err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                "message": "Database error",
                "error":   err.Error(), // Include error details for debugging
            })
        }

        // Check if reportTo is NULL
        if !reportTo.Valid {
            break
        }

        // Append reportTo to the hierarchy if not already present
        reportToStr := strconv.FormatInt(reportTo.Int64, 10)
        if !hierarchySet[reportToStr] {
            if hierarchy != "" {
                hierarchy += ","
            }
            hierarchy += reportToStr
        }

        // Stop if we've reached the top of the hierarchy
        if reportTo.Int64 == 1 {
            break
        }

        // Update currentUserID for next iteration
        currentUserID = reportToStr
    }

    // Return the combined hierarchy
    return c.JSON(fiber.Map{"hierarchy": hierarchy})
}

func getAppointedMembers(db *sql.DB, userID string, hierarchySet map[string]bool, visited map[string]bool) {
    if visited[userID] {
        return // Prevent infinite recursion
    }
    visited[userID] = true

    var appointedMembers string
    err := db.QueryRow("SELECT appointed_members FROM Login WHERE id = ?", userID).Scan(&appointedMembers)

    if err != nil {
        return // Stop if user not found or error occurs
    }

    // Split appointed members (assuming they are stored as comma-separated values)
    members := strings.Split(appointedMembers, ",")

    for _, member := range members {
        member = strings.TrimSpace(member)
        if member != "" && !hierarchySet[member] {
            hierarchySet[member] = true
            getAppointedMembers(db, member, hierarchySet, visited) // Pass visited map
        }
    }
}

// Handler function
func GetAppointedUser(c *fiber.Ctx) error {
    userID := c.Params("userId")
    if userID == "" {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "message": "User ID is required",
        })
    }

    // Initialize the hierarchy set and visited map
    hierarchySet := make(map[string]bool)
    visited := make(map[string]bool)

    // Start recursion with the visited map
    getAppointedMembers(config.DB, userID, hierarchySet, visited)

    // Convert map keys to a sorted slice for consistent output
    hierarchyList := make([]string, 0, len(hierarchySet))
    for member := range hierarchySet {
        hierarchyList = append(hierarchyList, member)
    }

    // Sort the hierarchy list for consistent output
    sort.Strings(hierarchyList)

    return c.JSON(fiber.Map{
        "hierarchy": strings.Join(hierarchyList, ","),
        "count":     len(hierarchyList),
    })
}


func GetLowerHierarchyUsers(c *fiber.Ctx) error {
	// Define role hierarchy
	roleHierarchy := map[string]int{
		"operation_head": 6,
		"backend_team": 5,
		"management_team": 4,
		"branch_manager": 3,
		"team_leader": 2,
		"executive": 1,
	}

	// Get user ID from query params
	userID := c.Query("userID")
	if userID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "UserID is required"})
	}

	// Get current user role
	var userRole string
	err := config.DB.QueryRow("SELECT role FROM Login WHERE id = ?", userID).Scan(&userRole)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
		}
		log.Println("Database error:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	// Get lower hierarchy users
	rows, err := config.DB.Query("SELECT id, name, role FROM Login")
	if err != nil {
		log.Println("Error fetching users:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error fetching users"})
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var id int
		var name, role string
		if err := rows.Scan(&id, &name, &role); err != nil {
			log.Println("Error scanning user:", err)
			continue
		}

		// Add only users with lower hierarchy
		if roleHierarchy[role] < roleHierarchy[userRole] {
			users = append(users, map[string]interface{}{
				"id":   id,
				"name": name,
				"role": role,
			})
		}
	}

	return c.Status(fiber.StatusOK).JSON(users)
}

func GetAllUsers(c *fiber.Ctx) error {
	rows, err := config.DB.Query("SELECT id, name, role, branch, email, number, salary, is_admin FROM Login")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error fetching users"})
	}
	defer rows.Close()

	var users []struct {
		ID   int    
		Name string
		Role string 
		Branch string 
		Email string 
		Number string 
		Salary string 
		IsAdmin bool 
	}

	for rows.Next() {
		var user struct {
			ID   int
			Name string
			Role string
			Branch string 
			Email string 
			Number string 
			Salary string 
			IsAdmin bool 
		}
		if err := rows.Scan(&user.ID, &user.Name, &user.Role, &user.Branch, &user.Email, &user.Number, &user.Salary, &user.IsAdmin); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error scanning users"})
		}
		users = append(users, user)
	}

	return c.JSON(users)
}
func GetUsersByRole(c *fiber.Ctx) error {
	role := c.Params("role")
	if role == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Role parameter is required"})
	}

	rows, err := config.DB.Query("SELECT id, name, role, appointed_members FROM Login WHERE role = ?", role)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error fetching users"})
	}
	defer rows.Close()

	var users []struct {
		ID               int      
		Name             string   
		Role             string   
		AppointedMembers string 
	}

	for rows.Next() {
		var user struct {
			ID               int
			Name             string
			Role             string
			AppointedMembers string // JSON field
		}

		if err := rows.Scan(&user.ID, &user.Name, &user.Role, &user.AppointedMembers); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error scanning users"})
		}

		

		users = append(users, user)
	}

	return c.JSON(users)
}

func UpdateNoOfFiles(c *fiber.Ctx) error {
	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	userID, ok := data["id"].(float64) 
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid or missing user ID"})
	}

	noOfFiles, ok := data["no_of_files"].(float64)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid or missing no_of_files"})
	}

	_, err := config.DB.Exec("UPDATE Login SET no_of_files = ? WHERE id = ?", int(noOfFiles), int(userID))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to update no_of_files"})
	}

	return c.JSON(fiber.Map{"message": "no_of_files updated successfully"})
}
func UpdateCaseStatus(c *fiber.Ctx) error {
	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	_, err := config.DB.Exec("UPDATE CaseName SET status = ? WHERE pindex= ?", data["status"], data["pindex"])
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to update no_of_files"})
	}

	return c.JSON(fiber.Map{"message": "status updated successfully"})
}

func GetCaseStatus(c *fiber.Ctx) error {
    var status string
    err := config.DB.QueryRow("SELECT status FROM CaseName WHERE pindex = ?", c.Params("pindex")).Scan(&status)
    
    if err != nil {
        if err == sql.ErrNoRows {
            return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "pindex not found"})
        }
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
    }

    return c.JSON(fiber.Map{"status": status})
}

// Logout by clearing JWT cookie
func Logout(c *fiber.Ctx) error {
	cookie := fiber.Cookie{
		Name:     "jwt",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		SameSite: "None",
	}
	c.Cookie(&cookie)
	return c.JSON(fiber.Map{"message": "Logged out successfully"})
}

/* 
func SetEMessage(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	_, err := config.DB.Exec("INSERT INTO Case (pindex, kfile, caseName, status, agentId) VALUES (?, ?, ?, ?, ?)", data["pindex"], data["kfile"], data["caseName"], data["status"], data["agentId"])
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register Encrypted Data"})
	}

	return c.JSON(fiber.Map{"message": "Eindex,Emessage registered successfully"})
}


// Fetch a product by ID
func GetEMessage(c *fiber.Ctx) error {
	index := c.Params("eindex")
	var Case struct {
		ID       int
		PIndex     string
		KFile string
		CaseName string
		Status string
		AgentId string
	}
	err := config.DB.QueryRow("SELECT id, pindex, kfile, caseName, status, agentId FROM Case WHERE eindex = ?", index).Scan(&Case.ID, &Case.PIndex, &Case.KFile, &Case.CaseName,&Case.Status,&Case.AgentId)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(Case)
}
 */


// SetCase inserts a new record into the CaseName table and updates the amount
func SetCase(c *fiber.Ctx) error {
	// Define a map to hold the incoming JSON data
	var data map[string]string

	// Parse the request body into the map
	if err := c.BodyParser(&data); err != nil {
		log.Println("Error parsing request body:", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request format"})
	}

	// Start a transaction
	tx, err := config.DB.Begin()
	if err != nil {
		log.Println("Error starting transaction:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to start transaction"})
	}

	// Insert into CaseName table
	query := `
		INSERT INTO CaseName (pindex, Pfile, PIV, Name, status, agentId, coustomerDetails, unknown1, caseDate, caseId) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.Exec(query, 
		data["pindex"], 
		data["Pfile"], 
		data["piv"], 
		data["caseName"], 
		data["status"], 
		data["agentId"], 
		data["coustomerDetails"],
		data["unknown1"],
		data["caseDate"],
		data["caseId"],
	)

	if err != nil {
		tx.Rollback()
		log.Println("Database error inserting into CaseName:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register case data"})
	}

	// If amount is provided, update the CaseAmount table
	if amount, ok := data["amount"]; ok && amount != "" {
		amountFloat, err := strconv.ParseFloat(amount, 64)
		if err != nil {
			tx.Rollback()
			log.Println("Error parsing amount:", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid amount format"})
		}

		_, err = tx.Exec(`
			INSERT INTO CaseAmount (pindex, caseId, amount)
			VALUES (?, ?, ?)
			ON DUPLICATE KEY UPDATE amount = ?`,
			data["pindex"],
			data["caseId"],
			amountFloat,
			amountFloat,
		)

		if err != nil {
			tx.Rollback()
			log.Println("Error updating CaseAmount:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to update case amount"})
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		log.Println("Error committing transaction:", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to commit transaction"})
	}

	return c.JSON(fiber.Map{"message": "Data inserted successfully"})
}


func GetCase(c *fiber.Ctx) error {
	index := c.Params("pindex")
	var Case struct {

		PIndex     string
		PFile string
		PIV string
		Name string
		Status string
		AgentId string
		CoustomerDetails string
		Unknown1 string
		CaseDate string
		CaseId string
	}
	err := config.DB.QueryRow("SELECT  pindex, Pfile, PIV, Name, status, agentId, coustomerDetails, unknown1, caseDate, caseId FROM CaseName WHERE pindex = ?", index).Scan( &Case.PIndex, &Case.PFile,&Case.PIV, &Case.Name,&Case.Status,&Case.AgentId,&Case.CoustomerDetails,&Case.Unknown1, &Case.CaseDate, &Case.CaseId)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(Case)
}


func GetCaseById(c *fiber.Ctx) error {
	index := c.Params("userID")
	rows, err := config.DB.Query("SELECT pindex, Pfile, PIV, Name, status, agentId, coustomerDetails, unknown1, caseDate, caseId FROM CaseName WHERE agentId = ?", index)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}
	defer rows.Close()

	var Cases []struct {
		PIndex     string
		PFile string
		PIV string
		Name string
		Status string
		AgentId string
		CoustomerDetails string
		Unknown1 string
		CaseDate string
		CaseId string
	}

	for rows.Next() {
		var Case struct {
		PIndex     string
		PFile string
		PIV string
		Name string
		Status string
		AgentId string
		CoustomerDetails string
		Unknown1 string
		CaseDate string
		CaseId string

	}
		if err := rows.Scan( &Case.PIndex, &Case.PFile, &Case.PIV, &Case.Name, &Case.Status, &Case.AgentId, &Case.CoustomerDetails, &Case.Unknown1,&Case.CaseDate,&Case.CaseId); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to scan notifications"})
		}
		Cases = append(Cases, Case)
	}

	return c.JSON(Cases)
}




func SetEMessage(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	_, err := config.DB.Exec("INSERT INTO CaseDocs (eindex, emessage, iv) VALUES (?, ?, ?)", data["eindex"], data["emessage"], data["iv"])
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register Encrypted Data"})
	}

	return c.JSON(fiber.Map{"message": "Eindex,Emessage registered successfully"})
}




// Fetch a product by ID
func GetEMessage(c *fiber.Ctx) error {
	index := c.Params("toUser")
	var CaseDocs struct {
		ID       int
		EIndex     string
		EMessage string
		IV string
	}
	err := config.DB.QueryRow("SELECT id, eindex, emessage, iv FROM CaseDocs WHERE eindex = ?", index).Scan(&CaseDocs.ID, &CaseDocs.EIndex, &CaseDocs.EMessage, &CaseDocs.IV)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(CaseDocs)
}
func SetNotify(c *fiber.Ctx) error {
	var data map[string]interface{}

	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request body"})
	}

	// Convert fromUser and toUser from string to int
	touserStr, ok := data["toUser"].(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid or missing toUser"})
	}
	touser, err := strconv.Atoi(touserStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid or missing toUser"})
	}

	fromuserStr, ok := data["fromUser"].(string)
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid or missing fromUser"})
	}
	fromuser, err := strconv.Atoi(fromuserStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid or missing fromUser"})
	}

	// Safely parse boolean values
	isMark := false
	if val, ok := data["mark"].(bool); ok {
		isMark = val
	} else if val, ok := data["mark"].(string); ok && val == "true" {
		isMark = true
	}

	isRead := false
	if val, ok := data["readStatus"].(bool); ok {
		isRead = val
	} else if val, ok := data["readStatus"].(string); ok && val == "true" {
		isRead = true
	}

	// Insert into database
	_, err = config.DB.Exec(`
		INSERT INTO Notification (fromUser, toUser, tousername, note, casePfile, mark, readStatus) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		fromuser, touser, data["tousername"], data["note"], data["casePfile"], isMark, isRead,
	)

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register notification"})
	}

	return c.JSON(fiber.Map{"message": "Notification registered successfully"})
}


func GetNotify(c *fiber.Ctx) error {
	toUser := c.Params("toUser")
	rows, err := config.DB.Query(`
		SELECT id, fromUser, toUser, tousername, note, casePfile, mark, readStatus 
		FROM Notification 
		WHERE toUser = ?`, toUser,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}
	defer rows.Close()

	var notifications []struct {
		ID       int    
		FromUser int    
		ToUser   int 
		Tousername string 
		Note string  
		PIndex string 
		Mark     bool
		ReadStatus bool 
	}

	for rows.Next() {
		var notification struct {
			ID       int    
			FromUser int    
			ToUser   int 
			Tousername string 
			Note string  
			PIndex string 
			Mark     bool
		ReadStatus bool  
		}
		if err := rows.Scan(&notification.ID, &notification.FromUser, &notification.ToUser, &notification.Tousername, &notification.Note, &notification.PIndex, &notification.Mark, &notification.ReadStatus); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to scan notifications"})
		}
		notifications = append(notifications, notification)
	}

	if len(notifications) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "No notifications found"})
	}

	return c.JSON(notifications)
}
func UpdateNotifyStatus(c *fiber.Ctx) error {
	var data map[string]interface{}
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request body"})
	}

	// Get and validate ID from body
	idVal, okID := data["id"]
	mark, okMark := data["mark"]
	readStatus, okRead := data["readStatus"]

	if !okID || !okMark || !okRead {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Missing id, mark, or readStatus"})
	}

	id := fmt.Sprintf("%v", idVal) // Convert to string

	// Convert mark to bool
	isMark := false
	if val, ok := mark.(bool); ok {
		isMark = val
	} else if val, ok := mark.(string); ok && val == "true" {
		isMark = true
	}

	// Convert readStatus to bool
	isRead := false
	if val, ok := readStatus.(bool); ok {
		isRead = val
	} else if val, ok := readStatus.(string); ok && val == "true" {
		isRead = true
	}

	// Perform the update
	_, err := config.DB.Exec("UPDATE Notification SET mark = ?, readStatus = ? WHERE id = ?", isMark, isRead, id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to update notification status",
		})
	}

	return c.JSON(fiber.Map{"message": "Notification status updated successfully"})
}



func SetEPFile(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	_, err := config.DB.Exec("INSERT INTO EncryptedPFile (eindex, pfile, pfileiv) VALUES (?, ?, ?)", data["eindex"], data["pfile"], data["pfileiv"])
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register Encrypted Data"})
	}

	return c.JSON(fiber.Map{"message": "Eindex,Emessage registered successfully"})
}

func GetEPFile(c *fiber.Ctx) error {
	index := c.Params("eindex")
	var EncryptedPFile struct {
		ID       int
		EIndex     string
		PFile string
		PFileIv string
	}
	err := config.DB.QueryRow("SELECT id, eindex, pfile, pfileiv FROM EncryptedPFile WHERE eindex = ?", index).Scan(&EncryptedPFile.ID, &EncryptedPFile.EIndex, &EncryptedPFile.PFile, &EncryptedPFile.PFileIv)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(EncryptedPFile)
}


func UploadDocuments(c *fiber.Ctx) error {
	pindex := c.FormValue("pindex")
	caseName := c.FormValue("casename")

	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid form data"})
	}
	files := form.File["files"]

	// Start transaction
	tx, err := config.DB.Begin()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to start transaction"})
	}

	stmt, err := tx.Prepare("INSERT INTO CaseFiles (pindex, case_name, file_name, file_content) VALUES (?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to prepare statement"})
	}
	defer stmt.Close()

	for _, file := range files {
		// Open file
		src, err := file.Open()
		if err != nil {
			tx.Rollback()
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to read file"})
		}
		defer src.Close()

		// Read file content into buffer
		var buf bytes.Buffer
		_, err = io.Copy(&buf, src)
		if err != nil {
			tx.Rollback()
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to process file"})
		}

		// Insert binary data into database
		_, err = stmt.Exec(pindex, caseName, file.Filename, buf.Bytes())
		if err != nil {
			tx.Rollback()
			log.Println("DB Insert Error:", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to insert file into database"})
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Transaction commit failed"})
	}

	return c.JSON(fiber.Map{"message": "Files uploaded successfully!"})
}

func GetCaseFiles(c *fiber.Ctx) error {
    pindex := c.Params("pindex")

    rows, err := config.DB.Query("SELECT id, file_name, file_content FROM CaseFiles WHERE pindex = ?", pindex)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
    }
    defer rows.Close()

    var files []map[string]interface{}

    for rows.Next() {
        var id int
        var fileName string
        var fileContent []byte

        if err := rows.Scan(&id, &fileName, &fileContent); err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Error reading files"})
        }

        // Encode file content as Base64 (to safely send binary data over JSON)
        encodedContent := base64.StdEncoding.EncodeToString(fileContent)

        files = append(files, map[string]interface{}{
            "id":          id,
            "file_name":   fileName,
            "file_content": encodedContent,
        })
    }

    return c.JSON(files)
}


func SetEPFile1(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return err
	}

	_, err := config.DB.Exec("INSERT INTO EncryptedPFile (eindex, pfile, pfileiv) VALUES (?, ?, ?)", data["eindex"], data["pfile"], data["pfileiv"])
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register Encrypted Data"})
	}

	return c.JSON(fiber.Map{"message": "Eindex,Emessage registered successfully"})
}
func SetELogPFile(c *fiber.Ctx) error {
    var data map[string]string
    if err := c.BodyParser(&data); err != nil {
        return err
    }

    // Get current version
    var currentVersion int
    err := config.DB.QueryRow("SELECT version FROM EncryptedLogPFile WHERE eindex = ?", data["eindex"]).Scan(&currentVersion)
    if err == sql.ErrNoRows {
        // If no existing entry, insert a new one with version 1
        _, err := config.DB.Exec(`
            INSERT INTO EncryptedLogPFile (eindex, pfile, pfileiv, version)
            VALUES (?, ?, ?, 1)`, data["eindex"], data["pfile"], data["pfileiv"])
        if err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to insert Encrypted Data"})
        }
    } else if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
    } else {
        // Update only if version matches
        result, err := config.DB.Exec(`
            UPDATE EncryptedLogPFile
            SET pfile = ?, pfileiv = ?, version = version + 1
            WHERE eindex = ? AND version = ?`,
            data["pfile"], data["pfileiv"], data["eindex"], currentVersion)
        
        rowsAffected, _ := result.RowsAffected()
        if rowsAffected == 0 {
            return c.Status(fiber.StatusConflict).JSON(fiber.Map{"message": "Conflict: Someone else updated the data."})
        }

        if err != nil {
            return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to update Encrypted Data"})
        }
    }

    return c.JSON(fiber.Map{"message": "Eindex, Pfile registered/updated successfully"})
}



func GetEPFile1(c *fiber.Ctx) error {
	index := c.Params("eindex")
	var EncryptedPFile struct {
		EIndex     string
		PFile string
		PFileIv string
	}
	err := config.DB.QueryRow("SELECT  eindex, pfile, pfileiv FROM EncryptedPFile WHERE eindex = ?", index).Scan( &EncryptedPFile.EIndex, &EncryptedPFile.PFile, &EncryptedPFile.PFileIv)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(EncryptedPFile)
}

func GetELogPFile(c *fiber.Ctx) error {
	index := c.Params("eindex")
	var EncryptedPFile struct {
		EIndex     string
		PFile string
		PFileIv string
	}
	err := config.DB.QueryRow("SELECT  eindex, pfile, pfileiv FROM EncryptedLogPFile WHERE eindex = ?", index).Scan( &EncryptedPFile.EIndex, &EncryptedPFile.PFile, &EncryptedPFile.PFileIv)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(EncryptedPFile)
}
func SetEMessage1(c *fiber.Ctx) error {
	var data map[string]string
	if err := c.BodyParser(&data); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request body", "error": err.Error()})
	}

	_, err := config.DB.Exec("INSERT INTO EncryptedMessages (eindex, emessage, iv) VALUES (?, ?, ?)", data["eindex"], data["emessage"], data["iv"])
	if err != nil {
		log.Println("DB Insert Error:", err) // ✅ Print the exact DB error
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Failed to register Encrypted Data", "error": err.Error()})
	}

	return c.JSON(fiber.Map{"message": "Eindex,Emessage registered successfully"})
}



// Fetch a product by ID
func GetEMessage1(c *fiber.Ctx) error {
	index := c.Params("eindex")
	var EncryptedMessages struct {
		EIndex     string
		EMessage string
		IV string
	}
	err := config.DB.QueryRow("SELECT  eindex, emessage, iv FROM EncryptedMessages WHERE eindex = ?", index).Scan( &EncryptedMessages.EIndex, &EncryptedMessages.EMessage, &EncryptedMessages.IV)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "Eindex not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	return c.JSON(EncryptedMessages)
}

