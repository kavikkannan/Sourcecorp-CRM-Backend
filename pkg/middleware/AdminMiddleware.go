package AdminMiddlewareAccess

import (
	"database/sql"
	"strconv"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/config"

	"github.com/gofiber/fiber/v2"
	"github.com/dgrijalva/jwt-go"
)

const SecretKey = "secret"


	func AdminMiddleware(c *fiber.Ctx) error {
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
	
	var isAdmin bool
	err = config.DB.QueryRow("SELECT is_admin FROM Login WHERE id = ?", userId).Scan(&isAdmin)
	if err == sql.ErrNoRows {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"message": "User not found"})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"message": "Database error"})
	}

	// Check if the user is an admin
	if !isAdmin {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"message": "Access denied, admin only"})
	}

	// User is authenticated and an admin, proceed to the next handler
	return c.Next()
}
