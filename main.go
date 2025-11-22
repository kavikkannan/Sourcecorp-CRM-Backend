package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/config"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/routes"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// Configure log output with timestamps and file info
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.SetOutput(os.Stdout)
	log.Printf("========== Application starting at %s ==========", time.Now().Format("2006-01-02 15:04:05"))

	config.Connect()
	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024, // 50MB limit
	})

	// Request logging middleware
	app.Use(func(c *fiber.Ctx) error {
		log.Printf("[HTTP] %s %s from %s", c.Method(), c.Path(), c.IP())
		return c.Next()
	})

	app.Use(cors.New(cors.Config{
		AllowOrigins:     "https://vfinserv.in", // Use correct frontend IP
		AllowCredentials: true,
		AllowHeaders:     "Content-Type, Authorization",
	}))

	routes.Setup(app)

	app.Listen(":9999") // Allows access from other devices in the network
}
