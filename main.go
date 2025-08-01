package main

import (
	/* "log"
	"net/http" */


	"github.com/gofiber/fiber/v2"
	/* "github.com/rs/cors" */
	"github.com/gofiber/fiber/v2/middleware/cors"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/config"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/routes"
	



	_ "github.com/mattn/go-sqlite3"
)

func main() {

    config.Connect()
	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024, // 50MB limit
	})
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "https://sourcecorp.in", // Use correct frontend IP
		AllowCredentials: true,
		AllowHeaders:     "Content-Type, Authorization",
	}))
	
	routes.Setup(app)

	
	app.Listen(":9999") // Allows access from other devices in the network
}


