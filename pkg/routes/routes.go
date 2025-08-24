package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/controllers"
	AdminMiddleware "github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/middleware"
)

func Setup(app *fiber.App) {
	// --- User CRUD ---
	app.Put("/api/users/:id",AdminMiddleware.AdminMiddleware, controllers.UpdateUser)    // Update user
	app.Delete("/api/users/:id",AdminMiddleware.AdminMiddleware, controllers.DeleteUser) // Delete user

	// --- Case CRUD & Bulk (Admin only) ---
	app.Get("/api/cases", AdminMiddleware.AdminMiddleware, controllers.ListCasesWithFilter) // List/filter cases
	app.Delete("/api/cases/:id", AdminMiddleware.AdminMiddleware, controllers.DeleteCase)   // Delete single case
	app.Delete("/api/cases/bulk", AdminMiddleware.AdminMiddleware, controllers.DeleteCasesBulk) // Bulk delete
	app.Get("/api/cases/report", AdminMiddleware.AdminMiddleware, controllers.DownloadCaseReport) // Download report


	app.Post("/api/register", AdminMiddleware.AdminMiddleware,controllers.Register)
	app.Post("/api/login", controllers.Login)
	app.Get("/api/user", controllers.User)
	app.Get("/api/user/:userId", controllers.GetUserByID)
	app.Post("/api/logout", controllers.Logout)
	app.Post("/api/updateNofiles",controllers.UpdateNoOfFiles)

		// Encrypted PFile

		app.Post("/api/userFile/insert", controllers.SetCase)
		app.Get("/api/userFile/fetch/:pindex", controllers.GetCase)	
		app.Get("/api/userFile/fetchbyid/:userID", controllers.GetCaseById)	
		app.Post("/api/userFile/updateStatus",controllers.UpdateCaseStatus)
		app.Post("/api/userFile/getStatus/:pindex",controllers.GetCaseStatus)
		// Encrypted PFile

	app.Post("/api/pfile/insert", controllers.SetEPFile)
	app.Get("/api/pfile/fetch/:eindex", controllers.GetEPFile)

		// Encrypted Messages
		
		app.Post("/api/insert", controllers.SetEMessage)
		app.Get("/api/fetch/:eindex", controllers.GetEMessage)

		//hadeling notification
		app.Post("/api/insert/notify", controllers.SetNotify)
		app.Get("/api/fetch/notify/:toUser", controllers.GetNotify)
		app.Post("/api/userFile/updateNotifyStatus", controllers.UpdateNotifyStatus)
		app.Get("/api/users/:role", controllers.GetUsersByRole)              // Fetch users by role
		app.Get("/api/lowusers/:role", controllers.GetUsersByRole)              // Fetch users by role

		app.Get("/api/all-users",AdminMiddleware.AdminMiddleware, controllers.GetAllUsers)            // Fetch all users
		app.Post("/api/appoint",AdminMiddleware.AdminMiddleware, controllers.AppointMember) 
		app.Post("/api/removeAppointedMember",AdminMiddleware.AdminMiddleware, controllers.RemoveAppointedMember)           // Assign lower-level workers
		app.Get("/api/appointed/:userId", controllers.GetAppointedMembers) 

		app.Get("/api/schedule/:userId", controllers.GetUserHierarchy) 
		app.Get("/api/appointedUser/:userId", controllers.GetAppointedUser) 

		//doc uplolad gdrive 

		app.Post("/api/uploadDocs",controllers.UploadDocuments)
		app.Get("/api/get-docs/:pindex",controllers.GetCaseFiles)





		// Encrypted PFile

	app.Post("/api/pfile/insert", controllers.SetEPFile1)
	app.Get("/api/pfile/fetch/:eindex", controllers.GetEPFile1)

		// Encrypted Messages
		
	app.Post("/api/insert/k", controllers.SetEMessage1)
	app.Get("/api/fetch/k/:eindex", controllers.GetEMessage1)

	//for logs
	app.Post("/api/logs/pfile/insert", controllers.SetELogPFile)
	app.Get("/api/logs/pfile/fetch/:eindex", controllers.GetELogPFile)

	// Case routes
	caseGroup := app.Group("/case")
	caseGroup.Post("/amount", controllers.AddOrUpdateAmount)
	caseGroup.Get("/amount", controllers.GetAmount)
	caseGroup.Get("/encrypted-data", controllers.GetCasesForDecryption)

	app.Get("/api/fetch_amount", controllers.GetAmount)                 // Requires pindex as a query parameter
	app.Post("/api/process_amounts", controllers.GetCasesForDecryption) // Triggers bulk processing of case amounts
}
