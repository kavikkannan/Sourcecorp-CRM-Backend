package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kavikkannan/go-ecommerce-grocery-delivery-service/pkg/controllers"
)

func Setup(app *fiber.App) {

	app.Post("/api/register", controllers.Register)
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

		app.Get("/api/all-users", controllers.GetAllUsers)            // Fetch all users
		app.Post("/api/appoint", controllers.AppointMember)           // Assign lower-level workers
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
 
	}
	

