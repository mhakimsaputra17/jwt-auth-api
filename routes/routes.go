package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/mhakimsaputra17/jwt-auth-api/controllers"
)

func RegisterRoutes(router *gin.Engine) {
	api := router.Group("/api")

	// Auth routes
	auth := api.Group("/auth")
	{
		auth.POST("/signup", controllers.SignUp)
		auth.POST("/login", controllers.Login)
		auth.POST("/refresh", controllers.RefreshToken)
		auth.POST("/logout", controllers.Logout)
		auth.GET("/profile", controllers.AuthMiddleware(), controllers.Profile)
		auth.GET("/role", controllers.AuthMiddleware(), controllers.GetUserRole)
	}

	// Example of a protected route
	user := api.Group("/user")
	{
		user.GET("/protected", controllers.AuthMiddleware(), controllers.ProtectedResource)
	}
}