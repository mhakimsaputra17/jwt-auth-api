package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/mhakimsaputra17/jwt-auth-api/database"
	"github.com/mhakimsaputra17/jwt-auth-api/routes"
)

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Initialize Database
	database.ConnectDatabase()

	// Setup Gin router
	router := gin.Default()
	routes.RegisterRoutes(router)

	// Start the server on specified port or default port 3000
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	router.Run(":" + port)
}