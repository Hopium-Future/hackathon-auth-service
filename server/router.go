package server

import (
	"na3/na3-auth/config"
	"na3/na3-auth/controllers"
	"na3/na3-auth/middlewares"

	"github.com/gin-gonic/gin"
)

func NewRouter() *gin.Engine {
	config := config.GetConfig()

	router := gin.New()

	if config.GetBool("server.logging") {
		router.Use(gin.Logger())
	}

	router.Use(gin.Recovery())

	health := new(controllers.HealthController)

	router.GET("/health", health.Status)

	v1 := router.Group("api/v1")
	{
		authGroup := v1.Group("auth")
		{
			authGroup.Use(middlewares.AuthMiddleware())
			auth := new(controllers.AuthController)
			authGroup.GET("", auth.Auth)
			authGroup.GET("add-header", auth.AddHeaderAuth)
			authGroup.POST("validate-telegram-token", auth.ValidateTelegramToken)

			// Internal routes
			authGroup.Use(middlewares.AuthApiKeyMiddleware())
			{
				authGroup.POST("sign-token", auth.SignToken)
			}
		}
	}
	return router
}
