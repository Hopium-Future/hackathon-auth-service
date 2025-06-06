package middlewares

import (
	"na3/na3-auth/config"

	"github.com/gin-gonic/gin"
)

func AuthApiKeyMiddleware() gin.HandlerFunc {
	config := config.GetConfig()
	apiKey := config.GetString("apiKey")
	return func(c *gin.Context) {

		reqApiKey := c.Request.Header.Get("X-API-KEY")

		if apiKey != reqApiKey {
			c.AbortWithStatus(401)
			return
		}

		c.Next()
	}
}
