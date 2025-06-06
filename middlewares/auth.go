package middlewares

import (
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		secureKey := c.Request.Header.Get("X-Auth-User")

		if secureKey != "" {
			c.AbortWithStatus(401)
			return
		}

		c.Next()
	}
}
