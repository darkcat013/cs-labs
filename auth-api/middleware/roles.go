package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func WithRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleFromToken := c.GetString("role")
		if roleFromToken != role {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			c.Abort()
			return
		}
		c.Next()
	}
}
