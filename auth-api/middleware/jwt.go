package middleware

import (
	"net/http"

	"github.com/darkcat013/cs-labs/auth-api/jwt"
	"github.com/gin-gonic/gin"
)

func JwtAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		email, role, err := jwt.ExtractEmailAndRole(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		c.Set("email", email)
		c.Set("role", role)
		c.Next()
	}
}
