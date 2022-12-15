package jwt

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

func Generate(email, role string) (string, error) {

	secret := os.Getenv("SECRET")

	claims := jwt.MapClaims{}
	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := jwtToken.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ExtractEmailAndRole(c *gin.Context) (string, string, error) {

	secret := os.Getenv("SECRET")

	authToken := c.Query("token")
	if authToken == "" {

		bearerToken := c.Request.Header.Get("Authorization")

		if len(strings.Split(bearerToken, " ")) == 2 {
			authToken = strings.Split(bearerToken, " ")[1]
		}
	}

	jwtToken, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return "", "", err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if ok && jwtToken.Valid {
		email := claims["email"].(string)
		role := claims["role"].(string)
		return email, role, nil
	}

	return "", "", nil
}
