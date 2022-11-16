package tests

import (
	"testing"

	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/database"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/services"
)

func TestValidLogin(t *testing.T) {
	//Arrange
	db := database.NewDatabase()
	userService := services.NewUserService(db)
	userService.Register("darkcat", "villv013")

	//Act
	_, err := userService.Login("darkcat", "villv013")

	//Assert
	if err != nil {
		t.Errorf("Login error should be nil, got %s", err.Error())
	}
}

func TestValidRegisterInvalidLogin(t *testing.T) {
	//Arrange
	db := database.NewDatabase()
	userService := services.NewUserService(db)
	userService.Register("darkcat", "villv013")

	//Act
	_, err := userService.Login("darkcat", "darkcat")

	//Assert
	if err == nil {
		t.Errorf("Login error should not be nil")
	}
}
