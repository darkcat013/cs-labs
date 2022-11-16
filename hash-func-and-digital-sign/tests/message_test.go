package tests

import (
	"testing"

	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/database"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/services"
)

func TestValidMessageCheck(t *testing.T) {
	//Arrange
	db := database.NewDatabase()
	userService := services.NewUserService(db)

	userService.Register("darkcat", "villv013")
	user, _ := userService.Login("darkcat", "villv013")

	messageService := services.NewMessageService()
	hashedMessage, signature, _ := messageService.NewMessage(user, "Very important message")

	//Act
	err := messageService.CheckMessage(&user.Key.PublicKey, hashedMessage, signature)

	//Assert
	if err != nil {
		t.Errorf("CheckMessage error should be nil, got %s", err.Error())
	}
}

func TestInvalidMessageCheck(t *testing.T) {
	//Arrange
	db := database.NewDatabase()
	userService := services.NewUserService(db)

	userService.Register("darkcat", "villv013")
	userService.Register("darkcat1", "villv01333")

	user, _ := userService.Login("darkcat", "villv013")
	user1, _ := userService.Login("darkcat1", "villv01333")

	messageService := services.NewMessageService()
	hashedMessage, signature, _ := messageService.NewMessage(user, "Very important message")

	//Act
	err := messageService.CheckMessage(&user1.Key.PublicKey, hashedMessage, signature)

	//Assert
	if err == nil {
		t.Errorf("CheckMessage error should not be nil")
	}
}
