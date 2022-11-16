package main

import (
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/database"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/services"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	db := database.NewDatabase()
	userService := services.NewUserService(db)

	err := userService.Register("darkcat", "villv013")
	check(err)

	err = userService.Register("darkcat1", "villv01333")
	check(err)

	user, err := userService.Login("darkcat", "villv013")
	check(err)

	user1, err := userService.Login("darkcat1", "villv01333")
	check(err)

	messageService := services.NewMessageService()
	hashedMessage, signature, err := messageService.NewMessage(user, "Very important message")
	check(err)

	err = messageService.CheckMessage(&user1.Key.PublicKey, hashedMessage, signature)
	check(err)
}
