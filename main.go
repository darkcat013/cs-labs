package main

import (
	authapi "github.com/darkcat013/cs-labs/auth-api"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	authapi.StartServer()
}
