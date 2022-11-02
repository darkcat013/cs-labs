package main

import (
	"crypto/rand"
	"fmt"

	"github.com/darkcat013/cs-labs/ciphers"
)

func main() {

	rsa, err := ciphers.GenerateRSAKeys(rand.Reader, 64)
	if err != nil {
		panic(err)
	}

	fmt.Println("Private key: ", rsa.D, rsa.N)
	fmt.Println("Public key: ", rsa.E, rsa.N)

	msg := "hello"
	fmt.Println("Message: " + msg)

	c := rsa.EncryptMessage(msg)
	fmt.Println("Encrypted: " + c)

	m := rsa.DecryptMessage(c)
	fmt.Println("Decrypted: " + m)
}
