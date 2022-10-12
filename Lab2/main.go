package main

import (
	"fmt"

	"github.com/darkcat013/cs-labs/ciphers"
	"github.com/darkcat013/cs-labs/interfaces"
)

func main() {
	var c interfaces.Cipher = ciphers.Rabbit{
		KeyString:        "rabbit-rabbit-16",
		InitVectorString: "rabbit16",
	}
	enc := c.EncryptMessage("Rabbit is a stream cipher algorithm that has been designed for high performance in software implementations.")
	fmt.Println(enc)
	fmt.Println(c.DecryptMessage(enc))
}
