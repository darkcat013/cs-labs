package main

import (
	"fmt"

	"github.com/darkcat013/cs-labs/ciphers"
	"github.com/darkcat013/cs-labs/interfaces"
)

func main() {
	var c interfaces.Cipher = ciphers.Caesar{
		Key: 3,
	}
	enc := c.EncryptMessage("cifrul cezar")
	fmt.Println(enc)
	fmt.Println(c.DecryptMessage(enc))
	fmt.Println()

	c = ciphers.PolybiusEnglish{
		ColumnKey: "mouse",
		RowKey:    "musca",
	}
	enc = c.EncryptMessage("VENI VIDI VICI")
	fmt.Println(enc)
	fmt.Println(c.DecryptMessage(enc))
	fmt.Println()

	c = ciphers.Vigenere{
		Key: "super",
	}
	enc = c.EncryptMessage("PERASPERAADASTRA")
	fmt.Println(enc)
	fmt.Println(c.DecryptMessage(enc))
	fmt.Println()

	c = ciphers.Playfair{
		Key: "PLAYFAIR",
	}
	enc = c.EncryptMessage("VINE IARNA")
	fmt.Println(enc)
	fmt.Println(c.DecryptMessage(enc))
	fmt.Println()
}
