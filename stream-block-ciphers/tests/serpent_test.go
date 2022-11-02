package tests

import (
	"testing"

	ciphers "github.com/darkcat013/cs-labs/stream-block-ciphers"
	"github.com/darkcat013/cs-labs/stream-block-ciphers/interfaces"
)

func TestSerpent1(t *testing.T) {
	//Arrange
	msg := "plain text hehe hee not plain text hehe hee not"
	expectedEnc := "ec848cb1d56ac3ad78d3c170ca44da9f9a19ed758dc534a87b623868fb786cfdff3001bba54a3d23f48a87492f82348a"
	expectedDec := "plain text hehe hee not plain text hehe hee not"

	var c interfaces.Cipher = ciphers.Serpent{
		KeyString: "asdfasdfasdfasdf",
	}

	//Act
	enc := c.EncryptMessage(msg)
	dec := c.DecryptMessage(enc)

	//Assert
	if enc != expectedEnc {
		t.Errorf("Expected encrypted '%s', got '%s'", expectedEnc, enc)
	}
	if dec != expectedDec {
		t.Errorf("Expected decrypted '%s', got '%s'", expectedDec, dec)
	}
}

func TestSerpent2(t *testing.T) {
	//Arrange
	msg := "Get familiar with the cryptography and symmetric ciphers, this is serpent cipher"
	expectedEnc := "150ff2ee22b3bc1555fae00154cd608645583ed24dbb480752eaed68183760402a95d2d1307f3a1d517facadc7e6a5de462ba2c24d94ac11cea669854e7a0d353f12703318df45a5d2e54a6ef9a7518d"
	expectedDec := "Get familiar with the cryptography and symmetric ciphers, this is serpent cipher"

	var c interfaces.Cipher = ciphers.Serpent{
		KeyString: "16-byte-key-this",
	}

	//Act
	enc := c.EncryptMessage(msg)
	dec := c.DecryptMessage(enc)

	//Assert
	if enc != expectedEnc {
		t.Errorf("Expected encrypted '%s', got '%s'", expectedEnc, enc)
	}
	if dec != expectedDec {
		t.Errorf("Expected decrypted '%s', got '%s'", expectedDec, dec)
	}
}
