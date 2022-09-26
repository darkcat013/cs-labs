package tests

import (
	"testing"

	"github.com/darkcat013/cs-labs/ciphers"
	"github.com/darkcat013/cs-labs/interfaces"
)

func TestPlayfair1(t *testing.T) {
	//Arrange
	msg := "VINE IARNA"
	expectedEnc := "UR UN BP IO YW"
	expectedDec := "VINEIARNAX"

	var c interfaces.Cipher = ciphers.Playfair{
		Key: "PLAYFAIR",
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

func TestPlayfair2(t *testing.T) {
	//Arrange
	msg := "Hello world cool goodbyey asd"
	expectedEnc := "OC NV UG YH SU ED KY GU HQ KE EV OR RT KA"
	expectedDec := "HELXLOWORLDCOXOLGOODBYEYASDX"

	var c interfaces.Cipher = ciphers.Playfair{
		Key: "StarPlatinum",
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
