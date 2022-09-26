package tests

import (
	"testing"

	"github.com/darkcat013/cs-labs/ciphers"
	"github.com/darkcat013/cs-labs/interfaces"
)

func TestCaesar1(t *testing.T) {
	//Arrange
	msg := "cifrul cezar"
	expectedEnc := "FLIUXO FHCDU"
	expectedDec := "CIFRUL CEZAR"

	var c interfaces.Cipher = ciphers.Caesar{
		Key: 3,
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

func TestCaesar2(t *testing.T) {
	//Arrange
	msg := "Get familiar with the basics of cryptography and classical ciphers"
	expectedEnc := "XVK WRDZCZRI NZKY KYV SRJZTJ FW TIPGKFXIRGYP REU TCRJJZTRC TZGYVIJ"
	expectedDec := "GET FAMILIAR WITH THE BASICS OF CRYPTOGRAPHY AND CLASSICAL CIPHERS"

	var c interfaces.Cipher = ciphers.Caesar{
		Key: 17,
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
