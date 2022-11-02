package tests

import (
	"testing"

	ciphers "github.com/darkcat013/cs-labs/classic-ciphers"
	"github.com/darkcat013/cs-labs/classic-ciphers/interfaces"
)

func TestPolybius1(t *testing.T) {
	//Arrange
	msg := "VENI VIDI VICI"
	expectedEnc := "MA EM US SU MA SU SM SU MA SU UM SU"
	expectedDec := "VENIVIDIVICI"

	var c interfaces.Cipher = ciphers.PolybiusEnglish{
		ColumnKey: "mouse",
		RowKey:    "musca",
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

func TestPolybius2(t *testing.T) {
	//Arrange
	msg := "Playfair cipher"
	expectedEnc := "53 13 11 45 12 11 42 24 31 42 53 32 51 24"
	expectedDec := "PLAYFAIRCIPHER"

	var c interfaces.Cipher = ciphers.PolybiusEnglish{
		ColumnKey: "12345",
		RowKey:    "12345",
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
