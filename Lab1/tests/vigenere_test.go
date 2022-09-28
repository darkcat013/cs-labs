package tests

import (
	"testing"

	"github.com/darkcat013/cs-labs/ciphers"
	"github.com/darkcat013/cs-labs/interfaces"
)

func TestVigenere1(t *testing.T) {
	//Arrange
	msg := "Per aspera ad astra"
	expectedEnc := "HYGEJHYGERVUHXIS"
	expectedDec := "PERASPERAADASTRA"

	var c interfaces.Cipher = ciphers.Vigenere{
		Key: "super",
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

func TestVigenere2(t *testing.T) {
	//Arrange
	msg := "Judging by the encryption mechanism one can conclude that this cipher is pretty easy to break"
	expectedEnc := "LLBVBBMSYIOCGBPJGHMAOCMVVVFGPWEQVIPCRMBBYYUVGKFPMHSWYAKGFTKWYGRTARASNKGLHTRTAB"
	expectedDec := "JUDGINGBYTHEENCRYPTIONMECHANISMONECANCONCLUDETHATTHISCIPHERISPRETTYEASYTOBREAK"

	var c interfaces.Cipher = ciphers.Vigenere{
		Key: "CryptographyconsistsapartofthescienceknownasCryptology",
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
