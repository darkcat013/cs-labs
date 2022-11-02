package tests

import (
	"crypto/rand"
	"testing"

	"github.com/darkcat013/cs-labs/ciphers"
)

func TestEncryptDecrypt(t *testing.T) {
	//Arrange
	rsa, err := ciphers.GenerateRSAKeys(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	msg := "hello world"
	expectedDec := "hello world"

	//Act
	enc := rsa.EncryptMessage(msg)
	dec := rsa.DecryptMessage(enc)

	//Assert
	if dec != expectedDec {
		t.Fatalf("Expected decrypted '%s', got '%s'", expectedDec, dec)
	}
}
