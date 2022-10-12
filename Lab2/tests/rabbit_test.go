package tests

import (
	"testing"

	"github.com/darkcat013/cs-labs/ciphers"
	"github.com/darkcat013/cs-labs/interfaces"
)

func TestRabbit1(t *testing.T) {
	//Arrange
	msg := "plain text -- dummy text to encrypt and decrypt with rabbit cipher"
	expectedEnc := "b622f810010c443724f72db61cbfab2fb809d92ce7fff32a6366997454d408026aa46bb0d41212af7bfaee6d175d76c57a78c9827df6da52ffd89cbe48c8d8249a65"
	expectedDec := "plain text -- dummy text to encrypt and decrypt with rabbit cipher"

	var c interfaces.Cipher = ciphers.Rabbit{
		KeyString:        "generate-16-byte",
		InitVectorString: "abcd1234",
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

func TestRabbit2(t *testing.T) {
	//Arrange
	msg := "Rabbit is a stream cipher algorithm that has been designed for high performance in software implementations."
	expectedEnc := "d0f234e0ba658c63d4346cba2b1ce31a3de69577e1ba0bd0c5f4de89846feab095b6cee25e507d5b409ba674567e63e0dfd481212e0dfa74c0251cda92c1b93532aacf0e228914b8a5d24d6d9a4eca06fcc686a5ad15e7b441043a9c10a55690f5b63a987beef9b7fa05e952"
	expectedDec := "Rabbit is a stream cipher algorithm that has been designed for high performance in software implementations."

	var c interfaces.Cipher = ciphers.Rabbit{
		KeyString:        "rabbit-rabbit-16",
		InitVectorString: "rabbit16",
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
