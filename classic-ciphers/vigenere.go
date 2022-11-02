package ciphers

import (
	"strings"

	"github.com/darkcat013/cs-labs/classic-ciphers/constants"
)

type Vigenere struct {
	Key string
}

func (c Vigenere) EncryptMessage(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToUpper(s)
	c.Key = strings.ToUpper(c.Key)

	var enc string
	for i := 0; i < len(s); i++ {

		if s[i] != ' ' {
			letterPos := int(s[i]) - constants.ASCII_A
			keyLetterPos := int(c.Key[i%len(c.Key)]) - constants.ASCII_A
			encPos := (letterPos + keyLetterPos) % constants.ALPHABET_LEN
			enc += string(constants.ALPHABET[encPos])
		} else {
			enc += " "
		}
	}
	return enc
}

func (c Vigenere) DecryptMessage(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToUpper(s)
	c.Key = strings.ToUpper(c.Key)

	var dec string
	for i := 0; i < len(s); i++ {

		if s[i] != ' ' {
			letterPos := int(s[i]) - constants.ASCII_A
			keyLetterPos := int(c.Key[i%len(c.Key)]) - constants.ASCII_A
			decPos := (letterPos - keyLetterPos + constants.ALPHABET_LEN) % constants.ALPHABET_LEN
			dec += string(constants.ALPHABET[decPos])
		} else {
			dec += " "
		}
	}
	return dec
}
