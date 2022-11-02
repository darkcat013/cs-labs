package ciphers

import (
	"strings"

	"github.com/darkcat013/cs-labs/classic-ciphers/constants"
)

type Caesar struct {
	Key int
}

func (c Caesar) EncryptMessage(s string) string {
	s = strings.ToUpper(s)
	var enc string
	for i := 0; i < len(s); i++ {

		if s[i] != ' ' {
			letterPos := int(s[i]) - constants.ASCII_A
			encPos := (letterPos + c.Key) % constants.ALPHABET_LEN
			enc += string(constants.ALPHABET[encPos])
		} else {
			enc += " "
		}
	}
	return enc
}

func (c Caesar) DecryptMessage(s string) string {
	s = strings.ToUpper(s)
	var dec string
	for i := 0; i < len(s); i++ {

		if s[i] != ' ' {
			letterPos := int(s[i]) - constants.ASCII_A
			decPos := (letterPos - c.Key + constants.ALPHABET_LEN) % constants.ALPHABET_LEN
			dec += string(constants.ALPHABET[decPos])
		} else {
			dec += " "
		}
	}
	return dec
}
