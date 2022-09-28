package ciphers

import (
	"strings"

	"github.com/darkcat013/cs-labs/constants"
)

type PolybiusEnglish struct {
	ColumnKey string
	RowKey    string
}

func (p PolybiusEnglish) getMatrix() map[byte]map[byte]byte {

	matrix := map[byte]map[byte]byte{}

	var newAlpha = strings.ReplaceAll(constants.ALPHABET, "J", "")
	row := -1
	for i := 0; i < len(newAlpha); i++ {
		if i%5 == 0 {
			row++
			matrix[p.RowKey[row]] = map[byte]byte{}
		}
		matrix[p.RowKey[row]][p.ColumnKey[i%5]] = newAlpha[i]
	}
	return matrix
}

func (p PolybiusEnglish) EncryptMessage(s string) string {

	p.ColumnKey = strings.ToUpper(p.ColumnKey)
	p.RowKey = strings.ToUpper(p.RowKey)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToUpper(s)

	var enc string
	for i := 0; i < len(s); i++ {
		letterPos := int(s[i]) - constants.ASCII_A
		if letterPos >= strings.IndexByte(constants.ALPHABET, 'J') {
			letterPos--
		}
		val := string(p.ColumnKey[letterPos%5]) + string(p.RowKey[letterPos/5])
		enc += string(val)
		if len(enc)%3 == 2 {
			enc += " "
		}
	}
	enc = strings.Trim(enc, " ")
	return enc
}

func (p PolybiusEnglish) DecryptMessage(s string) string {

	p.ColumnKey = strings.ToUpper(p.ColumnKey)
	p.RowKey = strings.ToUpper(p.RowKey)
	s = strings.ToUpper(s)

	matrix := p.getMatrix()

	var dec string
	for i := 0; i < len(s); i += 3 {
		dec += string(matrix[s[i+1]][s[i]])
	}

	return dec
}
