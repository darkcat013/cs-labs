package ciphers

import (
	"strings"

	"github.com/darkcat013/cs-labs/constants"
)

type Playfair struct {
	Key string
}

func encryptDigraph(alpha string, a, b byte) string {
	aPos := strings.IndexByte(alpha, a)
	bPos := strings.IndexByte(alpha, b)

	aRow, aCol := aPos/5, aPos%5
	bRow, bCol := bPos/5, bPos%5

	alphaLen := len(alpha)

	if aCol == bCol {
		return string(alpha[(aPos+5)%alphaLen]) + string(alpha[(bPos+5)%alphaLen])
	}
	if aRow == bRow {
		return string(alpha[(aPos+1)%alphaLen]) + string(alpha[(bPos+1)%alphaLen])
	}

	return string(alpha[aRow*5+bCol]) + string(alpha[bRow*5+aCol])
}

func decryptDigraph(alpha string, a, b byte) string {
	aPos := strings.IndexByte(alpha, a)
	bPos := strings.IndexByte(alpha, b)

	aRow, aCol := aPos/5, aPos%5
	bRow, bCol := bPos/5, bPos%5

	alphaLen := len(alpha)

	if aCol == bCol {
		return string(alpha[(aPos-5+alphaLen)%alphaLen]) + string(alpha[(bPos-5+alphaLen)%alphaLen])
	}
	if aRow == bRow {
		return string(alpha[(aPos-1+alphaLen)%alphaLen]) + string(alpha[(bPos-1+alphaLen)%alphaLen])
	}

	return string(alpha[aRow*5+bCol]) + string(alpha[bRow*5+aCol])
}

func (pf Playfair) EncryptMessage(s string) string {
	pf.Key = strings.ToUpper(pf.Key)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToUpper(s)
	var newAlpha = constants.ALPHABET

	for i := len(pf.Key) - 1; i >= 0; i-- {
		newAlpha = string(pf.Key[i]) + strings.ReplaceAll(newAlpha, string(pf.Key[i]), "")
	}
	newAlpha = strings.ReplaceAll(newAlpha, "J", "")

	var enc string

	for i := 0; i < len(s); i += 2 {

		if i+1 == len(s) {
			s += constants.RARE_LETTER
			enc += encryptDigraph(newAlpha, s[i], s[i+1]) + " "
			break
		}

		if s[i] == s[i+1] {
			s = s[:i+1] + constants.RARE_LETTER + s[i+1:]
		}
		enc += encryptDigraph(newAlpha, s[i], s[i+1]) + " "
	}
	enc = strings.Trim(enc, " ")
	return enc
}

func (pf Playfair) DecryptMessage(s string) string {
	pf.Key = strings.ToUpper(pf.Key)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ToUpper(s)
	var newAlpha = constants.ALPHABET

	for i := len(pf.Key) - 1; i >= 0; i-- {
		newAlpha = string(pf.Key[i]) + strings.ReplaceAll(newAlpha, string(pf.Key[i]), "")
	}
	newAlpha = strings.ReplaceAll(newAlpha, "J", "")

	var dec string

	for i := 0; i < len(s); i += 2 {
		dec += decryptDigraph(newAlpha, s[i], s[i+1])
	}

	return dec
}
