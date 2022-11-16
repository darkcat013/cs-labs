package utils

import "crypto/sha256"

func GetSHA256Digest(input string) []byte {
	hash := sha256.New()
	_, err := hash.Write([]byte(input))
	if err != nil {
		panic(err)
	}
	return hash.Sum(nil)
}
