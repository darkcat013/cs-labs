package domain

import "crypto/rsa"

type User struct {
	Username string
	Password []byte
	Key      *rsa.PrivateKey
}
