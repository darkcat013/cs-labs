package interfaces

import (
	"crypto/rsa"

	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/domain"
)

type IMessageService interface {
	NewMessage(from domain.User, message string) (hashedMessage []byte, signature []byte, err error)
	CheckMessage(publicKey *rsa.PublicKey, hashedMessage, signature []byte) error
}
