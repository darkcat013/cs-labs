package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/domain"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/interfaces"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/utils"
)

type MessageService struct{}

func NewMessageService() interfaces.IMessageService {
	return &MessageService{}
}

func (s *MessageService) NewMessage(from domain.User, message string) (hashedMessage []byte, signature []byte, err error) {
	hashedMessage = utils.GetSHA256Digest(message)

	signature, err = rsa.SignPKCS1v15(rand.Reader, from.Key, crypto.SHA256, hashedMessage)

	if err != nil {
		return nil, nil, errors.New("MessageService | Could not create new message")
	}

	return hashedMessage, signature, nil
}

func (s *MessageService) CheckMessage(publicKey *rsa.PublicKey, hashedMessage, signature []byte) error {
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, []byte(hashedMessage), []byte(signature))
	if err != nil {
		return errors.New("MessageService | Message signature check failed")
	}
	return nil
}
