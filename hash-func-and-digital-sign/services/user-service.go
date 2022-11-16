package services

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/domain"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/interfaces"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/utils"
)

type UserService struct {
	Users interfaces.IDatabase
}

func NewUserService(db interfaces.IDatabase) interfaces.IUserService {
	return &UserService{Users: db}
}

func (s *UserService) Register(username, password string) error {

	_, err := s.Users.Get(username)
	if err == nil {
		return errors.New("UserService Register | User already exists")
	}

	hashedPassword := utils.GetSHA256Digest(password)

	key, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		return err
	}

	user := domain.User{
		Username: username,
		Password: hashedPassword,
		Key:      key,
	}

	return s.Users.Set(username, user)
}

func (s *UserService) Login(username, password string) (domain.User, error) {
	user, err := s.Users.Get(username)
	if err != nil {
		return domain.User{}, err
	}

	hashedPassword := utils.GetSHA256Digest(password)

	if !bytes.Equal(hashedPassword, user.Password) {
		return domain.User{}, errors.New("UserService Login | Invalid password")
	}

	return user, nil
}
