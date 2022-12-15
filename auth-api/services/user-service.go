package services

import (
	"bytes"
	"errors"

	"github.com/darkcat013/cs-labs/auth-api/constants"
	"github.com/darkcat013/cs-labs/auth-api/domain"
	"github.com/darkcat013/cs-labs/auth-api/dto"
	"github.com/darkcat013/cs-labs/auth-api/jwt"
	"github.com/darkcat013/cs-labs/auth-api/utils"
)

type UserService struct {
	users map[string]domain.User
}

func NewUserService() *UserService {
	users := make(map[string]domain.User)

	users["noroc@mail.com"] = domain.User{
		Email:    "noroc@mail.com",
		Password: utils.GetSHA256Digest("norocPass"),
		Role:     constants.ROLE_ADMIN,
	}

	users["user@mail.com"] = domain.User{
		Email:    "user@mail.com",
		Password: utils.GetSHA256Digest("userPass"),
		Role:     constants.ROLE_USER,
	}

	return &UserService{users: users}
}

func (s *UserService) Get(email string) (domain.User, error) {
	if value, ok := s.users[email]; ok {
		return value, nil
	}

	return domain.User{}, errors.New("UserService Get | User not found")
}

func (s *UserService) GetAll() ([]domain.User, error) {
	var users []domain.User

	for _, value := range s.users {
		users = append(users, value)
	}

	return users, nil
}

func (s *UserService) Register(dto dto.UserDto) error {
	if _, ok := s.users[dto.Email]; ok {
		return errors.New("UserService Register | User already exists")
	}

	hashedPassword := utils.GetSHA256Digest(dto.Password)

	s.users[dto.Email] = domain.User{Email: dto.Email, Password: hashedPassword, Role: constants.ROLE_USER}

	return nil
}

func (s *UserService) Login(dto dto.UserDto) (string, error) {
	user, err := s.Get(dto.Email)
	if err != nil {
		return "", err
	}

	hashedPassword := utils.GetSHA256Digest(dto.Password)

	if !bytes.Equal(hashedPassword, user.Password) {
		return "", errors.New("UserService Login | Invalid password")
	}

	jwt, err := jwt.Generate(user.Email, user.Role)
	if err != nil {
		return "", err
	}

	return jwt, nil
}
