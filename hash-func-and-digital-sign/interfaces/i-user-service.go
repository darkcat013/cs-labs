package interfaces

import "github.com/darkcat013/cs-labs/hash-func-and-digital-sign/domain"

type IUserService interface {
	Register(username, password string) error
	Login(username, password string) (domain.User, error)
}
