package interfaces

import "github.com/darkcat013/cs-labs/hash-func-and-digital-sign/domain"

type IDatabase interface {
	Get(id string) (domain.User, error)
	Set(id string, value domain.User) error
	Delete(id string) error
}
