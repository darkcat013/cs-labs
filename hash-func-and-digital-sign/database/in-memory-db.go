package database

import (
	"errors"

	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/domain"
	"github.com/darkcat013/cs-labs/hash-func-and-digital-sign/interfaces"
)

type InMemoryDatabase struct {
	Users map[string]domain.User
}

func NewDatabase() interfaces.IDatabase {
	return &InMemoryDatabase{Users: make(map[string]domain.User)}
}

func (db *InMemoryDatabase) Get(username string) (domain.User, error) {
	if user, ok := db.Users[username]; ok {
		return user, nil
	}

	return domain.User{}, errors.New("database get | user not found")
}

func (db *InMemoryDatabase) Set(username string, value domain.User) error {
	db.Users[username] = value
	return nil
}

func (db *InMemoryDatabase) Delete(username string) error {

	if _, ok := db.Users[username]; ok {
		delete(db.Users, username)
		return nil
	}

	return errors.New("database delete | user not found")
}
