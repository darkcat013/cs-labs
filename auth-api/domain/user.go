package domain

type User struct {
	Email    string `json:"email"`
	Password []byte `json:"-"`
	Role     string `json:"role"`
}
