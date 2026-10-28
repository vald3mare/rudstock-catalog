package auth

import "github.com/vald3mare/Rudstock/auth/internal/models"

// AuthResult ответ register/login: токены и данные пользователя для {user: {...}}
type AuthResult struct {
	Tokens models.Tokens
	User   models.User
}

type RegUserInput struct {
	Email    string
	Password string
}

type LoginUserInput struct {
	Email    string
	Password string
}
