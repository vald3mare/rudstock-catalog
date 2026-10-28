package auth

import (
	"context"
	"net/mail"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (s *authService) Register(ctx context.Context, in RegUserInput) (AuthResult, error) {
	email := normalizeEmail(in.Email)
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return AuthResult{}, models.ErrInvalidEmail
	}

	if !isStrongPassword(in.Password) {
		return AuthResult{}, models.ErrWeakPassword
	}

	user, tokens, err := s.authRepo.Register(ctx, email, in.Password)
	if err != nil {
		return AuthResult{}, err
	}

	return AuthResult{Tokens: tokens, User: user}, nil
}
