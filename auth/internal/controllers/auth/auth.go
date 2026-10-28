package auth

import (
	"context"

	"github.com/vald3mare/Rudstock/auth/internal/models"
	authsvc "github.com/vald3mare/Rudstock/auth/internal/services/auth"
)

type authService interface {
	Register(ctx context.Context, in authsvc.RegUserInput) (authsvc.AuthResult, error)
	Login(ctx context.Context, in authsvc.LoginUserInput) (authsvc.AuthResult, error)
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)
	Logout(ctx context.Context, refresh string) error
}

type AuthHandler struct {
	svc authService
}

func NewAuthHandler(s authService) *AuthHandler {
	return &AuthHandler{svc: s}
}
