package auth

import (
	"context"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

type AuthService interface {
	// Register создаёт покупателя (роль всегда customer) и сразу выдаёт токены
	// Ошибки: models.ErrInvalidEmail, models.ErrWeakPassword, models.ErrEmailTaken.
	Register(ctx context.Context, in RegUserInput) (AuthResult, error)

	// Login проверяет email и пароль и выдаёт токены; ответ как у Register
	// Ошибки: models.ErrInvalidCredentials, models.ErrUserInactive.
	Login(ctx context.Context, in LoginUserInput) (AuthResult, error)

	// Refresh меняет refresh-токен на новую пару; старый refresh после этого недействителен
	// Ошибки: models.ErrInvalidRefresh.
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)

	// Logout гасит вход, которому принадлежит refresh. Неизвестный или погашенный refresh не ошибка
	Logout(ctx context.Context, refresh string) error

	// CheckExpire проверяет access-токен и возвращает, кто пришёл (для middleware)
	// Ошибки: models.ErrTokenExpired, models.ErrInvalidToken.
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

// AuthRepo что сервису нужно от репозитория (repositories/auth поверх keycloak)
type AuthRepo interface {
	Register(ctx context.Context, email, password string) (models.User, models.Tokens, error)
	Login(ctx context.Context, email, password string) (models.User, models.Tokens, error)
	Logout(ctx context.Context, refresh string) error
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

type authService struct {
	authRepo AuthRepo
}

func NewAuthService(repo AuthRepo) AuthService {
	return &authService{authRepo: repo}
}
