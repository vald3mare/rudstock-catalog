package auth

import (
	"context"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

// keycloak контракт identity-провайдера: сейчас его реализует dummycloak, потом адаптер к настоящему Keycloak
// Репозиторий про реализацию не знает, поэтому замена провайдера не трогает ни его, ни сервис
type keycloak interface {
	Register(ctx context.Context, email, password string) (models.User, models.Tokens, error)
	Login(ctx context.Context, email, password string) (models.User, models.Tokens, error)
	Logout(ctx context.Context, refresh string) error
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

// AuthRepo доступ сервиса к identity-провайдеру.
type AuthRepo interface {
	// Register заводит покупателя и сразу выдаёт токены.
	// Ошибки: models.ErrEmailTaken.
	Register(ctx context.Context, email, password string) (models.User, models.Tokens, error)

	// Login проверяет пароль и выдаёт токены.
	// Ошибки: models.ErrInvalidCredentials, models.ErrUserInactive.
	Login(ctx context.Context, email, password string) (models.User, models.Tokens, error)

	// Logout гасит вход по refresh.
	Logout(ctx context.Context, refresh string) error

	// Refresh меняет refresh на новую пару.
	// Ошибки: models.ErrInvalidRefresh.
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)

	// CheckExpire проверяет access-токен.
	// Ошибки: models.ErrTokenExpired, models.ErrInvalidToken.
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

type authRepo struct {
	keycloak keycloak
}

// NewAuthRepo конструктор репозитория поверх identity-провайдера.
func NewAuthRepo(kc keycloak) AuthRepo {
	return &authRepo{keycloak: kc}
}
