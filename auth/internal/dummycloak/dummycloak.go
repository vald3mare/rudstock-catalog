// Package dummycloak наша реализация identity-провайдера по контракту Keycloak.
// Внутри всё, что потом заберёт настоящий Keycloak: хеши паролей, сессии и ротация refresh,
// выпуск и проверка токенов, своя база (users, sessions). Остальные слои видят только Keycloak.
package dummycloak

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	"github.com/vald3mare/Rudstock/auth/internal/models"
)

// Keycloak контракт identity-провайдера; его же потом реализует адаптер к настоящему Keycloak.
type Keycloak interface {
	// Register заводит покупателя и сразу открывает сессию.
	// Ошибки: models.ErrEmailTaken.
	Register(ctx context.Context, email, password string) (models.User, models.Tokens, error)

	// Login проверяет пароль и открывает сессию.
	// Ошибки: models.ErrInvalidCredentials, models.ErrUserInactive.
	Login(ctx context.Context, email, password string) (models.User, models.Tokens, error)

	// Logout гасит вход, которому принадлежит refresh. Неизвестный refresh не ошибка.
	Logout(ctx context.Context, refresh string) error

	// Refresh меняет refresh на новую пару; повторное использование старого гасит весь вход.
	// Ошибки: models.ErrInvalidRefresh.
	Refresh(ctx context.Context, refresh string) (models.Tokens, error)

	// CheckExpire проверяет access-токен и возвращает, кто пришёл.
	// Ошибки: models.ErrTokenExpired, models.ErrInvalidToken.
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

// userStore что dummycloak нужно от хранилища пользователей (storage/user)
type userStore interface {
	Create(ctx context.Context, user models.User) (uuid.UUID, error)
	GetByEmail(ctx context.Context, email string) (models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (models.User, error)
}

// sessionStore что dummycloak нужно от хранилища сессий (storage/session)
type sessionStore interface {
	Create(ctx context.Context, s models.Session) (uuid.UUID, error)
	GetByTokenHash(ctx context.Context, hash []byte) (models.Session, error)
	Rotate(ctx context.Context, oldID uuid.UUID, next models.Session) (uuid.UUID, error)
	RevokeFamily(ctx context.Context, familyID uuid.UUID) error
}

// emitter что dummycloak нужно от пакета tokens
type emitter interface {
	Emit(userID uuid.UUID, role models.Role, sessionID uuid.UUID) (string, error)
	Verify(access string) (models.Identity, error)
	Refresh() (raw string, hash []byte, err error)
	HashRefresh(raw string) []byte
}

// Config настройки из конфигурации приложения.
type Config struct {
	RefreshTTL    time.Duration   // скользящий срок: каждый refresh продлевает вход на столько
	RefreshMaxTTL time.Duration   // абсолютный предел от ввода пароля, дальше только новый login
	Argon2        argon2id.Params // параметры хеширования паролей
}

type cloak struct {
	users    userStore
	sessions sessionStore
	emitter  emitter
	conf     Config

	// dummyHash для Login с несуществующим email: сравниваем пароль с ним, чтобы ответ шёл столько же,
	// сколько с существующим, и по времени нельзя было узнать, зарегистрирован ли email.
	// Считается с теми же параметрами, что и настоящие хеши, иначе время будет отличаться
	dummyHash string
}

func New(users userStore, sessions sessionStore, emitter emitter, conf Config) (Keycloak, error) {
	if conf.RefreshTTL <= 0 || conf.RefreshMaxTTL <= 0 {
		return nil, errors.New("refresh ttl must be positive")
	}

	dummyHash, err := argon2id.CreateHash(rand.Text(), &conf.Argon2)
	if err != nil {
		return nil, fmt.Errorf("create dummy hash: %w", err)
	}

	return &cloak{
		users:     users,
		sessions:  sessions,
		emitter:   emitter,
		conf:      conf,
		dummyHash: dummyHash,
	}, nil
}
