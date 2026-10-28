package dummycloak

import (
	"context"
	"errors"
	"fmt"

	"github.com/alexedwards/argon2id"
	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (c *cloak) Login(ctx context.Context, email, password string) (models.User, models.Tokens, error) {
	user, err := c.users.GetByEmail(ctx, email)
	if errors.Is(err, models.ErrUserNotFound) {
		// результат не важен, важно потраченное время (см. dummyHash)
		_, _ = argon2id.ComparePasswordAndHash(password, c.dummyHash)
		return models.User{}, models.Tokens{}, models.ErrInvalidCredentials
	}
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}

	ok, err := argon2id.ComparePasswordAndHash(password, user.PasswordHash)
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("compare password: %w", err)
	}
	if !ok {
		return models.User{}, models.Tokens{}, models.ErrInvalidCredentials
	}

	// блокировку проверяем только после верного пароля: иначе 403 выдаёт, что такой email есть
	if !user.IsActive {
		return models.User{}, models.Tokens{}, models.ErrUserInactive
	}

	tokens, err := c.startSession(ctx, user)
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}

	user.PasswordHash = "" // хеш не выходит за пределы keycloak
	return user, tokens, nil
}
