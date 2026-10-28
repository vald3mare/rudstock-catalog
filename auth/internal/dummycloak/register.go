package dummycloak

import (
	"context"
	"fmt"

	"github.com/alexedwards/argon2id"
	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (c *cloak) Register(ctx context.Context, email, password string) (models.User, models.Tokens, error) {
	hash, err := argon2id.CreateHash(password, &c.conf.Argon2)
	if err != nil {
		return models.User{}, models.Tokens{}, fmt.Errorf("hash password: %w", err)
	}

	user := models.User{
		Email:        email,
		PasswordHash: hash,
		Role:         models.RoleCustomer,
		IsActive:     true, // false = заблокирован
	}

	id, err := c.users.Create(ctx, user)
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}
	user.ID = id

	tokens, err := c.startSession(ctx, user)
	if err != nil {
		return models.User{}, models.Tokens{}, err
	}

	user.PasswordHash = "" // хеш не выходит за пределы keycloak
	return user, tokens, nil
}
