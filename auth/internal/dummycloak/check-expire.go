package dummycloak

import (
	"context"
	"errors"

	"github.com/vald3mare/Rudstock/auth/internal/dummycloak/tokens"
	"github.com/vald3mare/Rudstock/auth/internal/models"
)

// CheckExpire проверяет подпись и срок access-токена локально, без похода в базу:
// после logout токен живёт до своего exp, поэтому access и короткий.
// ctx не используется, но остаётся в контракте: у настоящего Keycloak это сетевой вызов.
func (c *cloak) CheckExpire(_ context.Context, access string) (models.Identity, error) {
	identity, err := c.emitter.Verify(access)
	if errors.Is(err, tokens.ErrTokenExpired) {
		return models.Identity{}, models.ErrTokenExpired
	}
	if err != nil {
		return models.Identity{}, models.ErrInvalidToken
	}

	return identity, nil
}
