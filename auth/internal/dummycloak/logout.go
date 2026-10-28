package dummycloak

import (
	"context"
	"errors"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

// Logout гасит всю семью, а не одну сессию: если клиент прислал уже обменянный refresh,
// живая сессия этого входа всё равно погаснет.
func (c *cloak) Logout(ctx context.Context, refresh string) error {
	session, err := c.sessions.GetByTokenHash(ctx, c.emitter.HashRefresh(refresh))
	if errors.Is(err, models.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	return c.sessions.RevokeFamily(ctx, session.FamilyID)
}
