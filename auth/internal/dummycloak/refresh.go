package dummycloak

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (c *cloak) Refresh(ctx context.Context, refresh string) (models.Tokens, error) {
	session, err := c.sessions.GetByTokenHash(ctx, c.emitter.HashRefresh(refresh))
	if errors.Is(err, models.ErrSessionNotFound) {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	if err != nil {
		return models.Tokens{}, err
	}

	// токен уже обменивали: его украли или это старая копия у клиента. Не знаем, у кого настоящий,
	// поэтому гасим весь вход, и обоим придётся логиниться заново
	if session.RevokedAt != nil {
		if err := c.sessions.RevokeFamily(ctx, session.FamilyID); err != nil {
			return models.Tokens{}, err
		}
		return models.Tokens{}, models.ErrInvalidRefresh
	}

	if !time.Now().Before(session.ExpiresAt) {
		return models.Tokens{}, models.ErrInvalidRefresh
	}

	// роль и блокировку берём из базы, а не из старого токена: они могли измениться
	user, err := c.users.GetByID(ctx, session.UserID)
	if err != nil {
		return models.Tokens{}, err
	}
	if !user.IsActive {
		if err := c.sessions.RevokeFamily(ctx, session.FamilyID); err != nil {
			return models.Tokens{}, err
		}
		return models.Tokens{}, models.ErrInvalidRefresh
	}

	raw, next, err := c.newSession(user.ID, session.FamilyID, session.AuthenticatedAt)
	if err != nil {
		return models.Tokens{}, err
	}

	nextID, err := c.sessions.Rotate(ctx, session.ID, next)
	// параллельный refresh тем же токеном успел первым: он и продолжит вход, этот отклоняем
	if errors.Is(err, models.ErrSessionRevoked) {
		return models.Tokens{}, models.ErrInvalidRefresh
	}
	if err != nil {
		return models.Tokens{}, err
	}

	access, err := c.emitter.Emit(user.ID, user.Role, nextID)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("emit access: %w", err)
	}

	return models.Tokens{Access: access, Refresh: raw}, nil
}
