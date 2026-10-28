package dummycloak

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vald3mare/Rudstock/auth/internal/models"
)

// newSession генерирует refresh-токен и собирает под него сессию; в базу не пишет.
// authenticatedAt при ротации переносится из старой сессии, от него считается абсолютный предел.
func (c *cloak) newSession(userID, familyID uuid.UUID, authenticatedAt time.Time) (string, models.Session, error) {
	raw, hash, err := c.emitter.Refresh()
	if err != nil {
		return "", models.Session{}, fmt.Errorf("generate refresh: %w", err)
	}

	// ExpiresAt = min(скользящий от сейчас, абсолютный от ввода пароля)
	expiresAt := time.Now().Add(c.conf.RefreshTTL)
	if limit := authenticatedAt.Add(c.conf.RefreshMaxTTL); limit.Before(expiresAt) {
		expiresAt = limit
	}

	return raw, models.Session{
		UserID:          userID,
		FamilyID:        familyID,
		TokenHash:       hash,
		AuthenticatedAt: authenticatedAt,
		ExpiresAt:       expiresAt,
	}, nil
}

// startSession открывает новый вход (register/login): новая семья, сессия в базе, пара токенов.
func (c *cloak) startSession(ctx context.Context, user models.User) (models.Tokens, error) {
	raw, session, err := c.newSession(user.ID, uuid.New(), time.Now())
	if err != nil {
		return models.Tokens{}, err
	}

	// сначала сессия: её id нужен в access-токене как sid
	sessionID, err := c.sessions.Create(ctx, session)
	if err != nil {
		return models.Tokens{}, err
	}

	access, err := c.emitter.Emit(user.ID, user.Role, sessionID)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("emit access: %w", err)
	}

	return models.Tokens{Access: access, Refresh: raw}, nil
}
