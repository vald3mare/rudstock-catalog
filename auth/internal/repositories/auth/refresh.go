package auth

import (
	"context"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (r *authRepo) Refresh(ctx context.Context, refresh string) (models.Tokens, error) {
	return r.keycloak.Refresh(ctx, refresh)
}
