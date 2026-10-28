package auth

import (
	"context"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (r *authRepo) CheckExpire(ctx context.Context, access string) (models.Identity, error) {
	return r.keycloak.CheckExpire(ctx, access)
}
