package auth

import (
	"context"

	"github.com/vald3mare/Rudstock/auth/internal/models"
)

func (s *authService) CheckExpire(ctx context.Context, access string) (models.Identity, error) {
	return s.authRepo.CheckExpire(ctx, access)
}
