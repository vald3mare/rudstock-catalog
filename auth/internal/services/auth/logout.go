package auth

import "context"

func (s *authService) Logout(ctx context.Context, refresh string) error {
	if refresh == "" {
		return nil
	}

	return s.authRepo.Logout(ctx, refresh)
}
