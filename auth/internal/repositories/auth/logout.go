package auth

import "context"

func (r *authRepo) Logout(ctx context.Context, refresh string) error {
	return r.keycloak.Logout(ctx, refresh)
}
