package auth

import "context"

func (s *authService) Login(ctx context.Context, in LoginUserInput) (AuthResult, error) {
	user, tokens, err := s.authRepo.Login(ctx, normalizeEmail(in.Email), in.Password)
	if err != nil {
		return AuthResult{}, err
	}

	return AuthResult{Tokens: tokens, User: user}, nil
}
