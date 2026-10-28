package models

import "errors"

var (
	ErrInvalidEmail       = errors.New("invalid email")
	ErrWeakPassword       = errors.New("weak password")
	ErrEmailTaken         = errors.New("email taken")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserInactive       = errors.New("user inactive")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidRefresh     = errors.New("invalid refresh token")
	ErrInvalidToken       = errors.New("invalid access token")
	ErrTokenExpired       = errors.New("access token expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionRevoked     = errors.New("session revoked") // уже погашена: повторное использование refresh или гонка двух refresh
)
