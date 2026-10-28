package controllers

import (
	"net/http"

	"github.com/vald3mare/Rudstock/auth/internal/controllers/auth"
)

// NewRouter вешает ручки; requireAuth собирается в cmd/app и закрывает ручки, которым нужен access-токен.
func NewRouter(
	authHandler *auth.AuthHandler,
	requireAuth func(http.Handler) http.Handler,
) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandler.Logout)

	mux.Handle("GET /auth/verify", requireAuth(http.HandlerFunc(authHandler.Verify)))

	return mux
}
