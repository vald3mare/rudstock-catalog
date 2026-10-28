package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/vald3mare/Rudstock/auth/internal/models"
	"github.com/vald3mare/Rudstock/auth/internal/platform/errs"
	"github.com/vald3mare/Rudstock/auth/internal/platform/httpx"
)

// verifier что middleware нужно от сервиса: проверка access-токена идёт по тем же слоям,
// что и ручки (service -> repo -> keycloak), сама middleware токены не разбирает
type verifier interface {
	CheckExpire(ctx context.Context, access string) (models.Identity, error)
}

// identityKey закрытый тип ключа: чужой пакет не сможет ни прочитать, ни подменить значение в контексте
type identityKey struct{}

// Middleware пропускает запрос только с валидным Authorization: Bearer <access>
// и кладёт в контекст, кто пришёл; хендлеры достают это через IdentityFrom.
func Middleware(v verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, ok := bearer(r)
		if !ok {
			httpx.WriteError(w, r, errs.Unauthorized("unauthorized", "Authorization required", nil))
			return
		}

		identity, err := v.CheckExpire(r.Context(), access)
		if err != nil {
			httpx.WriteError(w, r, mapTokenError(err))
			return
		}

		ctx := context.WithValue(r.Context(), identityKey{}, identity)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// IdentityFrom возвращает того, кого пропустил Middleware. false значит ручка не под Middleware.
func IdentityFrom(ctx context.Context) (models.Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(models.Identity)
	return identity, ok
}

// mapTokenError отдельный слаг для истёкшего: фронт по нему идёт в /auth/refresh, а не на страницу входа.
// Всё неизвестное (например, keycloak недоступен) уходит как есть, WriteError ответит 500.
func mapTokenError(err error) error {
	switch {
	case errors.Is(err, models.ErrTokenExpired):
		return errs.Unauthorized("token-expired", "Access token expired", err)
	case errors.Is(err, models.ErrInvalidToken):
		return errs.Unauthorized("invalid-token", "Invalid access token", err)
	default:
		return err
	}
}

// bearer достаёт токен из заголовка; схема по RFC 6750 регистронезависимая
func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	token = strings.TrimSpace(token)
	return token, token != ""
}
