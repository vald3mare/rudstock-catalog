package app

import (
	"fmt"
	"net/http"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vald3mare/Rudstock/auth/internal/controllers"
	authCtrl "github.com/vald3mare/Rudstock/auth/internal/controllers/auth"
	"github.com/vald3mare/Rudstock/auth/internal/dummycloak"
	sessionStore "github.com/vald3mare/Rudstock/auth/internal/dummycloak/storage/session"
	userStore "github.com/vald3mare/Rudstock/auth/internal/dummycloak/storage/user"
	"github.com/vald3mare/Rudstock/auth/internal/dummycloak/tokens"
	authMw "github.com/vald3mare/Rudstock/auth/internal/infrastructure/middleware/auth"
	"github.com/vald3mare/Rudstock/auth/internal/platform/config"
	authRepo "github.com/vald3mare/Rudstock/auth/internal/repositories/auth"
	authSvc "github.com/vald3mare/Rudstock/auth/internal/services/auth"
)

// App собранное приложение auth: все слои связаны, наружу отдаётся только роутер.
type App struct {
	Router http.Handler
}

// NewApp собирает слои снизу вверх: keycloak -> репозиторий -> сервис -> хендлер и middleware -> роутер.
// Ошибки только от конструкторов keycloak: с неправильным секретом или сроками сервис стартовать не должен.
func NewApp(pool *pgxpool.Pool, conf *config.Config) (*App, error) {
	keycloak, err := newDummyCloak(pool, conf)
	if err != nil {
		return nil, err
	}

	authRepo := authRepo.NewAuthRepo(keycloak)
	authService := authSvc.NewAuthService(authRepo)

	authHandler := authCtrl.NewAuthHandler(authService)
	requireAuth := func(next http.Handler) http.Handler {
		return authMw.Middleware(authService, next)
	}

	return &App{
		Router: controllers.NewRouter(authHandler, requireAuth),
	}, nil
}

// Переход на настоящий Keycloak = заменить эту функцию на конструктор адаптера, остальное не меняется
func newDummyCloak(pool *pgxpool.Pool, conf *config.Config) (dummycloak.Keycloak, error) {
	emitter, err := tokens.NewEmitter([]byte(conf.JWTSecret), conf.JWTIssuer, conf.AccessTTL, conf.RefreshTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("create token emitter: %w", err)
	}

	keycloak, err := dummycloak.New(
		userStore.NewUserRepo(pool),
		sessionStore.NewSessionRepo(pool),
		emitter,
		dummycloak.Config{
			RefreshTTL:    conf.RefreshTTL,
			RefreshMaxTTL: conf.RefreshMaxTTL,
			Argon2: argon2id.Params{
				Memory:      conf.Argon2Memory,
				Iterations:  conf.Argon2Iterations,
				Parallelism: conf.Argon2Parallelism,
				SaltLength:  conf.Argon2SaltLength,
				KeyLength:   conf.Argon2KeyLength,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create keycloak: %w", err)
	}

	return keycloak, nil
}
