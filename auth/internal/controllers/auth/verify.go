package auth

import (
	"net/http"

	authmw "github.com/vald3mare/Rudstock/auth/internal/infrastructure/middleware/auth"
	"github.com/vald3mare/Rudstock/auth/internal/platform/errs"
	"github.com/vald3mare/Rudstock/auth/internal/platform/httpx"
)

func (h *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	identity, ok := authmw.IdentityFrom(r.Context())
	if !ok {
		// ручку повесили без middleware: это ошибка сборки роутера, а не клиента
		httpx.WriteError(w, r, errs.Internal("identity-missing", "Internal server error", nil))
		return
	}

	w.Header().Set("X-User-Id", identity.UserID.String())
	w.Header().Set("X-User-Role", string(identity.Role))
	w.Header().Set("X-Session-Id", identity.SessionID.String())

	httpx.WriteJSON(w, r, http.StatusOK, toVerifyResponse(identity))
}
