package auth

import (
	"net/http"

	"github.com/vald3mare/Rudstock/auth/internal/platform/httpx"
)

// POST /auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	if err := h.svc.Logout(r.Context(), req.Refresh); err != nil {
		httpx.WriteError(w, r, mapAuthError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
