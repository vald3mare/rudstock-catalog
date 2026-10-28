package card

import (
	"net/http"

	"github.com/vald3mare/rudstock-platform/httpx"
)

// POST /admin/cards
func (h *AdminCardHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req CreateCardRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	id, err := h.svc.Create(r.Context(), req.toInput())
	if err != nil {
		httpx.WriteError(w, r, mapCardError(err))
		return
	}

	httpx.WriteJSON(w, r, http.StatusCreated, CreateCardResponse{CardID: id})
}
