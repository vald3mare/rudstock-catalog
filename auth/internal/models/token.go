package models

import "github.com/google/uuid"

// Tokens пара, которую выдаёт keycloak на register/login/refresh.
type Tokens struct {
	Access  string
	Refresh string
}

// Identity кто пришёл: то, что keycloak достаёт из валидного access-токена (CheckExpire).
type Identity struct {
	UserID    uuid.UUID
	Role      Role
	SessionID uuid.UUID
}
