package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Refresh генерирует refresh-токен: raw отдаётся клиенту, hash (sha256) кладётся в sessions.token_hash
func (t *token) Refresh() (raw string, hash []byte, err error) {
	b := make([]byte, t.refreshSize)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}

	raw = base64.RawURLEncoding.EncodeToString(b)

	return raw, t.HashRefresh(raw), nil
}

// HashRefresh sha256 от refresh-токена: по нему сервис ищет сессию, когда клиент присылает raw.
func (t *token) HashRefresh(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
