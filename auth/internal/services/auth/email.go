package auth

import "strings"

// normalizeEmail приводит email к виду, в котором он хранится: register и login должны искать одинаково
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
