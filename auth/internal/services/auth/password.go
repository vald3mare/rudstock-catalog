package auth

import "unicode"

func isStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasLetter, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	return hasLetter && hasDigit && hasSpecial
}
