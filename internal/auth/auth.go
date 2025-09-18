package auth

import (
	"errors"
	"net/http"
	"strings"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey extracts the API key from the Authorization header.
// Expected format: "ApiKey <key>"
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}

	// Use Fields instead of Split to handle multiple spaces safely
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || parts[0] != "ApiKey" || parts[1] == "" {
		return "", errors.New(" authorization header")
	}

	return parts[1], nil
}
