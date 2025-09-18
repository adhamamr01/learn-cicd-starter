package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey secret123")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	expected := "secret123"
	if apiKey != expected {
		t.Errorf("expected %q, got %q", expected, apiKey)
	}
}

func TestGetAPIKey_Errors(t *testing.T) {
	tests := []struct {
		name      string
		headerVal string
		wantErr   string
	}{
		{
			name:      "missing header",
			headerVal: "",
			wantErr:   ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:      "wrong scheme",
			headerVal: "Bearer abc123",
			wantErr:   "malformed authorization header",
		},
		{
			name:      "empty token",
			headerVal: "ApiKey ",
			wantErr:   "malformed authorization header",
		},
		{
			name:      "extra pieces",
			headerVal: "ApiKey a b",
			wantErr:   "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerVal != "" {
				headers.Set("Authorization", tt.headerVal)
			}

			_, err := GetAPIKey(headers)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("expected %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
