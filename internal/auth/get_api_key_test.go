package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got: %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
	}{
		{
			name:    "no scheme",
			headers: http.Header{"Authorization": []string{"apikey"}},
		},
		{
			name:    "wrong scheme",
			headers: http.Header{"Authorization": []string{"Bearer 12345"}},
		},
		{
			name:    "missing token",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
		},
		{
			name:    "empty value",
			headers: http.Header{"Authorization": []string{""}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := GetAPIKey(tc.headers)
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
		})
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"ApiKey 12345"},
	}
	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got != "12345" {
		t.Fatalf("expected \"12345\", got: %q", got)
	}
}
