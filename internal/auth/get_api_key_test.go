package auth

import (
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	headers := make(map[string][]string)
	headers["Authorization"] = []string{"ApiKey test-api-key"}

	key, err := GetAPIKey(headers)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if key == "" {
		t.Error("Expected API key to be set, got empty string")
	}
}

func TestGetAPIKeyNoAuthHeader(t *testing.T) {
	headers := make(map[string][]string)

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Error("Expected error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error to be %v, got %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKeyMalformedAuthHeader(t *testing.T) {
	headers := make(map[string][]string)
	headers["Authorization"] = []string{"MalformedHeader"}

	_, err := GetAPIKey(headers)

	if err == nil {
		t.Error("Expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Errorf("Expected error to be 'malformed authorization header', got %v", err)
	}
}
