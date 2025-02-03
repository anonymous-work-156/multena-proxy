package main

import (
	"net/http"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestGetBearerToken(t *testing.T) {

	log.Info().Caller().Msg("Start TestGetBearerToken().")
	defer log.Info().Msg("End TestGetBearerToken().")

	tests := []struct {
		name       string
		authHeader string
		expected   string
		expectErr  bool
	}{
		{
			name:       "no authorization header",
			authHeader: "",
			expectErr:  true,
		},
		{
			name:       "invalid authorization header",
			authHeader: "Token abc",
			expectErr:  true,
		},
		{
			name:       "valid bearer token",
			authHeader: "Bearer abc123",
			expected:   "abc123",
			expectErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{"Authorization": {tt.authHeader}}}
			got, err := trimBearerToken(r, "Authorization")
			if (err != nil) != tt.expectErr {
				t.Errorf("trimBearerToken() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if got != tt.expected {
				t.Errorf("trimBearerToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrimBearerToken(t *testing.T) {

	log.Info().Caller().Msg("Start TestTrimBearerToken().")
	defer log.Info().Msg("End TestTrimBearerToken().")

	assert := assert.New(t)

	tests := []struct {
		name          string
		headerName    string
		headerValue   string
		expectedToken string
		expectError   bool
	}{
		{
			name:          "Valid token",
			headerName:    "Authorization",
			headerValue:   "Bearer example_token",
			expectedToken: "example_token",
			expectError:   false,
		},
		{
			name:          "No Authorization header",
			headerName:    "Authorization",
			headerValue:   "",
			expectedToken: "",
			expectError:   true,
		},
		{
			name:          "Invalid Authorization header",
			headerName:    "Authorization",
			headerValue:   "totally a jwt",
			expectedToken: "",
			expectError:   true,
		},
		{
			name:          "Alternate header",
			headerName:    "Authorization2",
			headerValue:   "totally a jwt",
			expectedToken: "totally a jwt",
			expectError:   false,
		},
		{
			name:          "Token with space",
			headerName:    "Authorization",
			headerValue:   "Bearer token_with_space ",
			expectedToken: "token_with_space",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			req.Header.Set(tt.headerName, tt.headerValue)

			token, err := trimBearerToken(req, tt.headerName)

			assert.Equal(tt.expectedToken, token)

			var happy bool
			if tt.expectError {
				happy = assert.Error(err)
			} else {
				happy = assert.NoError(err)
			}

			log.Info().Bool("passed", happy).Str("name", tt.name).Msg("Auth test")
		})
	}
}
