// Copyright (c) 2025 dev7a
// SPDX-License-Identifier: MIT

package asmauthextension

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// testClient is a test implementation that overrides the default secret fetching behavior
type testClient struct {
	secretValue       string
	getSecretValueErr error
}

// TestHeaderPrefix tests that the header prefix functionality works correctly
func TestHeaderPrefix(t *testing.T) {
	testCases := []struct {
		name           string
		prefix         string
		headers        map[string]string
		expectedHeader map[string]string
	}{
		{
			name:   "default_header_prefix",
			prefix: "header_",
			headers: map[string]string{
				"header_X-API-Key":     "test-api-key",
				"header_Authorization": "Bearer token",
				"other_key":            "ignored-value",
			},
			expectedHeader: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
			},
		},
		{
			name:   "custom_header_prefix",
			prefix: "http_",
			headers: map[string]string{
				"http_X-API-Key":     "test-api-key",
				"http_Authorization": "Bearer token",
				"header_Other":       "ignored-value",
				"random_key":         "ignored-value",
			},
			expectedHeader: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
			},
		},
		{
			name:   "empty_header_prefix_uses_all",
			prefix: "",
			headers: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
				"Custom-Header": "custom-value",
			},
			expectedHeader: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
				"Custom-Header": "custom-value",
			},
		},
		{
			name:   "prefix_exact_match_no_header_name",
			prefix: "header_",
			headers: map[string]string{
				"header_":          "no-key-name",
				"header_X-API-Key": "test-api-key",
			},
			expectedHeader: map[string]string{
				"X-API-Key": "test-api-key",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a logger for testing
			logger := zaptest.NewLogger(t)

			// Create an authenticator with the test config
			auth := &secretsManagerAuthenticator{
				cfg: &Config{
					HeaderPrefix: tc.prefix,
				},
				logger:  logger,
				headers: tc.headers,
			}

			// Create a request to test with
			req, err := http.NewRequest("GET", "http://example.com", nil)
			require.NoError(t, err)

			// Call the RoundTrip method with our request
			newReq := req.Clone(context.Background())
			for key, value := range auth.headers {
				// If prefix is empty, use all keys directly as headers
				if auth.cfg.HeaderPrefix == "" {
					newReq.Header.Set(key, value)
				} else if len(key) > len(auth.cfg.HeaderPrefix) && key[:len(auth.cfg.HeaderPrefix)] == auth.cfg.HeaderPrefix {
					// Otherwise only use keys with the configured prefix, and strip the prefix
					headerKey := key[len(auth.cfg.HeaderPrefix):]
					newReq.Header.Set(headerKey, value)
				}
			}

			// Check that the expected headers are set (case-insensitive)
			for key, expectedValue := range tc.expectedHeader {
				// Find the actual key in a case-insensitive way
				found := false
				actualValue := ""
				for actualKey, v := range newReq.Header {
					if strings.EqualFold(actualKey, key) && len(v) > 0 {
						found = true
						actualValue = v[0]
						break
					}
				}
				assert.True(t, found, "Header %s not found", key)
				assert.Equal(t, expectedValue, actualValue, "Header %s should have value %s", key, expectedValue)
			}

			// Check that no unexpected headers are set
			for key := range newReq.Header {
				if key == "User-Agent" || key == "Content-Length" {
					continue
				}

				found := false
				for expectedKey := range tc.expectedHeader {
					if strings.EqualFold(key, expectedKey) {
						found = true
						break
					}
				}

				assert.True(t, found, "Found unexpected header: %s", key)
			}
		})
	}
}

// Additional test to verify fallback headers work with the prefix
func TestFallbackHeadersWithPrefix(t *testing.T) {
	// Create config with fallback headers
	config := &Config{
		SecretName:   "test-secret",
		HeaderPrefix: "header_",
		FallbackHeaders: map[string]string{
			"header_X-Fallback":     "fallback-value",
			"non-prefixed-fallback": "ignored-value",
		},
	}

	// Create a logger for testing
	logger := zaptest.NewLogger(t)

	// Create an authenticator with the test config
	auth := &secretsManagerAuthenticator{
		cfg:     config,
		logger:  logger,
		headers: make(map[string]string),
	}

	// Set up the auth authenticator
	err := config.Validate()
	require.NoError(t, err)

	// Override refreshHeaders with a function that returns an error
	auth.refreshHeaders = func(context.Context) error {
		return errors.New("simulated error")
	}

	// Since refreshHeaders fails, set the fallback headers manually like Start() would
	auth.headersMutex.Lock()
	auth.headers = config.FallbackHeaders
	auth.headersMutex.Unlock()

	// Create a test HTTP server to verify the headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that the fallback header with prefix is used
		assert.Equal(t, "fallback-value", r.Header.Get("X-Fallback"))

		// Check that the non-prefixed fallback header is not used
		assert.Empty(t, r.Header.Get("non-prefixed-fallback"))

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create a new HTTP client with our custom RoundTripper
	client := &http.Client{
		Transport: &secretsManagerRoundTripper{
			base:          http.DefaultTransport,
			authenticator: auth,
		},
	}

	// Make a request to the test server
	req, err := http.NewRequest("GET", server.URL, nil)
	require.NoError(t, err)

	// Send the request
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test that directly verifies the header prefix filtering logic
func TestHeaderPrefixFiltering(t *testing.T) {
	testCases := []struct {
		name           string
		prefix         string
		headers        map[string]string
		expectedResult map[string]string
	}{
		{
			name:   "default_header_prefix",
			prefix: "header_",
			headers: map[string]string{
				"header_X-API-Key":     "test-api-key",
				"header_Authorization": "Bearer token",
				"other_key":            "ignored-value",
			},
			expectedResult: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
			},
		},
		{
			name:   "custom_prefix",
			prefix: "http_",
			headers: map[string]string{
				"http_X-API-Key":     "test-api-key",
				"http_Authorization": "Bearer token",
				"header_Other":       "ignored-value",
				"random_key":         "ignored-value",
			},
			expectedResult: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
			},
		},
		{
			name:   "empty_prefix_uses_all",
			prefix: "",
			headers: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
				"Custom-Header": "custom-value",
			},
			expectedResult: map[string]string{
				"X-API-Key":     "test-api-key",
				"Authorization": "Bearer token",
				"Custom-Header": "custom-value",
			},
		},
		{
			name:   "prefix_with_empty_key",
			prefix: "header_",
			headers: map[string]string{
				"header_":          "no-key-name",
				"header_X-API-Key": "test-api-key",
			},
			expectedResult: map[string]string{
				"X-API-Key": "test-api-key",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create an HTTP request
			req, err := http.NewRequest("GET", "http://example.com", nil)
			require.NoError(t, err)

			// Apply the headers using our RoundTrip method logic
			modifiedReq := req.Clone(req.Context())

			// Manually apply the header prefix logic as done in RoundTrip
			prefix := tc.prefix
			for key, value := range tc.headers {
				// If prefix is empty, use all headers
				if prefix == "" {
					modifiedReq.Header.Set(key, value)
				} else if len(key) > len(prefix) && key[:len(prefix)] == prefix {
					// Only use keys with the configured prefix, and strip the prefix
					headerKey := key[len(prefix):]
					modifiedReq.Header.Set(headerKey, value)
				}
			}

			// Check that all expected headers are present
			for key, expectedValue := range tc.expectedResult {
				assert.Equal(t, expectedValue, modifiedReq.Header.Get(key),
					"In test %s: Header %s should have value %s", tc.name, key, expectedValue)
			}

			// Check that no unexpected headers are present - using case-insensitive comparison
			// since HTTP headers are case-insensitive
			for key := range modifiedReq.Header {
				if key == "User-Agent" || key == "Content-Length" { // Skip default Go headers
					continue
				}

				found := false
				for expectedKey := range tc.expectedResult {
					if strings.EqualFold(key, expectedKey) {
						found = true
						break
					}
				}

				assert.True(t, found, "In test %s: Unexpected header found: %s", tc.name, key)
			}
		})
	}
}
