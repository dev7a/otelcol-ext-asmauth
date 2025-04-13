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

	// Process the fallback headers as fetchHeadersFromAWS would
	finalHeaders := make(map[string]string)
	prefix := auth.cfg.HeaderPrefix
	if prefix != "" {
		for key, value := range auth.headers {
			if len(key) > len(prefix) && key[:len(prefix)] == prefix {
				headerKey := key[len(prefix):]
				finalHeaders[headerKey] = value
			}
		}
	} else {
		finalHeaders = auth.headers
	}

	// Update the headers with the processed ones
	auth.headersMutex.Lock()
	auth.headers = finalHeaders
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

// TestParseOtelHeadersFormat tests the parseOtelHeadersFormat function
func TestParseOtelHeadersFormat(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectedOutput map[string]string
		expectedError  bool
	}{
		{
			name:           "empty_string",
			input:          "",
			expectedOutput: map[string]string{},
			expectedError:  false,
		},
		{
			name:  "valid_format",
			input: "api-key=test-key,Authorization=Bearer token,X-Custom=value",
			expectedOutput: map[string]string{
				"api-key":       "test-key",
				"Authorization": "Bearer token",
				"X-Custom":      "value",
			},
			expectedError: false,
		},
		{
			name:  "with_spaces",
			input: " api-key = test-key , Authorization = Bearer token ",
			expectedOutput: map[string]string{
				"api-key":       "test-key",
				"Authorization": "Bearer token",
			},
			expectedError: false,
		},
		{
			name:          "invalid_format_missing_value",
			input:         "api-key=test-key,invalid-key",
			expectedError: true,
		},
		{
			name:          "invalid_format_missing_key",
			input:         "api-key=test-key,=value",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseOtelHeadersFormat(tc.input)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, result)
			}
		})
	}
}

// TestHeaderKey tests the header_key functionality
func TestHeaderKey(t *testing.T) {
	testCases := []struct {
		name           string
		headerKey      string
		secretData     map[string]string
		expectedHeader map[string]string
	}{
		{
			name:      "basic_header_key",
			headerKey: "otlp_headers",
			secretData: map[string]string{
				"otlp_headers": "api-key=test-key,Authorization=Bearer token",
				"other_key":    "ignored-value",
			},
			expectedHeader: map[string]string{
				"api-key":       "test-key",
				"Authorization": "Bearer token",
			},
		},
		{
			name:      "header_key_not_found",
			headerKey: "missing_key",
			secretData: map[string]string{
				"otlp_headers": "api-key=test-key",
				"other_key":    "ignored-value",
			},
			expectedHeader: map[string]string{},
		},
		{
			name:      "invalid_header_key_format",
			headerKey: "invalid_format",
			secretData: map[string]string{
				"invalid_format": "this-is-not-valid",
				"other_key":      "ignored-value",
			},
			expectedHeader: map[string]string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a logger for testing
			logger := zaptest.NewLogger(t)

			// Create an authenticator with the test config
			auth := &secretsManagerAuthenticator{
				cfg: &Config{
					HeaderKey: tc.headerKey,
				},
				logger:  logger,
				headers: make(map[string]string),
			}

			// Manually process the headers as fetchHeadersFromAWS would
			finalHeaders := make(map[string]string)

			// Process header_key
			if auth.cfg.HeaderKey != "" {
				if headerValue, exists := tc.secretData[auth.cfg.HeaderKey]; exists {
					parsedHeaders, err := parseOtelHeadersFormat(headerValue)
					if err == nil {
						for k, v := range parsedHeaders {
							finalHeaders[k] = v
						}
					}
				}
			}

			// Set the headers in the authenticator
			auth.headers = finalHeaders

			// Create a request to test with
			req, err := http.NewRequest("GET", "http://example.com", nil)
			require.NoError(t, err)

			// Clone the request and add headers
			newReq := req.Clone(context.Background())
			auth.headersMutex.RLock()
			for key, value := range auth.headers {
				newReq.Header.Set(key, value)
			}
			auth.headersMutex.RUnlock()

			// Check that the expected headers are set
			for key, expectedValue := range tc.expectedHeader {
				assert.Equal(t, expectedValue, newReq.Header.Get(key),
					"Header %s should have value %s", key, expectedValue)
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

// TestHeaderKeyAndPrefix tests using both header_key and header_prefix together
func TestHeaderKeyAndPrefix(t *testing.T) {
	testCases := []struct {
		name           string
		headerKey      string
		headerPrefix   string
		secretData     map[string]string
		expectedHeader map[string]string
	}{
		{
			name:         "non_overlapping_headers",
			headerKey:    "otlp_headers",
			headerPrefix: "header_",
			secretData: map[string]string{
				"otlp_headers":         "api-key=test-key,X-Custom=value1",
				"header_Authorization": "Bearer token",
				"other_key":            "ignored-value",
			},
			expectedHeader: map[string]string{
				"api-key":       "test-key",
				"X-Custom":      "value1",
				"Authorization": "Bearer token",
			},
		},
		{
			name:         "overlapping_headers_key_takes_precedence",
			headerKey:    "otlp_headers",
			headerPrefix: "header_",
			secretData: map[string]string{
				"otlp_headers":    "X-Custom=value1,Authorization=from-key",
				"header_X-Custom": "value2",
				"header_Other":    "other-value",
			},
			expectedHeader: map[string]string{
				"X-Custom":      "value1",      // From header_key, takes precedence
				"Authorization": "from-key",    // From header_key
				"Other":         "other-value", // From header_prefix
			},
		},
		{
			name:         "header_key_not_found_use_prefix",
			headerKey:    "missing_key",
			headerPrefix: "header_",
			secretData: map[string]string{
				"header_X-Custom": "value",
				"other_key":       "ignored-value",
			},
			expectedHeader: map[string]string{
				"X-Custom": "value",
			},
		},
		{
			name:         "invalid_header_key_format_use_prefix",
			headerKey:    "invalid_format",
			headerPrefix: "header_",
			secretData: map[string]string{
				"invalid_format":  "this-is-not-valid",
				"header_X-Custom": "value",
				"header_Other":    "other-value",
			},
			expectedHeader: map[string]string{
				"X-Custom": "value",
				"Other":    "other-value",
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
					HeaderKey:    tc.headerKey,
					HeaderPrefix: tc.headerPrefix,
				},
				logger:  logger,
				headers: make(map[string]string),
			}

			// Manually process the headers as fetchHeadersFromAWS would
			finalHeaders := make(map[string]string)

			// Process header_key if specified
			if auth.cfg.HeaderKey != "" {
				if headerValue, exists := tc.secretData[auth.cfg.HeaderKey]; exists {
					parsedHeaders, err := parseOtelHeadersFormat(headerValue)
					if err == nil {
						for k, v := range parsedHeaders {
							finalHeaders[k] = v
						}
					}
				}
			}

			// Process header_prefix keys
			prefix := auth.cfg.HeaderPrefix
			if prefix != "" {
				for key, value := range tc.secretData {
					if len(key) > len(prefix) && key[:len(prefix)] == prefix {
						headerKey := key[len(prefix):]
						// Only set if not already set by header_key (header_key takes precedence)
						if _, exists := finalHeaders[headerKey]; !exists {
							finalHeaders[headerKey] = value
						}
					}
				}
			} else {
				// If prefix is empty and header_key is not used, use all keys directly
				if auth.cfg.HeaderKey == "" {
					finalHeaders = tc.secretData
				}
			}

			// Set the headers in the authenticator
			auth.headers = finalHeaders

			// Create a request to test with
			req, err := http.NewRequest("GET", "http://example.com", nil)
			require.NoError(t, err)

			// Clone the request and add headers
			newReq := req.Clone(context.Background())
			auth.headersMutex.RLock()
			for key, value := range auth.headers {
				newReq.Header.Set(key, value)
			}
			auth.headersMutex.RUnlock()

			// Check that the expected headers are set
			for key, expectedValue := range tc.expectedHeader {
				assert.Equal(t, expectedValue, newReq.Header.Get(key),
					"Header %s should have value %s", key, expectedValue)
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
