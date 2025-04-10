// Copyright (c) 2025 dev7a
// SPDX-License-Identifier: MIT

package asmauthextension // import "github.com/dev7a/otelcol-ext-asmauth"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/auth"
	"go.uber.org/zap"
	"google.golang.org/grpc/credentials"
)

var (
	errSecretNotFound    = errors.New("secret not found in Secrets Manager")
	errInvalidSecretData = errors.New("invalid secret data: must be a JSON object with string values")
)

// secretsManagerAuthenticator implements the extension.Extension interface
type secretsManagerAuthenticator struct {
	component.StartFunc
	component.ShutdownFunc

	cfg          *Config
	logger       *zap.Logger
	client       *secretsmanager.Client
	headers      map[string]string
	headersMutex sync.RWMutex
	ticker       *time.Ticker
	done         chan struct{}

	// refreshHeaders is the function that fetches and updates headers
	// It's a field to allow overriding in tests
	refreshHeaders func(context.Context) error
}

// newAuthenticator creates a new secretsManagerAuthenticator extension
func newAuthenticator(cfg *Config, logger *zap.Logger) (extension.Extension, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	auth := &secretsManagerAuthenticator{
		cfg:     cfg,
		logger:  logger,
		headers: make(map[string]string),
		done:    make(chan struct{}),
	}

	// Set up the default refreshHeaders implementation
	auth.refreshHeaders = auth.fetchHeadersFromAWS

	return auth, nil
}

// Start initializes the AWS client and fetches the initial secret
func (a *secretsManagerAuthenticator) Start(ctx context.Context, _ component.Host) error {
	awsConfig, err := a.loadAWSConfig(ctx)
	if (err != nil) {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	a.client = secretsmanager.NewFromConfig(awsConfig)

	// Fetch initial headers
	if err := a.refreshHeaders(ctx); err != nil {
		a.logger.Warn("Failed to load initial headers from Secrets Manager, using fallback headers",
			zap.Error(err))
		// Use fallback headers if provided
		if a.cfg.FallbackHeaders != nil {
			a.headersMutex.Lock()
			a.headers = a.cfg.FallbackHeaders
			a.headersMutex.Unlock()
		}
	}

	// Start refresh ticker
	a.ticker = time.NewTicker(a.cfg.RefreshInterval)
	go a.refreshLoop(ctx)

	return nil
}

// Shutdown stops the secret refresh loop
func (a *secretsManagerAuthenticator) Shutdown(context.Context) error {
	if a.ticker != nil {
		a.ticker.Stop()
	}
	close(a.done)
	return nil
}

// loadAWSConfig loads the AWS configuration with optional role assumption
func (a *secretsManagerAuthenticator) loadAWSConfig(ctx context.Context) (aws.Config, error) {
	var options []func(*config.LoadOptions) error

	if a.cfg.Region != "" {
		options = append(options, config.WithRegion(a.cfg.Region))
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return aws.Config{}, err
	}

	// Configure role assumption if requested
	if a.cfg.AssumeRole.ARN != "" {
		stsClient := sts.NewFromConfig(awsConfig, func(o *sts.Options) {
			if a.cfg.AssumeRole.STSRegion != "" {
				o.Region = a.cfg.AssumeRole.STSRegion
			}
		})

		provider := stscreds.NewAssumeRoleProvider(stsClient, a.cfg.AssumeRole.ARN)
		awsConfig.Credentials = aws.NewCredentialsCache(provider)
	}

	return awsConfig, nil
}

// refreshLoop periodically refreshes the headers from Secrets Manager
func (a *secretsManagerAuthenticator) refreshLoop(ctx context.Context) {
	for {
		select {
		case <-a.ticker.C:
			if err := a.refreshHeaders(ctx); err != nil {
				a.logger.Warn("Failed to refresh headers from Secrets Manager", zap.Error(err))
			}
		case <-a.done:
			return
		}
	}
}

// fetchHeadersFromAWS fetches and updates the authentication headers from Secrets Manager
func (a *secretsManagerAuthenticator) fetchHeadersFromAWS(ctx context.Context) error {
	if a.client == nil {
		return errors.New("AWS client not initialized")
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(a.cfg.SecretName),
	}

	result, err := a.client.GetSecretValue(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to get secret value: %w", err)
	}

	if result.SecretString == nil {
		return errSecretNotFound
	}

	var headers map[string]string
	if err := json.Unmarshal([]byte(*result.SecretString), &headers); err != nil {
		return fmt.Errorf("%w: %w", errInvalidSecretData, err)
	}

	a.headersMutex.Lock()
	a.headers = headers
	a.headersMutex.Unlock()

	a.logger.Debug("Successfully refreshed authentication headers from Secrets Manager")
	return nil
}

// roundTripper returns a custom RoundTripper that adds headers from Secrets Manager
func (a *secretsManagerAuthenticator) roundTripper(base http.RoundTripper) (http.RoundTripper, error) {
	return &secretsManagerRoundTripper{
		base:          base,
		authenticator: a,
	}, nil
}

// perRPCCredentials returns nil as we don't support gRPC authentication
func (a *secretsManagerAuthenticator) perRPCCredentials() (credentials.PerRPCCredentials, error) {
	// We don't support gRPC authentication
	return nil, nil
}

// secretsManagerRoundTripper is a custom http.RoundTripper that adds headers from Secrets Manager
type secretsManagerRoundTripper struct {
	base          http.RoundTripper
	authenticator *secretsManagerAuthenticator
}

// RoundTrip adds the authentication headers to the request
func (rt *secretsManagerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	newReq := req.Clone(req.Context())

	// Add headers from the authenticator
	rt.authenticator.headersMutex.RLock()
	prefix := rt.authenticator.cfg.HeaderPrefix
	for key, value := range rt.authenticator.headers {
		// If prefix is empty, use all keys directly as headers
		if prefix == "" {
			newReq.Header.Set(key, value)
		} else if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			// Otherwise only use keys with the configured prefix, and strip the prefix
			headerKey := key[len(prefix):]
			newReq.Header.Set(headerKey, value)
		}
	}
	rt.authenticator.headersMutex.RUnlock()

	// Call the base RoundTripper
	return rt.base.RoundTrip(newReq)
}

// CreateClientAuth creates an auth.Client using the secretsManagerAuthenticator
func CreateClientAuth(cfg *Config, logger *zap.Logger) (auth.Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	auth := &secretsManagerAuthenticator{
		cfg:     cfg,
		logger:  logger,
		headers: make(map[string]string),
		done:    make(chan struct{}),
	}

	// Set up the default refreshHeaders implementation
	auth.refreshHeaders = auth.fetchHeadersFromAWS

	// Use auth.NewClient with functional options
	return auth.NewClient(), nil
}

// NewClient creates a new auth.Client using functional options
func (a *secretsManagerAuthenticator) NewClient() auth.Client {
	return auth.NewClient(
		auth.WithClientRoundTripper(a.roundTripper),
		auth.WithClientPerRPCCredentials(a.perRPCCredentials),
		auth.WithClientStart(a.Start),
		auth.WithClientShutdown(a.Shutdown),
	)
}
