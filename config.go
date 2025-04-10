// Copyright (c) 2025 dev7a
// SPDX-License-Identifier: MIT

package asmauthextension // import "github.com/dev7a/otelcol-ext-asmauth"

import (
	"errors"
	"time"
)

var errNoSecretName = errors.New("secret_name must be specified")

// Config defines the configuration for the AWS Secrets Manager authenticator extension.
type Config struct {
	// Region is the AWS region where the secret is stored.
	// If not specified, the region from the default AWS configuration chain will be used.
	Region string `mapstructure:"region"`

	// SecretName is the name of the secret in AWS Secrets Manager.
	// Required.
	SecretName string `mapstructure:"secret_name"`

	// AssumeRole contains the configuration for assuming an IAM role.
	AssumeRole AssumeRoleConfig `mapstructure:"assume_role"`

	// FallbackHeaders are headers to use if the secret cannot be retrieved.
	// Optional.
	FallbackHeaders map[string]string `mapstructure:"fallback_headers"`

	// RefreshInterval is the interval at which the secret will be refreshed.
	// Default: 1 minute
	RefreshInterval time.Duration `mapstructure:"refresh_interval"`

	// ClientAuth indicates whether this extension should be used as an auth.Client.
	// Default: true
	ClientAuth bool `mapstructure:"client_auth"`
}

// AssumeRoleConfig contains the configuration for assuming an IAM role.
type AssumeRoleConfig struct {
	// ARN is the Amazon Resource Name (ARN) of the role to assume.
	ARN string `mapstructure:"arn"`

	// STSRegion is the AWS region where the STS endpoint will be used.
	// Default: region from the default AWS configuration chain.
	STSRegion string `mapstructure:"sts_region"`
}

// Validate validates the configuration.
func (cfg *Config) Validate() error {
	if cfg.SecretName == "" {
		return errNoSecretName
	}

	// Set default refresh interval if not specified
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = time.Minute
	}

	// Default to client auth if not specified
	if !cfg.ClientAuth {
		cfg.ClientAuth = true
	}

	return nil
}

// IsClientAuth returns whether this extension should be used as an auth.Client.
func (cfg *Config) IsClientAuth() bool {
	return cfg.ClientAuth
}
