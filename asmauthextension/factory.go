// Copyright (c) 2025 dev7a
// SPDX-License-Identifier: MIT

package asmauthextension // import "github.com/dev7a/otelcol-ext-asmauth"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

const (
	// The value of extension "type" in configuration.
	typeStr = "asmauthextension"
	// The stability level of the extension.
	stability = component.StabilityLevelBeta
)

// NewFactory creates a factory for the AWS Secrets Manager authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType(typeStr),
		createDefaultConfig,
		createExtension,
		stability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		RefreshInterval: time.Minute,
	}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	config := cfg.(*Config)

	// For client auth, use CreateClientAuth which returns auth.Client
	if config.IsClientAuth() {
		return CreateClientAuth(config, set.Logger)
	}

	// For regular extension, use newAuthenticator which returns extension.Extension
	return newAuthenticator(config, set.Logger)
}
