// Copyright (c) 2025 dev7a
// SPDX-License-Identifier: MIT

// Package asmauthextension provides an OpenTelemetry Collector extension for
// authenticating HTTP requests using credentials stored in AWS Secrets Manager.
//
// This extension adds headers to outgoing HTTP requests based on secrets
// retrieved from AWS Secrets Manager. It supports automatic refresh of
// credentials, fallback headers, and AWS IAM role assumption.
package asmauthextension // import "github.com/dev7a/otelcol-ext-asmauth"
