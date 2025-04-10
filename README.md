# AWS Secrets Manager Authenticator Extension (ASMAuth)

The AWS Secrets Manager authenticator extension enables authentication for HTTP requests using credentials stored in AWS Secrets Manager. This extension adds headers to outgoing HTTP requests based on secrets retrieved from AWS Secrets Manager.

## Configuration

The following configuration options are available:

- `region` (optional): The AWS region where the secret is stored. If not specified, the region from the default AWS configuration chain will be used.
- `secret_name` (required): The name of the secret in AWS Secrets Manager.
- `assume_role` (optional): Configuration for assuming an IAM role.
  - `arn` (optional): The Amazon Resource Name (ARN) of the role to assume.
  - `sts_region` (optional): The AWS region where the STS endpoint will be used. If not specified, the region from the default AWS configuration chain will be used.
- `fallback_headers` (optional): Headers to use if the secret cannot be retrieved.
- `refresh_interval` (optional): The interval at which the secret will be refreshed. Default: 1 minute.

## Example Configuration

```yaml
extensions:
  asmauth:
    region: us-west-2
    secret_name: my-api-headers
    refresh_interval: 5m
    fallback_headers:
      User-Agent: otel-collector
    assume_role:
      arn: arn:aws:iam::123456789012:role/my-role
      sts_region: us-east-1

service:
  extensions: [asmauth]
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [otlphttp/with_auth]

exporters:
  otlphttp/with_auth:
    endpoint: https://api.example.com/v1/traces
    auth:
      authenticator: asmauth
```

## Secret Format

The secret in AWS Secrets Manager must be a JSON object with string values. For example:

```json
{
  "X-API-Key": "your-api-key",
  "Authorization": "Bearer your-token",
  "Custom-Header": "custom-value"
}
```

## AWS Authentication

This extension uses the default AWS SDK credentials chain. It can authenticate using:

1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. Shared credentials file (~/.aws/credentials)
3. EC2 Instance Profile or ECS Task Role
4. Other methods supported by the AWS SDK

You can also use the `assume_role` configuration to assume an IAM role with different permissions.

## Example Use Case

This extension is useful when:

1. You need to authenticate HTTP exporters with API keys or tokens
2. You want to centrally manage your authentication credentials in AWS Secrets Manager
3. You need to securely rotate credentials without restarting the collector

## Auto-Refresh Behavior

The extension automatically refreshes the credentials from AWS Secrets Manager based on the configured `refresh_interval`. If the extension fails to retrieve the secret during a refresh, it will:

1. Log a warning
2. Continue using the previously retrieved credentials
3. If no credentials were previously retrieved, use the fallback headers if provided

## Development

### Prerequisites

- Go 1.24 or later
- Git

### Setup and Testing

1. **Clone the repository**
   ```bash
   git clone https://github.com/dev7a/asmauthextension.git
   cd asmauthextension
   ```

2. **Install dependencies**
   ```bash
   go mod download
   go get go.opentelemetry.io/collector/cmd/mdatagen
   go get github.com/dev7a/asmauthextension
   go get -t github.com/dev7a/asmauthextension/...
   ```

3. **Generate metadata files**
   ```bash
   go run go.opentelemetry.io/collector/cmd/mdatagen ./metadata.yaml
   ```
   This will generate several files:
   - documentation.md
   - generated_component_test.go
   - generated_package_test.go
   - internal/metadata/* files

4. **Build the extension**
   ```bash
   go build ./...
   ```

5. **Run tests**
   ```bash
   go test ./...
   ```

Alternatively, you can use the provided Makefile:
```bash
# Download dependencies
make deps

# Generate metadata files
make generate

# Build the extension
make build

# Run tests
make test
```
