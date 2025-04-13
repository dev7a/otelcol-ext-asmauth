# AWS Secrets Manager Authenticator Extension

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
- `header_prefix` (optional): The prefix used to identify which keys in the secret should be used as headers. Only keys with this prefix will be used as headers, with the prefix stripped. Default: "header_". If set to an empty string, all keys will be used as headers.
- `header_key` (optional): The key in the secret that contains a string in the format of OTEL_EXPORTER_OTLP_HEADERS (e.g., "api-key=key,other-config-value=value"). If specified, headers will be extracted from this string. Can be used alongside `header_prefix`, in which case headers from `header_key` take precedence for any overlapping header names.

## Example Configurations

### Using header_prefix (Default Approach)

```yaml
extensions:
  asmauthextension:
    region: us-west-2
    secret_name: my-api-headers
    refresh_interval: 5m
    header_prefix: "header_"
    fallback_headers:
      User-Agent: otel-collector
    assume_role:
      arn: arn:aws:iam::123456789012:role/my-role
      sts_region: us-east-1

service:
  extensions: [asmauthextension]
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [otlphttp/with_auth]

exporters:
  otlphttp/with_auth:
    endpoint: https://api.example.com/v1/traces
    auth:
      authenticator: asmauthextension
```

### Using header_key

```yaml
extensions:
  asmauthextension:
    region: us-west-2
    secret_name: my-api-headers
    refresh_interval: 5m
    header_key: "otlp_headers"
    fallback_headers:
      User-Agent: otel-collector

service:
  extensions: [asmauthextension]
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [otlphttp/with_auth]

exporters:
  otlphttp/with_auth:
    endpoint: https://api.example.com/v1/traces
    auth:
      authenticator: asmauthextension
```

### Using Both Approaches

```yaml
extensions:
  asmauthextension:
    region: us-west-2
    secret_name: my-api-headers
    refresh_interval: 5m
    header_prefix: "header_"
    header_key: "otlp_headers"
    fallback_headers:
      User-Agent: otel-collector

service:
  extensions: [asmauthextension]
  pipelines:
    traces:
      receivers: [otlp]
      processors: []
      exporters: [otlphttp/with_auth]

exporters:
  otlphttp/with_auth:
    endpoint: https://api.example.com/v1/traces
    auth:
      authenticator: asmauthextension
```

## Secret Format

The secret in AWS Secrets Manager must be a JSON object with string values. There are two ways to specify headers:

### 1. Using header_prefix (Default)

With this approach, keys in the secret that have the specified prefix will be used as headers:

```json
{
  "header_X-API-Key": "your-api-key",
  "header_Authorization": "Bearer your-token",
  "header_Custom-Header": "custom-value",
  "other_key": "This will not be sent as a header"
}
```

With the default `header_prefix` configuration, only the keys with the "header_" prefix will be used as headers, with the prefix stripped. The headers sent to the API would be:
- X-API-Key: your-api-key
- Authorization: Bearer your-token
- Custom-Header: custom-value

### 2. Using header_key

Alternatively, you can specify a single key that contains a string in the OTEL_EXPORTER_OTLP_HEADERS format:

```json
{
  "otlp_headers": "api-key=your-api-key,Authorization=Bearer your-token,Custom-Header=custom-value",
  "other_data": "This will not be used for headers"
}
```

With `header_key: "otlp_headers"`, the extension will parse the value of the "otlp_headers" key and extract the headers. The headers sent to the API would be the same as in the previous example.

### Using Both Approaches

You can also use both approaches together. If there are overlapping header names, the values from `header_key` will take precedence:

```json
{
  "otlp_headers": "api-key=value1,X-Custom=value2",
  "header_X-Custom": "value3",
  "header_Authorization": "Bearer token"
}
```

With both `header_key: "otlp_headers"` and `header_prefix: "header_"`, the headers sent would be:
- api-key: value1 (from header_key)
- X-Custom: value2 (from header_key, takes precedence over header_prefix)
- Authorization: Bearer token (from header_prefix)

## AWS Authentication

This extension uses the default AWS SDK credentials chain. It can authenticate using:

1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
2. Shared credentials file (~/.aws/credentials)
3. EC2 Instance Profile or ECS Task Role
4. Other methods supported by the AWS SDK

You can also use the `assume_role` configuration to assume an IAM role with different permissions.

## Example Use Cases

This extension is useful when:

1. You need to authenticate HTTP exporters with API keys or tokens
2. You want to centrally manage your authentication credentials in AWS Secrets Manager
3. You need to securely rotate credentials without restarting the collector
4. You're migrating from environment variable-based configuration (using `header_key` with the OTEL_EXPORTER_OTLP_HEADERS format)
5. You need to share header configurations between different systems that use different formats

## Auto-Refresh Behavior

The extension automatically refreshes the credentials from AWS Secrets Manager based on the configured `refresh_interval`. If the extension fails to retrieve the secret during a refresh, it will:

1. Log a warning
2. Continue using the previously retrieved credentials
3. If no credentials were previously retrieved, use the fallback headers if provided

## Compatibility

This extension version **v0.2.0** is designed to be compatible with **OpenTelemetry Collector v0.119.0**.

Using it with earlier or later Collector versions may require adjustments or may not be supported.

## Development

### Prerequisites

- Go 1.24 or later
- Git

### Setup and Testing

1. **Clone the repository**
   ```bash
   git clone https://github.com/dev7a/otelcol-ext-asmauth.git
   cd otelcol-ext-asmauth
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Generate metadata files**
   ```bash
   # First, install the mdatagen tool with the appropriate version
   go get go.opentelemetry.io/collector/cmd/mdatagen@v0.119.0
   
   # Then run the generator
   go run go.opentelemetry.io/collector/cmd/mdatagen ./metadata.yaml
   
   # Or use the Makefile
   make generate
   ```
   
   This will generate several files:
   - documentation.md
   - generated_component_test.go
   - generated_package_test.go
   - internal/metadata/* files
   
   > **NOTE:** Make sure to use the mdatagen version that matches your collector's version to avoid compatibility issues. The example above uses v0.119.0.

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
