# HTTP Client & Server Utilities

This repository contains a collection of Rust crates designed to facilitate the development of HTTP clients and servers
with a focus on security, configuration management, and logging.

## Crates

### `cosmian_http_client`

A comprehensive HTTP client library with robust authentication support:

- Multiple authentication mechanisms including OAuth2
- Custom certificate verification for enhanced security
- Support for client certificates (TLS client authentication)
- Integration with Actix for session management (optional feature)
- Configurable request handling with support for different content types

### `cosmian_logger`

A flexible logging utility that simplifies tracing and telemetry:

- OpenTelemetry integration for distributed tracing
- Support for stdout, file, and syslog outputs
- Configurable log levels and formats
- Tokio runtime integration
- Metrics collection capabilities

### `cosmian_config_utils`

Utilities for managing application configuration:

- Loading configuration from various sources (files, environment variables)
- Parsing of TOML and JSON configuration formats
- URL parsing and validation
- Base64 encoding/decoding for configuration values

## Getting Started

To use these crates in your project, add them to your `Cargo.toml`:

```toml
[dependencies]
cosmian_http_client = { version = "0.5.2", features = ["session"] }
cosmian_logger = "0.5.2"
cosmian_config_utils = "0.5.2"
```

## License

This project is licensed under the Business Source License 1.1 (BUSL-1.1).

## Repository

<https://github.com/Cosmian/http_client_server>

## Authors

- Bruno Grieder <bruno.grieder@cosmian.com>
- Emmanuel Coste <emmanuel.coste@cosmian.com>
