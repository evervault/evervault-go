[![Evervault](https://evervault.com/evervault.svg)](https://evervault.com/)

# Evervault Go SDK

[![Go Report Card][go-reportcard-badge]][go-reportcard]
[![Go Reference][pkg.go.dev-badge]][pkg.go.dev]

For up to date usage docs please refer to
[Evervault docs](https://docs.evervault.com/sdks/go) and
[godocs](https://pkg.go.dev/github.com/evervault/evervault-go)

## Testing

### Required Env

Currently, a significant number of the tests rely on credentials or resource identifiers that are not included in this repo.

The list of required env vars is:
- `EV_APP_UUID` - a valid Evervault app uuid
- `EV_API_KEY` - an Evervault API Key with `function:invoke` and relay authenticate
- `EV_ENCLAVE_API_KEY` - an Evervault Enclave API Key with `enclave:invoke`
- `EV_SYNTHETIC_ENDPOINT_URL` - an existing Relay destination for the given app
- `EV_INITIALIZATION_ERROR_FUNCTION_NAME` - the name of a function which will fail when invoked
- `EV_FUNCTION_NAME` - the name of a function which will run when invoked

### Running the Tests

To run all tests in the sdk:

```bash
go test -v -count=1 -race ./...
```

To run unit tests only:

```bash
go test -v -count=1 --short -race ./...
```

## Linting

Linting is run on all PR with `golangci-lint`.

To test locally you can run

```bash
golangci-lint run ./...
```

[go-reportcard-badge]:
  https://goreportcard.com/badge/github.com/evervault/evervault-go
[go-reportcard]:
  https://goreportcard.com/report/github.com/evervault/evervault-go
[pkg.go.dev-badge]:
  https://pkg.go.dev/badge/github.com/evervault/evervault-go.svg
[pkg.go.dev]: https://pkg.go.dev/github.com/evervault/evervault-go
