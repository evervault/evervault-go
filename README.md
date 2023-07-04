# Evervault Go SDK

[![Go Report Card][go-reportcard-badge]][go-reportcard]
[![Go Reference][pkg.go.dev-badge]][pkg.go.dev]

For up to date usage docs please refer to
[Evervault docs](https://docs.evervault.com/sdks/go) and
[godocs](https://pkg.go.dev/github.com/evervault/evervault-go)

## Testing

To Test the sdk run

```bash
go test -v -count=1 -race ./...
```

### Linting

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
