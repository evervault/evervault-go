# Evervault Go SDK

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
