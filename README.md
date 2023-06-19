# Evervault Go SDK

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
