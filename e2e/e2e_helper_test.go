package e2e_test

import (
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/stretchr/testify/require"
)


func GetClient(t *testing.T) *evervault.Client {
	t.Helper()

	if testing.Short() {
		t.Skip("short was provided when running the test command. Skipping e2e tests.")
	}

	appUUID := os.Getenv("EV_APP_UUID")

	apiKey := os.Getenv("EV_API_KEY")

	client, err := evervault.MakeClient(appUUID, apiKey)
	require.NoError(t, err)

	return client
}