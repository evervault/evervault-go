package e2e_test

import (
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/internal/testhelper"
	"github.com/stretchr/testify/require"
)


func GetClient(t *testing.T) *evervault.Client {
	t.Helper()

	if testing.Short() {
		t.Skip("short was provided when running the test command. Skipping e2e tests.")
	}

	appUUID := testhelper.LoadRequiredEnv(t, "EV_APP_UUID")

	apiKey := testhelper.LoadRequiredEnv(t, "EV_API_KEY")

	client, err := evervault.MakeClient(appUUID, apiKey)
	require.NoError(t, err)

	return client
}