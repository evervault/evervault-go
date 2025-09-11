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
		t.Skip("Skipping e2e tests as short flag was provided")
	}

	appUUID := testhelper.LoadRequiredEnvVar("EV_APP_UUID", t)

	apiKey := testhelper.LoadRequiredEnvVar("EV_API_KEY", t)

	client, err := evervault.MakeClient(appUUID, apiKey)
	require.NoError(t,err)

	return client
}