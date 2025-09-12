//go:build unit_test
// +build unit_test

package evervault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutboundClientRoutesToOutboundRelay(t *testing.T) {
	t.Parallel()

	targetURL := "http://testtarget.com/"
	mockRelayServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.String(), targetURL) {
			t.Errorf("Expected request to %s, got %s", targetURL, r.URL.String())
		}
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/json")

		err := json.NewEncoder(writer).Encode("OK")
		require.NoError(t, err)
	}))

	defer mockRelayServer.Close()

	server := startMockHTTPServer("", "")
	testClient := mockedClient(t, server)

	relayClient, err := testClient.OutboundRelayClient()
	require.NoError(t, err)

	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	require.NoError(t, err)

	resp, err := relayClient.Do(req)
	require.NoError(t, err)

	assert.Equal(t, resp.StatusCode, http.StatusOK)

	resp.Body.Close()
}
