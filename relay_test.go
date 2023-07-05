package evervault_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

		if err := json.NewEncoder(writer).Encode("OK"); err != nil {
			t.Errorf("Failed to encode response %s", err)
		}
	}))

	defer mockRelayServer.Close()

	mocks := makeMockedClient(t, nil)
	defer mocks.Close()

	relayClient, err := mocks.client.OutboundRelayClient()
	if err != nil {
		t.Errorf("Fialed to build oubound client, got %s", err)
		return
	}

	ctx := context.Background()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		t.Fatal("failed to build get request: %w", err)
	}

	resp, err := relayClient.Do(req)
	if err != nil {
		t.Errorf("Expected status code 200, got %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	resp.Body.Close()
}
