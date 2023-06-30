package evervault_test

import (
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
		json.NewEncoder(writer).Encode("OK")
	}))

	defer mockRelayServer.Close()

	server := startMockHTTPServer(nil)

	testClient := mockedClient(t, server)

	relayClient, _ := testClient.OutboundRelayClient()

	resp, _ := relayClient.Get(targetURL)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	resp.Body.Close()
}
