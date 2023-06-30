package evervault_test

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
)

func TestCageClient(t *testing.T) {
	t.Parallel()

	apiKey := os.Getenv("EV_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping testing when no API key provided")
	}

	appUUID := os.Getenv("EV_APP_UUID")
	if appUUID == "" {
		t.Skip("Skipping testing when no app uuid provided")
	}

	testClient, err := evervault.MakeClient(apiKey, appUUID)
	if err != nil {
		t.Errorf("Unexpected error, got error message %s", err)
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "2f1d96a6a897cf7b9d15f2198355ac4cf13ab1b5e4f06b249e5b91bb3e1637b8d6d071f29c64ce89825a5b507c6656a9",
		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		PCR2: "64c193500432b8e551e82438b3636ddc0ca43413e9bcf75112e3074e9f97e62260ff5835f763bfd6b32aa55d6e3d8474",
		PCR8: "8da2e6c5b1d3c885a586014345cdcd4dbc078938f6f8694b84ed197a3d2ab3be1c5e78b52d18ae6a88d188fa37864497",
	}

	cageClient, err := testClient.CageClient(
		"hello-cage-2.app_89a080d2228e.cages.evervault.com:443", []evervault.PCRs{expectedPCRs},
	)
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://hello-cage-2.app_89a080d2228e.cages.evervault.com/hello", nil)
	req.Close = true
	req.Header.Set("API-KEY", "<API_KEY>")

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
	}

	defer resp.Body.Close()
	fmt.Println(resp)
}
