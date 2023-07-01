package evervault_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/stretchr/testify/assert"
)

const testCage = "staging-synthetic-cage.app_1bba8ba15402.cages.evervault.dev"

func makeTestClient(t *testing.T) *evervault.Client {
	t.Helper()

	apiKey := os.Getenv("EV_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping testing when no API key provided")
	}

	appUUID := os.Getenv("EV_APP_UUID")
	if appUUID == "" {
		t.Skip("Skipping testing when no app uuid provided")
	}

	config := evervault.Config{
		EvAPIURL:            "https://api.evervault.io",
		EvervaultCagesCaURL: "https://cages-ca.evervault.io/cages-ca.crt",
	}

	testClient, err := evervault.MakeCustomClient(apiKey, appUUID, config)
	if err != nil {
		t.Errorf("Unexpected error, got error message %s", err)
	}

	return testClient
}

func buildCageRequest() *http.Request {
	body := []byte(`{"test": true}`)
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/echo", testCage), bytes.NewBuffer(body))
	req.Close = true
	req.Header.Set("API-KEY", os.Getenv("EV_API_KEY"))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	return req
}

func TestCageClient(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)
	testClient := makeTestClient(t)
	expectedPCRs := evervault.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
	}

	req := buildCageRequest()

	t.Log("making request")

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
	}

	defer resp.Body.Close()

	assert.Equal(resp.Status, "200 OK", "expect 200 ok")
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, _ := io.ReadAll(resp.Body)
	assert.Contains(string(respBody), `{"test":true}`)
}

func TestCageFailsOnIncorrectPCRs(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)
	testClient := makeTestClient(t)
	expectedPCRs := evervault.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR1: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR2: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
	}

	req := buildCageRequest()

	resp, err := cageClient.Do(req)
	assert.ErrorIs(err, evervault.ErrAttestionFailure)
	resp.Body.Close()
}

func Example_connectToCage() {
	apiKey := os.Getenv("EV_API_KEY")
	appUUID := os.Getenv("EV_APP_UUID")

	evClient, err := evervault.MakeClient(apiKey, appUUID)
	if err != nil {
		panic(err)
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := evClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		panic(err)
	}

	body := []byte(`{"test": true}`)
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/echo", testCage), bytes.NewBuffer(body))
	req.Close = true
	req.Header.Set("API-KEY", apiKey)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	resp, err := cageClient.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	fmt.Println(string(respBody))
	// Output: {"test": true}
}
