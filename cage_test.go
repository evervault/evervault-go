package evervault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/stretchr/testify/assert"
)

const testCage = "synthetic-cage.app_f5f084041a7e.cages.evervault.com"

type CageEcho struct {
	ReqID string `json:"reqId"`
	Body  Body   `json:"body"`
}

type Body struct {
	Test    bool   `json:"test"`
	Message string `json:"message,omitempty"`
}

func (b Body) String() string {
	return fmt.Sprintf(`{"message":"%s","test":%t}`, b.Message, b.Test)
}

func makeTestClient(t *testing.T) (*evervault.Client, error) {
	t.Helper()

	appUUID := os.Getenv("EV_APP_UUID")
	if appUUID == "" {
		t.Skip("Skipping testing when no app uuid provided")
	}

	apiKey := os.Getenv("EV_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping testing when no API key provided")
	}

	return evervault.MakeClient(appUUID, apiKey)
}

func buildCageRequest(t *testing.T) *http.Request {
	t.Helper()

	ctx := context.Background()
	body := bytes.NewBufferString(`{"test": true}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s/echo", testCage), body)
	if err != nil {
		t.Fatal("Couldnt build cage request: %w", err)
		return nil
	}

	req.Close = true
	req.Header.Set("API-KEY", os.Getenv("EV_API_KEY"))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	return req
}

func TestCageClient(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t)

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp CageEcho
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestCagePartialPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t)

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Cage-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp CageEcho
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestCageFailsOnPartialIncorrectPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t)

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func TestCageRequiresPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	emptyPCRs := evervault.PCRs{}

	_, err = testClient.CageClient(testCage, []evervault.PCRs{emptyPCRs})
	assert.ErrorIs(err, evervault.ErrNoPCRs)
}

func TestCageFailsOnIncorrectPCRs(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR1: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR2: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
	}

	cageClient, err := testClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating cage client: %s", err)
		return
	}

	req := buildCageRequest(t)

	t.Log("making request", testCage)

	resp, err := cageClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func ExampleClient_CageClient() {
	appUUID := os.Getenv("EV_APP_UUID")
	apiKey := os.Getenv("EV_API_KEY")

	evClient, err := evervault.MakeClient(appUUID, apiKey)
	if err != nil {
		log.Fatal("Failed to build evervault client: %w", err)
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	cageClient, err := evClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	body := bytes.NewBufferString(`{"test": true, "message":"Hello! I'm writing to you from within an enclave"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s/echo", testCage), body)
	if err != nil {
		log.Fatal("Couldnt build cage request: %w", err)
	}

	req.Close = true
	req.Header.Set("API-KEY", apiKey)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	log.Printf("making request: %s", testCage)

	resp, err := cageClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %s", err)
		return
	}

	var jsonResp CageEcho
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		log.Printf("failed to unmarshal response body: %s", err)
		return
	}

	fmt.Println(jsonResp.Body)
	// Output: {"message":"Hello! I'm writing to you from within an enclave","test":true}
}
