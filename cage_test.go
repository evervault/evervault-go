package evervault_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/stretchr/testify/assert"
)

const testCage = "go-sdk-hello-cage.app_869a0605f7c3.cages.evervault.com"

func makeTestClient(t *testing.T) (*evervault.Client, error) {
	t.Helper()

	apiKey := os.Getenv("EV_API_KEY")
	if apiKey == "" {
		t.Skip("Skipping testing when no API key provided")
	}

	appUUID := os.Getenv("EV_APP_UUID")
	if appUUID == "" {
		t.Skip("Skipping testing when no app uuid provided")
	}

	return evervault.MakeClient(apiKey, appUUID)
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
		PCR0: "3a10079d879b01b011dca8d206c0b5b70c11a153ad9a44a4c178be6ae1a8b088a37e9c233284ecd46eeb36d37a3696ef",
		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		PCR2: "0aacf0c29d6832c050df0b8435bd939fc2d767dfdc3c139eabd2e281d77effd04ba88f51c1932911731934aeabff868f",
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
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

	assert.Equal(`{"message":"Hello! I'm writing to you from within an enclave","body":{"test":true}}`, string(respBody))
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
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
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

	assert.Equal(`{"message":"Hello! I'm writing to you from within an enclave","body":{"test":true}}`, string(respBody))
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
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
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
	apiKey := os.Getenv("EV_API_KEY")
	appUUID := os.Getenv("EV_APP_UUID")

	evClient, err := evervault.MakeClient(apiKey, appUUID)
	if err != nil {
		log.Fatal("Failed to build evervault client: %w", err)
	}

	expectedPCRs := evervault.PCRs{
		PCR0: "3a10079d879b01b011dca8d206c0b5b70c11a153ad9a44a4c178be6ae1a8b088a37e9c233284ecd46eeb36d37a3696ef",
		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
		PCR2: "0aacf0c29d6832c050df0b8435bd939fc2d767dfdc3c139eabd2e281d77effd04ba88f51c1932911731934aeabff868f",
		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
	}

	cageClient, err := evClient.CageClient(testCage, []evervault.PCRs{expectedPCRs})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	body := bytes.NewBufferString(`{"test": true}`)

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

	fmt.Println(string(respBody))
	// Output: {"message":"Hello! I'm writing to you from within an enclave","body":{"test":true}}
}
