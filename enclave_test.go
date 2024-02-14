//go:build unit_test
// +build unit_test

package evervault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/attestation"
	"github.com/stretchr/testify/assert"
)

const enclave = "synthetic-cage.app-f5f084041a7e.enclave.evervault.com"

type Echo struct {
	ReqID string `json:"reqId"`
	Body  Body   `json:"body"`
}

func buildEnclaveRequest(t *testing.T, testEnclave string) *http.Request {
	t.Helper()

	ctx := context.Background()
	body := bytes.NewBufferString(`{"test": true}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://%s/echo", testEnclave), body)
	if err != nil {
		t.Fatal("Couldnt build enclave request: %w", err)
		return nil
	}

	req.Close = true
	req.Header.Set("API-KEY", os.Getenv("EV_ENCLAVE_API_KEY"))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	return req
}

func TestEnclaveClient(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := attestation.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	client, err := testClient.EnclaveClient(enclave, []attestation.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating enclave client: %s", err)
		return
	}

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp Echo
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestEnclavePartialPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := attestation.PCRs{
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	enclaveClient, err := testClient.EnclaveClient(enclave, []attestation.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating enclave client: %s", err)
		return
	}

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := enclaveClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp Echo
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestEnclavePartialPCRProvider(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	enclaveClient, err := testClient.EnclaveClientWithProvider(enclave, GetPCRData)
	if err != nil {
		t.Errorf("Error creating enclave client: %s", err)
		return
	}

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := enclaveClient.Do(req)
	if err != nil {
		t.Errorf("Error making request: %s", err)
		return
	}

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Errorf("failed to read response body: %s", err)
		return
	}

	var jsonResp Echo
	if err = json.Unmarshal(respBody, &jsonResp); err != nil {
		t.Errorf("failed to unmarshal response body: %s", err)
		return
	}

	assert.Equal(jsonResp.Body.Test, true)
}

func TestEnclaveFailsOnPartialIncorrectPCRProvider(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	enclaveClient, err := testClient.EnclaveClientWithProvider(enclave, GetInvalidPCRData)
	if err != nil {
		t.Errorf("Error creating enclave client: %s", err)
		return
	}

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := enclaveClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func TestEnclaveFailsOnPartialIncorrectPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	expectedPCRs := attestation.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	enclaveClient, err := testClient.EnclaveClient(enclave, []attestation.PCRs{expectedPCRs})
	if err != nil {
		t.Errorf("Error creating enclave client: %s", err)
		return
	}

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := enclaveClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	assert.ErrorIs(err, evervault.ErrAttestionFailure)
}

func TestEnclaveRequiresPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	if err != nil {
		t.Errorf("Error creating evervault client: %s", err)
		return
	}

	_, err = testClient.EnclaveClient(enclave, []attestation.PCRs{})
	assert.ErrorIs(err, evervault.ErrNoPCRs)
}
