package evervault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/attestation"
	"github.com/evervault/evervault-go/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err)

	req.Close = true
	req.Header.Set("API-KEY", testhelper.LoadRequiredEnvVar("EV_ENCLAVE_API_KEY", t))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	return req
}

func TestEnclaveClient(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	require.NoError(t, err)

	expectedPCRs := attestation.PCRs{
		PCR0: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR1: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR2: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	client, err := testClient.EnclaveClient(enclave, []attestation.PCRs{expectedPCRs})
	require.NoError(t, err)

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var jsonResp Echo
	err = json.Unmarshal(respBody, &jsonResp)
	require.NoError(t, err)

	assert.Equal(jsonResp.Body.Test, true)
}

func TestEnclavePartialPCR(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	require.NoError(t, err)

	expectedPCRs := attestation.PCRs{
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	enclaveClient, err := testClient.EnclaveClient(enclave, []attestation.PCRs{expectedPCRs})
	require.NoError(t, err)

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := enclaveClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var jsonResp Echo
	err = json.Unmarshal(respBody, &jsonResp)
	require.NoError(t, err)

	assert.Equal(jsonResp.Body.Test, true)
}

func TestEnclavePartialPCRProvider(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	require.NoError(t, err)

	enclaveClient, err := testClient.EnclaveClientWithProvider(enclave, GetPCRData)
	require.NoError(t, err)

	req := buildEnclaveRequest(t, enclave)

	t.Log("making request", enclave)

	resp, err := enclaveClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal("200 OK", resp.Status)
	assert.Contains(resp.Header, "X-Evervault-Ctx")

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var jsonResp Echo
	err = json.Unmarshal(respBody, &jsonResp)
	require.NoError(t, err)

	assert.Equal(jsonResp.Body.Test, true)
}

func TestEnclaveFailsOnPartialIncorrectPCRProvider(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)

	testClient, err := makeTestClient(t)
	require.NoError(t, err)

	enclaveClient, err := testClient.EnclaveClientWithProvider(enclave, GetInvalidPCRData)
	require.NoError(t, err)

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
	require.NoError(t, err)

	expectedPCRs := attestation.PCRs{
		PCR0: "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
		PCR8: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	enclaveClient, err := testClient.EnclaveClient(enclave, []attestation.PCRs{expectedPCRs})
	require.NoError(t, err)

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
	require.NoError(t, err)

	_, err = testClient.EnclaveClient(enclave, []attestation.PCRs{})
	assert.ErrorIs(err, evervault.ErrNoPCRs)
}
