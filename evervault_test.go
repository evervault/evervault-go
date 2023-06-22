package evervault_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

func TestEncryptString(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, _ := testClient.Encrypt("plaintext")
	if !isValidEncryptedString(res, datatypes.String) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptInt(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, _ := testClient.Encrypt(123)
	if !isValidEncryptedString(res, datatypes.Number) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptBoolean(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, _ := testClient.Encrypt(true)
	if !isValidEncryptedString(res, datatypes.Boolean) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptByte(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, _ := testClient.Encrypt([]byte("plaintext"))
	if !isValidEncryptedString(res, datatypes.String) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestClientInitClientErrorWithoutApiKey(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	_, err := evervault.MakeClient("", "")

	if err.Error() != evervault.ErrAppCredentialsRequired.Error() {
		t.Errorf("Unexpected error, got error message %s", err)
	}

	_, err = evervault.MakeCustomClient("test_api_key", "", evervault.MakeConfig())
	if err.Error() != evervault.ErrAppCredentialsRequired.Error() {
		t.Errorf("Unexpected error, got error message %s", err)
	}
}

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

func TestGetFunctionRunToken(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()
	testClient := mockedClient(t, server)

	res, _ := testClient.CreateFunctionRunToken("test_function", "test_payload")

	if res.Token != "test_token" {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestRunFunctionWithRunToken(t *testing.T) {
	t.Parallel()

	functionResponsePayload := map[string]interface{}{
		"appUuid": "app_89a080d2228e",
		"result": map[string]interface{}{
			"message": "Hello from a Function! It seems you have 4 letters in your name",
			"name":    "ev:z6CVgEMXL2eqh0io:A4K51eCnhkHkwJ5GiZs9pOGvsWQJv4MBdckQ5rPjm/O7:FgbRc2CYwxuuzFmyh86mTKQ/ah0=:$",
		},
		"runId": "func_run_65bc5168cb8b",
	}
	server := startMockHTTPServer(functionResponsePayload)

	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{
		"name": "john",
		"age":  30,
	}
	runToken := "test_token"

	res, _ := testClient.RunFunction("test_function", payload, runToken)
	if res.AppUUID != functionResponsePayload["appUuid"] {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestRunFunctionWithApiKey(t *testing.T) {
	t.Parallel()

	functionResponsePayload := map[string]interface{}{
		"appUuid": "app_89a080d2228e",
		"result": map[string]any{
			"message": "Hello from a Function! It seems you have 4 letters in your name",
			"name":    "ev:z6CVgEMXL2eqh0io:A4K51eCnhkHkwJ5GiZs9pOGvsWQJv4MBdckQ5rPjm/O7:FgbRc2CYwxuuzFmyh86mTKQ/ah0=:$",
		},
		"runId": "func_run_65bc5168cb8b",
	}

	server := startMockHTTPServer(functionResponsePayload)

	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]interface{}{
		"name": "john",
		"age":  30,
	}

	res, _ := testClient.RunFunction("test_function", payload, "")
	if res.AppUUID != functionResponsePayload["appUuid"] {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func startMockHTTPServer(mockResponse map[string]any) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		if reader.URL.Path == "/test_function" {
			apiKey := reader.Header.Get("API-KEY")
			authHeader := reader.Header.Get("Authorization")
			if apiKey == "" && authHeader == "" {
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			writer.WriteHeader(http.StatusOK)
			writer.Header().Set("Content-Type", "application/json")
			appUUIDResponse, appUUIDOk := mockResponse["appUuid"].(string)
			if !appUUIDOk {
				appUUIDResponse = ""
			}
			runIDResposne, ok := mockResponse["runId"].(string)
			if !ok {
				runIDResposne = ""
			}
			resultResponse, ok := mockResponse["result"].(map[string]any)
			if !ok {
				resultResponse = map[string]any{}
			}
			responseBody := evervault.FunctionRunResponse{
				AppUUID: appUUIDResponse,
				RunID:   runIDResposne,
				Result:  resultResponse,
			}
			json.NewEncoder(writer).Encode(responseBody)

			return
		}

		if reader.URL.Path == "/v2/functions/test_function/run-token" {
			writer.WriteHeader(http.StatusOK)
			writer.Header().Set("Content-Type", "application/json")
			json.NewEncoder(writer).Encode(evervault.RunTokenResponse{Token: "test_token"})

			return
		}

		ephemeralECDHCurve := ecdh.P256()
		ephemeralECDHKey, _ := ephemeralECDHCurve.GenerateKey(rand.Reader)
		ephemeralPublicKey := ephemeralECDHKey.PublicKey().Bytes()
		compressedEphemeralPublicKey := crypto.CompressPublicKey(ephemeralPublicKey)
		keys := evervault.KeysResponse{
			TeamUUID:                "test_team_uuid",
			Key:                     "test_key",
			EcdhKey:                 "ras_key",
			EcdhP256Key:             base64.StdEncoding.EncodeToString(compressedEphemeralPublicKey),
			EcdhP256KeyUncompressed: base64.StdEncoding.EncodeToString(ephemeralPublicKey),
		}
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(writer).Encode(keys)
	}))

	return server
}

func mockedClient(t *testing.T, server *httptest.Server) *evervault.Client {
	t.Helper()

	config := evervault.Config{
		EvervaultCaURL: server.URL,
		EvAPIURL:       server.URL,
		FunctionRunURL: server.URL,
		RelayURL:       server.URL,
	}

	client, err := evervault.MakeCustomClient("test_api_key", "test_app_uuid", config)
	if err != nil {
		t.Fail()
	}

	return client
}

func isValidEncryptedString(encryptedString string, datatype datatypes.Datatype) bool {
	parts := strings.Split(encryptedString, ":")
	if len(parts) < 6 {
		return false
	}

	if datatype == datatypes.Number || datatype == datatypes.Boolean {
		correctDataType := parts[2] == "number" || parts[2] == "boolean"

		if len(parts) < 7 && !correctDataType {
			return false
		}
	}

	return true
}
