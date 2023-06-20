package evervault_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

func TestDecrypt(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	type EncryptedCardData struct {
		number string
		cvv string
		expiry string
	}

	var stringType = reflect.TypeOf("")
	var floatType = reflect.TypeOf(1.0)

	res, _ := testClient.Decrypt(EncryptedCardData{"ev:abc123", "ev:def456", "ev:ghi789"})
	if reflect.TypeOf(res["number"]) != stringType {
		t.Errorf("Expected encrypted string, got %s", res["number"])
	}
	if reflect.TypeOf(res["cvv"]) != floatType {
		t.Errorf("Expected encrypted string, got %s", res["cvv"])
	}
	if reflect.TypeOf(res["expiry"]) != stringType {
		t.Errorf("Expected encrypted string, got %s", res["expiry"])
	}
}

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

	if err.Error() != evervault.ErrAPIKeyRequired.Error() {
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

func TestRunFunction(t *testing.T) {
	t.Parallel()

	functionResponsePayload := []byte("{\"name\": \"ev:fdfksjdfksjdfjsdfsf\", \"age\": \"ev:dfkjsdfkjsdfjsdfjsdf\"}")
	server := startMockHTTPServer(functionResponsePayload)

	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]interface{}{
		"name": "john",
		"age":  30,
	}
	runToken := "test_token"

	res, _ := testClient.RunFunction("test_function", payload, runToken)
	if string(res.Result) != string(functionResponsePayload) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func startMockHTTPServer(mockResponse []byte) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		if reader.URL.Path == "/test_function" {
			writer.WriteHeader(http.StatusOK)
			writer.Header().Set("Content-Type", "application/json")
			responseBody := evervault.FunctionRunResponse{
				AppUUID: "test_app_uuid",
				RunID:   "func_jksf93423df",
				Result:  mockResponse,
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

		if reader.URL.Path == "/decrypt" {
			writer.WriteHeader(http.StatusOK)
			writer.Header().Set("Content-Type", "application/json")

			returnData := map[string]interface{}{
				"number": "4242424242424242",
				"cvv": 123,
				"expiry": "01/24",
			}
			json.NewEncoder(writer).Encode(returnData)
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
