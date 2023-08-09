package evervault_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

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
		cvv    string
		expiry string
	}

	stringType := reflect.TypeOf("")

	floatType := reflect.TypeOf(1.0)

	res, err := testClient.Decrypt(EncryptedCardData{"ev:abc123", "ev:def456", "ev:ghi789"})
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

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

func TestCreateClientSideDecryptToken(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	type EncryptedCardData struct {
		number string
		cvv string
		expiry string
	}

	expiry := time.Now()
	res, err := testClient.CreateClientSideDecryptToken(EncryptedCardData{"4242", "111", "01/23"}, expiry)

	if err != nil {
		t.Errorf("error creating decrypt token %s", err)
		return
	}
	
	if res.Token != "abcdefghij1234567890" {
		t.Errorf("Expected token, got %s", res.Token)
	}

	if res.Expiry != expiry.UnixMilli() {
		t.Errorf("Expected expiry, got %d", res.Expiry)
	}
}

func TestEncryptString(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.Encrypt("plaintext")
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	if !isValidEncryptedString(res, datatypes.String) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptInt(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.Encrypt(123)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	if !isValidEncryptedString(res, datatypes.Number) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptBoolean(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.Encrypt(true)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	if !isValidEncryptedString(res, datatypes.Boolean) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptByte(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.Encrypt([]byte("plaintext"))
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

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
		return
	}

	_, err = evervault.MakeCustomClient("test_api_key", "", evervault.MakeConfig())
	if err.Error() != evervault.ErrAppCredentialsRequired.Error() {
		t.Errorf("Unexpected error, got error message %s", err)
	}
}

func testFuncHandler(writer http.ResponseWriter, reader *http.Request, mockResponse map[string]any) {
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
	if err := json.NewEncoder(writer).Encode(responseBody); err != nil {
		log.Printf("error encoding json: %s", err)
	}
}

func handleRoute(writer http.ResponseWriter, reader *http.Request, mockResponse map[string]any) {
	if reader.URL.Path == "/test_function" {
		testFuncHandler(writer, reader, mockResponse)
	}

	if reader.URL.Path == "/v2/functions/test_function/run-token" {
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(evervault.RunTokenResponse{Token: "test_token"}); err != nil {
			log.Printf("error encoding json: %s", err)
		}
	}

	if reader.URL.Path == "/decrypt" {
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/json")

		returnData := map[string]interface{}{
			"number": "4242424242424242",
			"cvv":    123,
			"expiry": "01/24",
		}

		if err := json.NewEncoder(writer).Encode(returnData); err != nil {
			log.Printf("error encoding json: %s", err)
		}
	}

	if reader.URL.Path == "/client-side-tokens" {
		writer.WriteHeader(http.StatusOK)
		writer.Header().Set("Content-Type", "application/json")

		var body map[string]any
		err := json.NewDecoder(reader.Body).Decode(&body)

		if err != nil {
			log.Printf("error decoding body: %s", err)
		}

		returnData := map[string]interface{}{
			"token": "abcdefghij1234567890",
			"expiry": body["expiry"],
		}

		if err := json.NewEncoder(writer).Encode(returnData); err != nil {
			log.Printf("error encoding json: %s", err)
		}
	}
}

func hasSpecialPath(path string) bool {
	specialPaths := map[string]bool {
		"/test_function": true,
		"/v2/functions/test_function/run-token": true,
		"/decrypt": true,
		"/client-side-tokens": true,
	}
	if specialPaths[path] {
		return true
	}
	return false
}

func startMockHTTPServer(mockResponse map[string]any) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		if hasSpecialPath(reader.URL.Path) {
			handleRoute(writer, reader, mockResponse)
			return
		}

		ephemeralECDHCurve := ecdh.P256()

		ephemeralECDHKey, err := ephemeralECDHCurve.GenerateKey(rand.Reader)
		if err != nil {
			log.Printf("error generating key: %s", err)
		}

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
		if err := json.NewEncoder(writer).Encode(keys); err != nil {
			log.Printf("error encoding json: %s", err)
		}
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
