//go:build unit_test
// +build unit_test

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
	"github.com/stretchr/testify/assert"
)

func TestDecryptString(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"result": "decrypted",
	}
	server := startMockHTTPServer(response, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	stringType := reflect.TypeOf("")

	res, err := testClient.DecryptString("ev:abc123")
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if reflect.TypeOf(res) != stringType {
		t.Errorf("Expected decrypted string, got %s", reflect.TypeOf(res))
	}
}

func TestDecryptInt(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"result": "123",
	}
	server := startMockHTTPServer(response, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	intType := reflect.TypeOf(1)

	res, err := testClient.DecryptInt("ev:abc123")
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if reflect.TypeOf(res) != intType {
		t.Errorf("Expected decrypted int, got %s", reflect.TypeOf(res))
	}
}

func TestDecryptFloat64(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"result": "1.1",
	}
	server := startMockHTTPServer(response, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	float64Type := reflect.TypeOf(1.1)

	res, err := testClient.DecryptFloat64("ev:abc123")
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if reflect.TypeOf(res) != float64Type {
		t.Errorf("Expected decrypted float64, got %s", reflect.TypeOf(res))
	}
}

func TestDecryptBoolean(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"result": "true",
	}
	server := startMockHTTPServer(response, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	booleanType := reflect.TypeOf(true)

	res, err := testClient.DecryptBool("ev:abc123")
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if reflect.TypeOf(res) != booleanType {
		t.Errorf("Expected decrypted bool, got %s", reflect.TypeOf(res))
	}
}

func TestDecryptByteArray(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"result": "Hello World!",
	}
	server := startMockHTTPServer(response, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	byteArrayType := reflect.TypeOf([]byte("Hello World!"))

	res, err := testClient.DecryptByteArray("ev:abc123")
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if reflect.TypeOf(res) != byteArrayType {
		t.Errorf("Expected decrypted byte array, got %s", reflect.TypeOf(res))
	}
}

func TestDecryptJsonResponse(t *testing.T) {
	t.Parallel()

	response := map[string]any{
		"result": "Hello World!",
	}
	server := startMockHTTPServer(response, "application/json")
	defer server.Close()

	testClient := mockedClient(t, server)

	_, err := testClient.DecryptByteArray("ev:abc123")
	assert.ErrorIs(t, err, evervault.ErrInvalidDataType)
}

func TestCreateClientSideDecryptToken(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	type EncryptedCardData struct {
		number string
		cvv    string
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

	server := startMockHTTPServer(nil, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptString("plaintext")
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

	server := startMockHTTPServer(nil, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptInt(123)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	if !isValidEncryptedString(res, datatypes.Number) {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestEncryptFloat64(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptFloat64(1.1)
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

	server := startMockHTTPServer(nil, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptBool(true)
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

	server := startMockHTTPServer(nil, "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptByteArray([]byte("plaintext"))
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

	server := startMockHTTPServer(nil, "")
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

func handleRoute(writer http.ResponseWriter, reader *http.Request, mockResponse map[string]any, contentType string) {
	if reader.URL.Path == "/test_function" {
		testFuncHandler(writer, reader, mockResponse)
		return
	}

	if reader.URL.Path == "/v2/functions/test_function/run-token" {
		if contentType == "" {
			contentType = "application/json"
		}
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(writer).Encode(evervault.RunTokenResponse{Token: "test_token"}); err != nil {
			log.Printf("error encoding json: %s", err)
		}
		return
	}

	if reader.URL.Path == "/decrypt" {
		if contentType == "" {
			contentType = "text/plain"
		}

		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte(mockResponse["result"].(string)))
		return
	}

	if reader.URL.Path == "/client-side-tokens" {
		if contentType == "" {
			contentType = "application/json"
		}
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(http.StatusOK)

		var body map[string]any

		err := json.NewDecoder(reader.Body).Decode(&body)
		if err != nil {
			log.Printf("error decoding body: %s", err)
		}

		returnData := map[string]interface{}{
			"token":  "abcdefghij1234567890",
			"expiry": body["expiry"],
		}

		if err := json.NewEncoder(writer).Encode(returnData); err != nil {
			log.Printf("error encoding json: %s", err)
		}
	}
}

func hasSpecialPath(path string) bool {
	specialPaths := map[string]bool{
		"/test_function":                        true,
		"/v2/functions/test_function/run-token": true,
		"/decrypt":                              true,
		"/client-side-tokens":                   true,
	}

	return specialPaths[path]
}

func startMockHTTPServer(mockResponse map[string]any, contentType string) *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, reader *http.Request) {
		if hasSpecialPath(reader.URL.Path) {
			handleRoute(writer, reader, mockResponse, contentType)

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
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
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
