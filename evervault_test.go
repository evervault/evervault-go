//go:build unit_test
// +build unit_test

package evervault_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"time"

	"strings"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/internal/crypto"
	"github.com/evervault/evervault-go/internal/datatypes"
)

func TestDecryptString(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("decrypted", "")
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

	server := startMockHTTPServer(123, "")
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

	server := startMockHTTPServer(1.1, "")
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

	server := startMockHTTPServer(true, "")
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

	server := startMockHTTPServer("Hello World!", "")
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

func TestCreateClientSideDecryptToken(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
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

	server := startMockHTTPServer("", "")
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

func TestEncryptStringWithRole(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptStringWithDataRole("plaintext", "role")
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

	server := startMockHTTPServer("", "")
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

func TestEncryptIntWithRole(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptIntWithDataRole(123, "role")
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

	server := startMockHTTPServer("", "")
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

func TestEncryptFloat64WithRole(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptFloat64WithDataRole(1.1, "role")
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

	server := startMockHTTPServer("", "")
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

func TestEncryptBooleanWithRole(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptBoolWithDataRole(true, "role")
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

	server := startMockHTTPServer("", "")
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

func TestEncryptByteWithRole(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
	defer server.Close()

	testClient := mockedClient(t, server)

	res, err := testClient.EncryptByteArrayWithDataRole([]byte("plaintext"), "role")
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

	server := startMockHTTPServer("", "")
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

func testFuncHandler(writer http.ResponseWriter, reader *http.Request, mockResponse interface{}) {
	apiKey := reader.Header.Get("API-KEY")
	authHeader := reader.Header.Get("Authorization")

	if apiKey == "" && authHeader == "" {
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")

	// Handle mockResponse based on its type
	switch v := mockResponse.(type) {
	case []byte:
		writer.Write(v) // mockResponse is already []byte
	case string:
		writer.Write([]byte(v)) // Convert string to []byte
	default:
		// For other types, use JSON encoding
		if err := json.NewEncoder(writer).Encode(mockResponse); err != nil {
			log.Printf("error encoding json: %s", err)
		}
	}
}

func handleRoute(writer http.ResponseWriter, reader *http.Request, mockResponse interface{}, contentType string) {
	if reader.URL.Path == "/functions/test_function/runs" {
		// Pass mockResponse directly to testFuncHandler if it uses mockResponse
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
		// Set default content type if not specified
		if contentType == "" {
			contentType = "application/json"
		}
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(http.StatusOK)

		// Handle the response based on type
		switch v := mockResponse.(type) {
		case string:
			writer.Write([]byte(fmt.Sprintf("\"%s\"", v)))
		case int, int32, int64:
			writer.Write([]byte(fmt.Sprintf("%d", v))) // Write integers as numbers
		case float32, float64:
			writer.Write([]byte(fmt.Sprintf("%f", v))) // Write floats as numbers
		case bool:
			writer.Write([]byte(fmt.Sprintf("%t", v))) // Write booleans as true/false
		default:
			// Fallback to JSON encoding if none of the above types match
			if contentType == "application/json" {
				if err := json.NewEncoder(writer).Encode(mockResponse); err != nil {
					log.Printf("error encoding json: %s", err)
				}
			} else {
				writer.Write([]byte(fmt.Sprintf("%v", v))) // Write as string for unknown types
			}
		}
		return
	}

	if reader.URL.Path == "/client-side-tokens" {
		if contentType == "" {
			contentType = "application/json"
		}
		writer.Header().Set("Content-Type", contentType)
		writer.WriteHeader(http.StatusOK)

		var body map[string]interface{}

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
		"/functions/test_function/runs":         true,
		"/v2/functions/test_function/run-token": true,
		"/decrypt":                              true,
		"/client-side-tokens":                   true,
	}

	return specialPaths[path]
}

func startMockHTTPServer(mockResponse interface{}, contentType string) *httptest.Server {
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
