package evervault_test

import (
	"strings"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/internal/datatypes"
)

func TestEncryptString(t *testing.T) {
	t.Parallel()

	mocks := makeMockedClient(t, nil)
	defer mocks.Close()

	res, err := mocks.client.Encrypt("plaintext")
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

	mocks := makeMockedClient(t, nil)
	defer mocks.Close()

	res, err := mocks.client.Encrypt(123)
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

	mocks := makeMockedClient(t, nil)
	defer mocks.Close()

	res, err := mocks.client.Encrypt(true)
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

	mocks := makeMockedClient(t, nil)
	defer mocks.Close()

	res, err := mocks.client.Encrypt([]byte("plaintext"))
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
