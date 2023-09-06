//+build e2e

package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
)

func TestE2EEncryptString(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := "hello world"

	encrypted, err := client.Encrypt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	castResponse, ok := decrypted.(string)
	if !ok {
		t.Errorf("Failed type assertion")
		return
	}

	if payload != castResponse {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

func TestE2EEncryptBoolTrue(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := true

	encrypted, err := client.Encrypt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

func TestE2EEncryptBoolFalse(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := false

	encrypted, err := client.Encrypt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

func TestE2EEncryptInt(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1

	encrypted, err := client.Encrypt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	// Need to convert here, as ints are returned as floats
	if float64(payload) != decrypted {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

func TestE2EEncryptFloat(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1.5

	encrypted, err := client.Encrypt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

func TestE2EEncryptBytes(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := []byte{97, 98, 99, 100, 101, 102}

	encrypted, err := client.Encrypt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	castResponse, ok := decrypted.(string)
	if !ok {
		t.Errorf("Failed type assertion")
		return
	}

	if string(payload) != castResponse {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

type MyStruct struct {
	String string  `json:"string"`
	Int    int     `json:"int"`
	Float  float64 `json:"float"`
	True   bool    `json:"true"`
	False  bool    `json:"false"`
}

func TestE2EEncryptStruct(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := MyStruct{"hello world", 1, 1.5, true, false}

	reqBodyBytes := new(bytes.Buffer)

	err := json.NewEncoder(reqBodyBytes).Encode(payload)
	if err != nil {
		t.Fail()
	}

	encrypted, err := client.Encrypt(reqBodyBytes.Bytes())
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.Decrypt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	data := MyStruct{}

	castResponse, ok := decrypted.(string)
	if !ok {
		t.Errorf("Failed type assertion")
		return
	}

	err = json.Unmarshal([]byte(castResponse), &data)
	if err != nil {
		t.Fail()
	}

	CheckStructResponses(t, payload, data)
}

func CheckStructResponses(t *testing.T, payload MyStruct, data MyStruct) {
	t.Helper()

	if payload.String != data.String {
		t.Errorf("decrypted struct data `String` does not match the original")
		return
	}

	if payload.Int != data.Int {
		t.Errorf("decrypted struct data `Int` does not match the original")
		return
	}

	if payload.Float != data.Float {
		t.Errorf("decrypted struct data `Float` does not match the original")
		return
	}

	if payload.True != data.True {
		t.Errorf("decrypted struct data `True` does not match the original")
		return
	}

	if payload.False != data.False {
		t.Errorf("decrypted struct data `False` does not match the original")
		return
	}
}

func GetClient(t *testing.T) *evervault.Client {
	t.Helper()

	appUUID := os.Getenv("EV_APP_UUID")

	apiKey := os.Getenv("EV_API_KEY")

	client, err := evervault.MakeClient(appUUID, apiKey)
	if err != nil {
		t.Fail()
	}

	return client
}
