package e2e

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
)

func TestEncryptString(t *testing.T) {
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

	if payload != decrypted.(string) {
		t.Errorf("decrypted data does not match the original")
		return
	}
}

func TestEncryptBoolTrue(t *testing.T) {
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

func TestEncryptBoolFalse(t *testing.T) {
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

func TestEncryptInt(t *testing.T) {
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

func TestEncryptFloat(t *testing.T) {
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

func TestEncryptBytes(t *testing.T) {
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

	if string(payload) != decrypted.(string) {
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

func TestEncryptStruct(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := MyStruct{"hello world", 1, 1.5, true, false}

	// Encrypt doesn't handle structs - convert to bytes first
	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(payload)

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

	// Convert bytes back to struct
	data := MyStruct{}
    json.Unmarshal([]byte(decrypted.(string)), &data)

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
	appUuid := os.Getenv("EV_APP_UUID")
	apiKey := os.Getenv("EV_API_KEY")

	client, err := evervault.MakeClient(appUuid, apiKey)
	if err != nil {
		t.Fail()
	}

	return client
}