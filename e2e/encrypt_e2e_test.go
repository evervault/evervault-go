//go:build e2e
// +build e2e

package e2e_test

import (
	"os"
	"testing"

	"github.com/evervault/evervault-go"
)

func TestE2EEncryptString(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := "hello world"

	encrypted, err := client.EncryptString(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.DecryptString(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %s %s", payload, decrypted)
		return
	}
}

func TestE2EEncryptBoolTrue(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := true

	encrypted, err := client.EncryptBool(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.DecryptBool(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %t %t", payload, decrypted)
		return
	}
}

func TestE2EEncryptBoolFalse(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := false

	encrypted, err := client.EncryptBool(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.DecryptBool(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %t %t", payload, decrypted)
		return
	}
}

func TestE2EEncryptInt(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1

	encrypted, err := client.EncryptInt(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.DecryptInt(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %d %d", payload, decrypted)
		return
	}
}

func TestE2EEncryptFloat(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := 1.5

	encrypted, err := client.EncryptFloat64(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.DecryptFloat64(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if payload != decrypted {
		t.Errorf("decrypted data does not match the original %f %f", payload, decrypted)
		return
	}
}

func TestE2EEncryptBytes(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := []byte{97, 98, 99, 100, 101, 102}

	encrypted, err := client.EncryptByteArray(payload)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	decrypted, err := client.DecryptByteArray(encrypted)
	if err != nil {
		t.Errorf("error decrypting data %s", err)
		return
	}

	if string(payload) != string(decrypted) {
		t.Errorf("decrypted data does not match the original %s %s", string(payload), string(decrypted))
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
