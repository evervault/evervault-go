//go:build e2e
// +build e2e

package e2e_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/stretchr/testify/assert"
)

var functionName string = os.Getenv("EV_FUNCTION_NAME")

type Payload struct {
	String string `json:"string"`
	Integer int `json:"integer"`
	Float float64 `json:"float"`
	True bool `json:"true"`
	False bool `json:"false"`
}

func TestE2EFunctionRun(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	fmt.Println("test", os.Getenv("EV_TEST_ENV_VAR"))

	encryptedPayload := map[string]any{}

	encrypted, err := client.EncryptString("hello")
	if err != nil {
		t.Errorf("error encrypting string %s", err)
		return
	}
	encryptedPayload["String"] = encrypted

	encrypted, err = client.EncryptInt(1)
	if err != nil {
		t.Errorf("error encrypting integer %s", err)
		return
	}
	encryptedPayload["Integer"] = encrypted

	encrypted, err = client.EncryptFloat64(1.5)
	if err != nil {
		t.Errorf("error encrypting float %s", err)
		return
	}
	encryptedPayload["Float"] = encrypted

	encrypted, err = client.EncryptBool(true)
	if err != nil {
		t.Errorf("error encrypting true %s", err)
		return
	}
	encryptedPayload["True"] = encrypted

	encrypted, err = client.EncryptBool(false)
	if err != nil {
		t.Errorf("error encrypting false %s", err)
		return
	}
	encryptedPayload["False"] = encrypted

	runResult, err := client.RunFunction(functionName, encryptedPayload)
	if err != nil {
		t.Errorf("error running function %s", err)
		return
	}

	if runResult.Status != "success" {
		t.Errorf("Expected success, got %s", runResult.Status)
	}

	assert.Equal(t, runResult.Result["String"], "string")
	assert.Equal(t, runResult.Result["Integer"], "number")
	assert.Equal(t, runResult.Result["Float"], "number")
	assert.Equal(t, runResult.Result["True"], "boolean")
	assert.Equal(t, runResult.Result["False"], "boolean")
}

func TestE2EFunctionRunWithError(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	payload := map[string]any{"shouldError": true}

	_, err := client.RunFunction(functionName, payload)
	if runtimeError, ok := err.(evervault.FunctionRuntimeError); !ok {
		t.Error("Expected FunctionRuntimeError, got", err)
	} else {
		assert.Equal(t, runtimeError.ErrorBody.Message, "User threw an error")
	}
}