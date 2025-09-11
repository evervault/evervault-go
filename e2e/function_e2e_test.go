package e2e_test

import (
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestE2EFunctionRun(t *testing.T) {
	t.Parallel()

	client := GetClient(t)
	functionName := testhelper.LoadRequiredEnvVar("EV_FUNCTION_NAME", t)

	encryptedPayload := map[string]any{}

	encrypted, err := client.EncryptString("hello")
	require.NoError(t, err)
	
	encryptedPayload["String"] = encrypted

	encrypted, err = client.EncryptInt(1)
	require.NoError(t, err)

	encryptedPayload["Integer"] = encrypted

	encrypted, err = client.EncryptFloat64(1.5)
	require.NoError(t, err)

	encryptedPayload["Float"] = encrypted

	encrypted, err = client.EncryptBool(true)
	require.NoError(t, err)

	encryptedPayload["True"] = encrypted

	encrypted, err = client.EncryptBool(false)
	require.NoError(t, err)

	encryptedPayload["False"] = encrypted

	runResult, err := client.RunFunction(functionName, encryptedPayload)
	require.NoError(t, err)

	if runResult.Status != "success" {
		t.Errorf("Expected success, got %s", runResult.Status)
	}

	assert.Equal(t, "string", runResult.Result["String"])
	assert.Equal(t, "number", runResult.Result["Integer"])
	assert.Equal(t, "number", runResult.Result["Float"])
	assert.Equal(t, "boolean", runResult.Result["True"])
	assert.Equal(t, "boolean", runResult.Result["False"])
}

func TestE2EFunctionRunWithError(t *testing.T) {
	t.Parallel()

	client := GetClient(t)
	functionName := testhelper.LoadRequiredEnvVar("EV_FUNCTION_NAME", t)

	payload := map[string]any{"shouldError": true}

	_, err := client.RunFunction(functionName, payload)
	if runtimeError, ok := err.(evervault.FunctionRuntimeError); !ok {
		t.Error("Expected FunctionRuntimeError, got", err)
	} else {
		assert.Equal(t, "User threw an error", runtimeError.ErrorBody.Message)
	}
}

func TestE2EFunctionRunWithInitializationError(t *testing.T) {
	t.Parallel()

	client := GetClient(t)
	initializationErrorFunctionName := testhelper.LoadRequiredEnvVar("EV_INITIALIZATION_ERROR_FUNCTION_NAME", t)

	payload := map[string]any{}

	_, err := client.RunFunction(initializationErrorFunctionName, payload)
	if runtimeError, ok := err.(evervault.FunctionRuntimeError); !ok {
		t.Error("Expected FunctionRuntimeError, got", err)
	} else {
		assert.Equal(t, "The function failed to initialize. This error is commonly encountered when there are problems with the function code (e.g. a syntax error) or when a required import is missing.", runtimeError.ErrorBody.Message)
	}
}
