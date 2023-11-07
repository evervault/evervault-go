//go:build unit_test
// +build unit_test

package evervault_test

import (
	"fmt"
	"testing"

	"github.com/evervault/evervault-go"
	"github.com/evervault/evervault-go/types"
	"github.com/stretchr/testify/assert"
)

func TestGetFunctionRunToken(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer("", "")
	defer server.Close()
	testClient := mockedClient(t, server)

	res, err := testClient.CreateFunctionRunToken("test_function", "test_payload")
	if err != nil {
		t.Errorf("Failed to create run token, got %s", err)
		return
	}

	if res.Token != "test_token" {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestRunFunctionSuccess(t *testing.T) {
	t.Parallel()

	message := "Hello from a Function! It seems you have 4 letters in your name"
	id := "func_run_65bc5168cb8b"
	functionResponsePayload := fmt.Sprintf(`
	{
		"status": "success",
		"result": { "message": "%s" },
		"id": "%s"
	}`, message, id)

	server := startMockHTTPServer(functionResponsePayload, "")
	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{"name": "john", "age": 30}

	res, err := testClient.RunFunction("test_function", payload)
	if err != nil {
		t.Errorf("Failed to run Function, got %s", err)
		return
	}

	assert.Equal(t, res.Status, "success")
	assert.Equal(t, res.ID, id)
	assert.Equal(t, res.Result["message"], message)
}

func TestRunFunctionFailure(t *testing.T) {
	t.Parallel()

	message := "Uh oh!"
	stack := "Error: Uh oh!..."
	id := "func_run_65bc5168cb8b"
	functionResponsePayload := fmt.Sprintf(`
	{
		"status": "failure",
		"error": { "message": "%s", "stack": "%s" },
		"id": "%s"
	}`, message, stack, id)

	server := startMockHTTPServer(functionResponsePayload, "")
	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{"name": "john", "age": 30}

	_, err := testClient.RunFunction("test_function", payload)
	if runtimeError, ok := err.(types.FunctionRuntimeError); !ok {
		t.Error("Expected FunctionRuntimeError, got", err)
	} else {
		assert.Equal(t, runtimeError.ErrorBody.Message, message)
		assert.Equal(t, runtimeError.ErrorBody.Stack, stack)
		assert.Equal(t, runtimeError.ID, id)
	}
}

func TestRunFunctionTimeout(t *testing.T) {
	t.Parallel()

	message := "Function execution exceeded the allotted time and has timed out. Please review your code to ensure it finishes within the time limit set in function.toml."
	functionResponsePayload := fmt.Sprintf(`
	{
		"status": 408,
		"code": "functions/request-timeout",
		"title": "Function Request Timeout",
		"detail": "%s"
	}`, message)

	server := startMockHTTPServer(functionResponsePayload, "")
	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{"name": "john", "age": 30}

	_, err := testClient.RunFunction("test_function", payload)
	if functionTimeoutError, ok := err.(evervault.FunctionTimeoutError); !ok {
		t.Error("Expected FunctionTimeoutError, got", err)
	} else {
		assert.Equal(t, functionTimeoutError.Message, message)
	}
}

func TestRunFunctionNotReady(t *testing.T) {
	t.Parallel()

	message := "The Function is not ready to be invoked yet. This can occur when it hasn't been executed recently. Please try again shortly."
	functionResponsePayload := fmt.Sprintf(`
	{
		"status": 409,
		"code": "functions/function-not-ready",
		"title": "Function Not Ready",
		"detail": "%s"
	}`, message)

	server := startMockHTTPServer(functionResponsePayload, "")
	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{"name": "john", "age": 30}

	_, err := testClient.RunFunction("test_function", payload)
	if functionNotReadyError, ok := err.(evervault.FunctionNotReadyError); !ok {
		t.Error("Expected FunctionNotReadyError, got", err)
	} else {
		assert.Equal(t, functionNotReadyError.Message, message)
	}
}

func TestRunFunctionUnauthorized(t *testing.T) {
	t.Parallel()

	message := "The request cannot be authenticated. The request does not contain valid credentials. Please retry with a valid API key."
	code := "unauthorized"
	functionResponsePayload := fmt.Sprintf(`
	{
		"status": 409,
		"code": "%s",
		"title": "Unauthorized",
		"detail": "%s"
	}`, code, message)

	server := startMockHTTPServer(functionResponsePayload, "")
	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{"name": "john", "age": 30}

	_, err := testClient.RunFunction("test_function", payload)
	if evervaultError, ok := err.(evervault.APIError); !ok {
		t.Error("Expected Evervault Error, got", err)
	} else {
		assert.Equal(t, evervaultError.Code, code)
		assert.Equal(t, evervaultError.Message, message)
	}
}
