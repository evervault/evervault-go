package evervault_test

import "testing"

func TestGetFunctionRunToken(t *testing.T) {
	t.Parallel()

	server := startMockHTTPServer(nil)
	defer server.Close()
	testClient := mockedClient(t, server)

	res, _ := testClient.CreateFunctionRunToken("test_function", "test_payload")

	if res.Token != "test_token" {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestRunFunctionWithRunToken(t *testing.T) {
	t.Parallel()

	functionResponsePayload := map[string]interface{}{
		"appUuid": "app_89a080d2228e",
		"result": map[string]interface{}{
			"message": "Hello from a Function! It seems you have 4 letters in your name",
			"name":    "ev:z6CVgEMXL2eqh0io:A4K51eCnhkHkwJ5GiZs9pOGvsWQJv4MBdckQ5rPjm/O7:FgbRc2CYwxuuzFmyh86mTKQ/ah0=:$",
		},
		"runId": "func_run_65bc5168cb8b",
	}
	server := startMockHTTPServer(functionResponsePayload)

	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]any{
		"name": "john",
		"age":  30,
	}
	runToken := "test_token"

	res, _ := testClient.RunFunction("test_function", payload, runToken)
	if res.AppUUID != functionResponsePayload["appUuid"] {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}

func TestRunFunctionWithApiKey(t *testing.T) {
	t.Parallel()

	functionResponsePayload := map[string]interface{}{
		"appUuid": "app_89a080d2228e",
		"result": map[string]any{
			"message": "Hello from a Function! It seems you have 4 letters in your name",
			"name":    "ev:z6CVgEMXL2eqh0io:A4K51eCnhkHkwJ5GiZs9pOGvsWQJv4MBdckQ5rPjm/O7:FgbRc2CYwxuuzFmyh86mTKQ/ah0=:$",
		},
		"runId": "func_run_65bc5168cb8b",
	}

	server := startMockHTTPServer(functionResponsePayload)

	defer server.Close()

	testClient := mockedClient(t, server)
	payload := map[string]interface{}{
		"name": "john",
		"age":  30,
	}

	res, _ := testClient.RunFunction("test_function", payload, "")
	if res.AppUUID != functionResponsePayload["appUuid"] {
		t.Errorf("Expected encrypted string, got %s", res)
	}
}
