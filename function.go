package evervault

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Struct containing a token for Function invocation.
// RunTokenResponse.Token can be used to invoke a function run by the user.
type RunTokenResponse struct {
	Token string `json:"token"`
}

// Passing the name of your Evervault Function along with the data to be sent to that function will
// return a RunTokenResponse. This response contains a token that can be returned to your
// client for Function invocation.
func (c *Client) CreateFunctionRunToken(functionName string, payload any) (RunTokenResponse, error) {
	tokenResponse, err := c.createRunToken(functionName, payload)
	if err != nil {
		return RunTokenResponse{}, err
	}

	return tokenResponse, nil
}

// Response containing the results of a Function run.
// - FunctionRunResponse.Status contains the status of the function invocation (success/failure).
// - FunctionRunResponse.ID contains the run ID of the function invocation.
// - FunctionRunResponse.Result contains the response from the function invocation.
type FunctionRunResponse struct {
	Status string         `json:"status"`
	ID     string         `json:"id"`
	Result map[string]any `json:"result"`
}

// Passing the name of your Evervault Function along with the data to be sent to that
// function will invoke a function in your Evervault App. The response from the function
// will be returned as a FunctionRunResponse.
func (c *Client) RunFunction(functionName string, payload map[string]any) (FunctionRunResponse, error) {
	functionResponse, err := c.runFunction(functionName, payload)
	if err != nil {
		return FunctionRunResponse{}, err
	}

	return functionResponse, nil
}

func (c *Client) createRunToken(functionName string, payload any) (RunTokenResponse, error) {
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return RunTokenResponse{}, fmt.Errorf("error parsing payload as json %w", err)
	}

	runTokenURL := fmt.Sprintf("%s/v2/functions/%s/run-token", c.Config.EvAPIURL, functionName)

	response, err := c.makeRequest(runTokenURL, http.MethodPost, pBytes, false)

	if response.statusCode != http.StatusOK {
		return RunTokenResponse{}, APIError{Message: "Error making HTTP request"}
	}

	if err != nil {
		return RunTokenResponse{}, err
	}

	res := RunTokenResponse{}
	if err := json.Unmarshal(response.body, &res); err != nil {
		return RunTokenResponse{}, fmt.Errorf("error parsing JSON response %w", err)
	}

	return res, nil
}

func (c *Client) runFunction(functionName string, payload map[string]any) (FunctionRunResponse, error) {
	wrappedPayload := map[string]any{"payload": payload}

	pBytes, err := json.Marshal(wrappedPayload)
	if err != nil {
		return FunctionRunResponse{}, fmt.Errorf("error parsing payload as json %w", err)
	}

	apiURL := fmt.Sprintf("%s/functions/%s/runs", c.Config.EvAPIURL, functionName)

	response, err := c.makeRequest(apiURL, http.MethodPost, pBytes, true)
	if err != nil {
		return FunctionRunResponse{}, err
	}

	functionRunResponse := FunctionRunResponse{}
	err = json.Unmarshal(response.body, &functionRunResponse)

	if err == nil && functionRunResponse.Status == "success" {
		return functionRunResponse, nil
	} else if err == nil && functionRunResponse.Status == "failure" {
		functionRuntimeError := FunctionRuntimeError{}

		err = json.Unmarshal(response.body, &functionRuntimeError)
		if err == nil {
			return FunctionRunResponse{}, functionRuntimeError
		}
	}

	return FunctionRunResponse{}, ExtractAPIError(response.body)
}
