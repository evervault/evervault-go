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
//   - FunctionRunResponse.AppUUID of app that was run
//   - FunctionRunResponse.RunID for Function exacution can be used to see logs for function
//   - FunctionRunResponse.Result if the returned from the Function itself.
type FunctionRunResponse struct {
	AppUUID string         `json:"appUuid"`
	RunID   string         `json:"runId"`
	Result  map[string]any `json:"result"`
}

// Passing the name of your Evervault Function along with the data to be sent to that
// function will invoke a function in your Evervault App. The response from the function
// will be returned as a FunctionRunResponse.
func (c *Client) RunFunction(functionName string, payload any, runToken string) (FunctionRunResponse, error) {
	functionResponse, err := c.runFunction(functionName, payload, runToken)
	if err != nil {
		return FunctionRunResponse{}, err
	}

	return functionResponse, nil
}

func (c *Client) createRunToken(functionName string, payload any) (RunTokenResponse, error) {
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return RunTokenResponse{}, fmt.Errorf("Error parsing payload as json %w", err)
	}

	runTokenURL := fmt.Sprintf("%s/v2/functions/%s/run-token", c.Config.EvAPIURL, functionName)

	runToken, err := c.makeRequest(runTokenURL, http.MethodPost, pBytes, "")
	if err != nil {
		return RunTokenResponse{}, err
	}

	res := RunTokenResponse{}
	if err := json.Unmarshal(runToken, &res); err != nil {
		return RunTokenResponse{}, fmt.Errorf("Error parsing JSON response %w", err)
	}

	return res, nil
}

func (c *Client) runFunction(functionName string, payload any, runToken string) (FunctionRunResponse, error) {
	pBytes, err := json.Marshal(payload)
	if err != nil {
		return FunctionRunResponse{}, fmt.Errorf("Error parsing payload as json %w", err)
	}

	runFunctionURL := fmt.Sprintf("%s/%s", c.Config.FunctionRunURL, functionName)

	resp, err := c.makeRequest(runFunctionURL, http.MethodPost, pBytes, runToken)
	if err != nil {
		return FunctionRunResponse{}, err
	}

	functionRunResponse := FunctionRunResponse{}
	if err := json.Unmarshal(resp, &functionRunResponse); err != nil {
		return FunctionRunResponse{}, fmt.Errorf("Error parsing JSON response %w", err)
	}

	return functionRunResponse, nil
}
