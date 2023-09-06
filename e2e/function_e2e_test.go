//+build e2e

package e2e_test

import (
	"os"
	"testing"
)

var functionName string = os.Getenv("EV_FUNCTION_NAME")

type MyData struct {
	Name string `json:"name"`
	Age int `json:"age"`
	IsAlive bool `json:"isAlive"`
}

type payload struct {
	Name string `json:"name"`
	Age string `json:"age"`
	IsAlive string `json:"isAlive"`
}

func TestE2EFunctionRunWithToken(t *testing.T) {
	t.Parallel()

	client := GetClient(t)

	data := MyData{"John Doe", 42, true}

	encrypted, err := client.Encrypt(data.Name)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	payload := payload{}

	payload.Name = encrypted

	encrypted, err = client.Encrypt(data.Age)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	payload.Age = encrypted

	encrypted, err = client.Encrypt(data.IsAlive)
	if err != nil {
		t.Errorf("error encrypting data %s", err)
		return
	}

	payload.IsAlive = encrypted

	token, err := client.CreateFunctionRunToken(functionName, data)
	if err != nil {
		t.Errorf("error creating token %s", err)
		return
	}

	runResult, err := client.RunFunction(functionName, data, token.Token)
	if err != nil {
		t.Errorf("error running function %s", err)
		return
	}

	if runResult.Result["message"] != "OK" {
		t.Errorf("Unexpected function run response %s", runResult.Result["message"])
		return
	}

}