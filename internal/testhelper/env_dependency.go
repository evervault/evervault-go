package testhelper

import (
	"os"
	"testing"
)

func LoadRequiredEnvVar(envName string, t *testing.T) string {
	t.Helper()

	envVar, isSet := os.LookupEnv(envName)

	if !isSet {
		t.Errorf("Required env var %s is not set.", envName)
	}

	return envVar
}
