package testhelper

import (
	"os"
	"testing"
)

func LoadRequiredEnv(t *testing.T, key string) string {
	value, isSet := os.LookupEnv(key)
	if !isSet {
		t.Skipf("Skipping test: required env var %s is not set", key)
	}
	return value
}