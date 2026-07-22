package testhelper

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func LoadRequiredEnv(t *testing.T, key string) string {
	value, isSet := os.LookupEnv(key)
	require.Truef(t, isSet, "Expected required env var %s to be set", key)
	return value
}