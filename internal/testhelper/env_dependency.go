package testhelper

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func LoadRequiredEnvVar(envName string, t *testing.T) string {
	t.Helper()

	envVar := os.Getenv(envName)
	require.NotZero(t, envVar)

	return envVar
}
