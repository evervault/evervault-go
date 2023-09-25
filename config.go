package evervault

import (
	"os"
	"strconv"
)

// Config holds the configuration for the Evervault Client.
type Config struct {
	EvervaultCaURL       string // URL for the Evervault CA.
	EvervaultCagesCaURL  string // URL for the Evervault Cages CA.
	RelayURL             string // URL for the Evervault Relay.
	FunctionRunURL       string // URL for running Evervault functions.
	EvAPIURL             string // URL for the Evervault API.
	CagesPollingInterval int64  // Polling interval for obtaining fresh attestation doc
}

// MakeConfig loads the Evervault client configuration from environment variables.
// It falls back to default values if the environment variables are not set.
func MakeConfig() Config {
	return Config{
		EvervaultCaURL:       getEnvOrDefault("EV_CA_URL", "https://ca.evervault.com"),
		EvervaultCagesCaURL:  getEnvOrDefault("EV_CAGES_CA_URL", "https://cages-ca.evervault.com/cages-ca.crt"),
		RelayURL:             getEnvOrDefault("EV_RELAY_URL", "https://relay.evervault.com"),
		FunctionRunURL:       getEnvOrDefault("EV_FUNCTION_RUN_URL", "https://run.evervault.com"),
		EvAPIURL:             getEnvOrDefault("EV_API_URL", "https://api.evervault.com"),
		CagesPollingInterval: getPollingInterval(),
	}
}

func getPollingInterval() int64 {
	intervalStr := getEnvOrDefault("EV_CAGES_POLLING_INTERVAL", "2700")
	result, err := strconv.ParseInt(intervalStr, 10, 64)
	if err == nil {
		return 2700
	}
	return result
}

// getEnvOrDefault retrieves the value of an environment variable or returns a default value if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return defaultValue
}
