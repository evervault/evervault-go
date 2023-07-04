package evervault

import "os"

// Config holds the configuration for the Evervault Client.
type Config struct {
	EvervaultCaURL      string // URL for the Evervault CA.
	EvervaultCagesCaURL string // URL for the Evervault Cages CA.
	RelayURL            string // URL for the Evervault Relay.
	FunctionRunURL      string // URL for running Evervault functions.
	EvAPIURL            string // URL for the Evervault API.
}

// MakeConfig loads the Evervault client configuration from environment variables.
// It falls back to default values if the environment variables are not set.
func MakeConfig() Config {
	return Config{
		EvervaultCaURL:      getEnvOrDefault("EV_CA_URL", "https://ca.evervault.com"),
		EvervaultCagesCaURL: getEnvOrDefault("EV_CAGES_CA_URL", "https://cages-ca.evervault.com/cages-ca.crt"),
		RelayURL:            getEnvOrDefault("EV_RELAY_URL", "https://relay.evervault.com"),
		FunctionRunURL:      getEnvOrDefault("EV_FUNCTION_RUN_URL", "https://run.evervault.com"),
		EvAPIURL:            getEnvOrDefault("EV_API_URL", "https://api.evervault.com"),
	}
}

// getEnvOrDefault retrieves the value of an environment variable or returns a default value if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return defaultValue
}
