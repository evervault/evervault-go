package evervault

import (
	"os"
)

type Config struct {
	evervaultCaURL string
	relayURL       string
	functionRunURL string
	evAPIURL       string
}

func MakeConfig() Config {
	caURL := os.Getenv("EV_CA_URL")
	if caURL == "" {
		caURL = "https://ca.evervault.com"
	}

	evAPIURL := os.Getenv("EV_API_URL")
	if evAPIURL == "" {
		evAPIURL = "https://api.evervault.com"
	}

	evFunctionRun := os.Getenv("EV_FUNCTION_RUN_URL")
	if evFunctionRun == "" {
		evFunctionRun = "https://run.evervault.com"
	}

	evRelayURL := os.Getenv("EV_RELAY_URL")
	if evRelayURL == "" {
		evRelayURL = "https://relay.evervault.com"
	}

	return Config{
		evervaultCaURL: caURL,
		relayURL:       evRelayURL,
		functionRunURL: evFunctionRun,
		evAPIURL:       evAPIURL,
	}
}
