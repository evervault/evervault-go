package evervault

import (
	"os"
)

type Config struct {
	EvervaultCaURL      string
	EvervaultCagesCaUrl string
	RelayURL            string
	FunctionRunURL      string
	EvAPIURL            string
}

func MakeConfig() Config {
	caURL := os.Getenv("EV_CA_URL")
	if caURL == "" {
		caURL = "https://ca.evervault.com"
	}

	cagesCageUrl := os.Getenv("EV_CAGES_CA_URL")
	if cagesCageUrl == "" {
		cagesCageUrl = "https://cages-ca.evervault.com/cages-ca.crt"
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
		EvervaultCaURL:      caURL,
		EvervaultCagesCaUrl: cagesCageUrl,
		RelayURL:            evRelayURL,
		FunctionRunURL:      evFunctionRun,
		EvAPIURL:            evAPIURL,
	}
}
