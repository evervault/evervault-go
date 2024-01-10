package evervault

import (
	"crypto/tls"
	"net/http"

	"github.com/evervault/evervault-go/attestation"
	internalAttestation "github.com/evervault/evervault-go/internal/attestation"
)

// Will return a http.Client that is connected to a specified cage hostname with a fully attested client.
// The Client will attest the connection every time it makes a HTTP request and will return an error on request if it
// fails attestation
//
//	cageURL = "<CAGE_NAME>.<APP_UUID>.cages.evervault.com"
//	expectedPCRs := evervault.PCRs{
//		PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
//		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//		PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
//		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
//	}
//
//	cageClient, err := evClient.CagesClient(cageURL, []evervault.PCRs{expectedPCRs})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/", cageURL), bytes.NewBuffer(payload))
//	req.Close = true
//	req.Header.Set("API-KEY", "<API_KEY>")
//	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
//
//	resp, err := cageClient.Do(req)
//
// Deprecated: Use EnclaveClient instead.
func (c *Client) CagesClient(cageHostname string, pcrs []attestation.PCRs) (*http.Client, error) {
	pcrManager := internalAttestation.NewStaticPCRManager(pcrs)

	client, err := c.createCagesClient(pcrManager, cageHostname)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Will return a http.Client that is connected to a specified cage hostname with a fully attested client.
// Specify a callback to be polled periodically to pick up the latest PCRs to attest with.
// The Client will attest the connection every time it makes a HTTP request and will return an error on request if it
// fails attestation
//
//	cageURL = "<CAGE_NAME>.<APP_UUID>.cages.evervault.com"
//	func GetPCRs() ([]attestation.PCRs, error) {
//		// logic to get PCRs
//		return pcrs, nil
//	}
//
//
//	cageClient, err := evClient.CagesClientWithProvider(cageURL, GetPCRs)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/", cageURL), bytes.NewBuffer(payload))
//	req.Close = true
//	req.Header.Set("API-KEY", "<API_KEY>")
//	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
//
//	resp, err := cageClient.Do(req)
//
// Deprecated: Use EnclaveClientWithProvider instead.
func (c *Client) CagesClientWithProvider(cageHostname string,
	pcrsProvider func() ([]attestation.PCRs, error),
) (*http.Client, error) {
	pcrManager := internalAttestation.NewPollingPCRManager(c.Config.CagesPollingInterval, pcrsProvider)

	cagesClient, err := c.createCagesClient(pcrManager, cageHostname)
	if err != nil {
		return nil, err
	}

	return cagesClient, nil
}

func (c *Client) createCagesClient(pcrManager internalAttestation.PCRManager,
	cageHostname string,
) (*http.Client, error) {
	expectedPCRs := pcrManager.Get()

	if len(filterEmptyPCRs(*expectedPCRs)) == 0 {
		return nil, ErrNoPCRs
	}

	cache, err := internalAttestation.NewAttestationCache(cageHostname, c.Config.CagesPollingInterval)
	if err != nil {
		return nil, err
	}

	cagesClient := c.cagesClient(cageHostname, cache, pcrManager)

	return cagesClient, nil
}

// cagesClient returns an HTTP client for connecting to the cage.
func (c *Client) cagesClient(cageHostname string,
	cache *internalAttestation.Cache, provider internalAttestation.PCRManager,
) *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		ServerName:         cageHostname,
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext:    c.createDial(tlsConfig, cache, provider),
	}

	return &http.Client{Transport: transport}
}
