package evervault

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/evervault/evervault-go/attestation"
	internalAttestation "github.com/evervault/evervault-go/internal/attestation"
)

// Will return a http.Client that is connected to a specified enclave hostname with a fully attested client.
// The Client will attest the connection every time it makes a HTTP request and will return an error on request if it
// fails attestation
//
//	enclaveURL = "<ENCLAVE_NAME>.<APP_UUID>.enclave.evervault.com"
//	expectedPCRs := evervault.PCRs{
//		PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
//		PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//		PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
//		PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
//	}
//
//	enclaveClient, err := evClient.EnclaveClient(enclaveURL, []evervault.PCRs{expectedPCRs})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/", enclaveURL), bytes.NewBuffer(payload))
//	req.Close = true
//	req.Header.Set("API-KEY", "<API_KEY>")
//	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
//
//	resp, err := enclaveClient.Do(req)
func (c *Client) EnclaveClient(enclaveHostname string, pcrs []attestation.PCRs) (*http.Client, error) {
	provider := attestation.BuildStaticPcrProvider(pcrs)

	client, err := c.EnclaveClientWithProvider(enclaveHostname, provider)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Will return an http.Client that is connected to a specified enclave hostname with a fully attested client.
// Specify a callback to be polled periodically to pick up the latest PCRs to attest with.
// The Client will attest the connection every time it makes a HTTP request and will return an error on request if it
// fails attestation
//
//	enclaveURL = "<ENCLAVE_NAME>.<APP_UUID>.enclave.evervault.com"
//	func GetPCRs() ([]attestation.PCRs, error) {
//		// logic to get PCRs
//		return pcrs, nil
//	}
//
//
//	enclaveClient, err := evClient.EnclaveClientWithProvider(enclaveURL, GetPCRs)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	payload, err := json.Marshal(fmt.Sprintf(`{"encrypted": "%s"}`, encrypted))
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("https://%s/", enclaveURL), bytes.NewBuffer(payload))
//	req.Close = true
//	req.Header.Set("API-KEY", "<API_KEY>")
//	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
//
//	resp, err := enclaveClient.Do(req)
func (c *Client) EnclaveClientWithProvider(
	enclaveHostname string,
	pcrsProvider func() ([]attestation.PCRs, error),
) (*http.Client, error) {
	customDial, err := c.EnclaveTCPConnectionWithProvider(enclaveHostname, pcrsProvider)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext:    customDial,
	}

	return &http.Client{Transport: transport}, nil
}

// Will return a http.Client that is connected to a specified enclave hostname with a fully attested client.
// The Client will attest the connection every time it makes a HTTP request and will return an error on request if it
// fails attestation
//
//		enclaveURL = "<ENCLAVE_NAME>.<APP_UUID>.enclave.evervault.com"
//
//		func GetPCRs() ([]attestation.PCRs, error) {
//			// logic to get PCRs
//			return evervault.PCRs{
//				PCR0: "f039c31c536749ac6b2a9344fcb36881dd1cf066ca44afcaf9369a9877e2d3c85fa738c427d502e01e35994da7458e2d",
//				PCR1: "bcdf05fefccaa8e55bf2c8d6dee9e79bbff31e34bf28a99aa19e6b29c37ee80b214a414b7607236edf26fcb78654e63f",
//				PCR2: "71c478711438fe252fbd9b1da56218bea5d630da55aa56431257df77bd42f65a434601bf53be9a1901fcd61680e425c7",
//				PCR8: "1650274b27bf44fba6f1779602399763af9e4567927d771b1b37aeb1ac502c84fbd6a7ab7b05600656a257247529fbb8",
//			}, nil
//		}
//
//		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
//		defer cancel()
//
//		enclaveDial, err := evClient.EnclaveTCPConnectionWithProvider(enclaveURL, GetPCRs)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		conn, err := enclaveDial(ctx, "tcp", enclaveURL)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		defer conn.Close()
//
//		if _, err := conn.Write([]byte("Hello, World!")); err != nil {
//	 	log.Fatal(err)
//		}
func (c *Client) EnclaveTCPConnectionWithProvider(
	enclaveHostname string,
	pcrsProvider func() ([]attestation.PCRs, error),
) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	pcrManager := internalAttestation.NewPollingPCRManager(c.Config.AttestationPollingInterval, pcrsProvider)

	expectedPcrs := pcrManager.Get()

	if len(filterEmptyPCRs(*expectedPcrs)) == 0 {
		return nil, ErrNoPCRs
	}

	cache, err := internalAttestation.NewAttestationCache(enclaveHostname, c.Config.AttestationPollingInterval)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		ServerName:         enclaveHostname,
	}

	return c.createDial(tlsConfig, cache, pcrManager), nil
}
