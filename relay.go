package evervault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
)

func (c *Client) relayClient(caCert []byte) (*http.Client, error) {
	transport, err := c.transport(caCert)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func (c *Client) transport(caCert []byte) (*http.Transport, error) {
	proxyURL, err := url.Parse(c.Config.RelayURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing relay URL %w", err)
	}

	tlsClientConfig, err := tlsConfig(caCert)
	if err != nil {
		return nil, err
	}

	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   tlsClientConfig,
		Proxy:             http.ProxyURL(proxyURL),
	}, nil
}

func tlsConfig(caCert []byte) (*tls.Config, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error getting system cert pool %w", err)
	}

	rootCAs.AppendCertsFromPEM(caCert)

	return &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
	}, nil
}
