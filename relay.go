package evervault

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/url"
)

func (c *Client) relayClient(caCert []byte) *http.Client {
	return &http.Client{
		Transport: c.transport(caCert),
	}
}

func (c *Client) transport(caCert []byte) *http.Transport {
	proxyURL, err := url.Parse(c.Config.RelayURL)
	if err != nil {
		log.Fatalln("proxy error", err)
	}

	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   tlsConfig(caCert),
		Proxy:             http.ProxyURL(proxyURL),
	}
}

func tlsConfig(caCert []byte) *tls.Config {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalln("Error getting system cert pool", err)
	}

	rootCAs.AppendCertsFromPEM(caCert)

	return &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
	}
}
