package evervault

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

func main() {
	caCert, err := http.Get("https://ca.evervault.com")
	if err != nil {
		log.Fatal(err)
	}
	defer caCert.Body.Close()
	caBody, err := io.ReadAll(caCert.Body)
	if err != nil {
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodGet, os.Getenv("PROXY_DESTINATION"), nil)
	if err != nil {
		log.Fatalln("request error", err)
	}

	res, err := client(caBody).Do(req)
	if err != nil {
		log.Fatalln("client error", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}

func client(caCert []byte) *http.Client {
	return &http.Client{
		Transport: transport(caCert),
	}
}

func transport(caCert []byte) *http.Transport {
	proxy_url, err := url.Parse(os.Getenv("PROXY_URL"))
	if err != nil {
		log.Fatalln("proxy error", err)
	}
	return &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   tlsConfig(caCert),
		Proxy:             http.ProxyURL(proxy_url),
	}
}

func tlsConfig(caCert []byte) *tls.Config {
	rootCAs, _ := x509.SystemCertPool()
	rootCAs.AppendCertsFromPEM(caCert)

	return &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
}
