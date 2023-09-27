package evervault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type AttestationCache struct {
	cageURL         *url.URL
	pollingInterval time.Duration
	doc             []byte
	mutex           sync.RWMutex
	client          http.Client
}

const pollTimeout = 5 * time.Second

func NewAttestationCache(cageDomain string, pollingInterval time.Duration) (*AttestationCache, error) {
	cageURL, err := url.Parse(fmt.Sprintf("https://%s/.well-known/attestation", cageDomain))
	if err != nil {
		return nil, fmt.Errorf("cage url could not be parsed %w", err)
	}

	cache := &AttestationCache{
		cageURL:         cageURL,
		pollingInterval: pollingInterval,
		doc:             make([]byte, 0),
		mutex:           sync.RWMutex{},
		client:          http.Client{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()

	cache.loadDoc(ctx)

	go cache.pollAPI(pollingInterval)

	return cache, nil
}

func (c *AttestationCache) Set(doc []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.doc = doc
}

func (c *AttestationCache) Get() []byte {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.doc
}

//nolint:tagliatelle
type CageDocResponse struct {
	AttestationDoc string `json:"attestation_doc"`
}

func (c *AttestationCache) getDoc(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, c.cageURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("could not generate attestation doc request %w", err)
	}

	req = req.WithContext(ctx)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not generate attestation doc request %w", err)
	}

	if err != nil {
		return nil, fmt.Errorf("error getting attestation doc %w", err)
	}
	defer resp.Body.Close()

	var response CageDocResponse
	err = json.NewDecoder(resp.Body).Decode(&response)

	if err != nil {
		return nil, fmt.Errorf("error decoding attestation doc json %w", err)
	}

	docBytes, err := base64.StdEncoding.DecodeString(response.AttestationDoc)
	if err != nil {
		return nil, fmt.Errorf("Error decoding attestation doc %w", err)
	}

	return docBytes, nil
}

func (c *AttestationCache) loadDoc(ctx context.Context) {
	docBytes, err := c.getDoc(ctx)
	if err != nil {
		log.Printf("could not get attestation doc: %v", err)
	}

	c.Set(docBytes)
}

func (c *AttestationCache) pollAPI(interval time.Duration) {
	ticker := time.NewTicker(interval)

	for range ticker.C {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
			defer cancel()

			docBytes, err := c.getDoc(ctx)
			if err != nil {
				log.Printf("couldn't get attestation doc: %v", err)
			}

			c.Set(docBytes)
		}()
	}
}
