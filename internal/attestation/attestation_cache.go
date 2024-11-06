package attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Cache struct {
	cageURL  *url.URL
	doc      []byte
	mutex    sync.RWMutex
	client   http.Client
	ticker   *time.Ticker
	stopPoll chan bool
}

const (
	pollTimeout   = 30 * time.Second
	maxRetries    = 3
	retryInterval = 1 * time.Second
	backoffFactor = 2
)

func NewAttestationCache(cageDomain string, pollingInterval time.Duration) (*Cache, error) {
	cageURL, err := url.Parse(fmt.Sprintf("https://%s/.well-known/attestation", cageDomain))
	if err != nil {
		return nil, fmt.Errorf("enclave attestation URL could not be parsed: %w", err)
	}

	cache := &Cache{
		cageURL:  cageURL,
		doc:      make([]byte, 0),
		mutex:    sync.RWMutex{},
		client:   http.Client{},
		ticker:   time.NewTicker(pollingInterval),
		stopPoll: make(chan bool),
	}

	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()

	cache.LoadDoc(ctx)

	go cache.pollAPI()

	return cache, nil
}

func (c *Cache) Set(doc []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.doc = doc
}

func (c *Cache) Get() []byte {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.doc
}

func (c *Cache) StopPolling() {
	c.stopPoll <- true
}

//nolint:tagliatelle
type CageDocResponse struct {
	AttestationDoc string `json:"attestation_doc"`
}

func (c *Cache) getDoc(ctx context.Context) ([]byte, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("context canceled or timed out: %w", ctx.Err())
		default:
			if attempt > 1 {
				log.Printf("Attestation Document Cache: Attempt %d: Retrying in %v\n", attempt, retryInterval)
			}

			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, c.cageURL.String(), nil)
			if reqErr != nil {
				return nil, fmt.Errorf("could not create request: %w", reqErr)
			}

			resp, respErr := c.client.Do(req)
			if respErr != nil {
				lastErr = c.handleError("could not get attestation doc", respErr, attempt)
				continue
			}
			defer resp.Body.Close()

			var response CageDocResponse
			if decodeErr := json.NewDecoder(resp.Body).Decode(&response); decodeErr != nil {
				lastErr = c.handleError("error decoding attestation doc JSON", decodeErr, attempt)
				continue
			}

			docBytes, err := base64.StdEncoding.DecodeString(response.AttestationDoc)
			if err == nil {
				return docBytes, nil
			}

			lastErr = c.handleError("error decoding attestation doc", err, attempt)
		}
	}

	return nil, fmt.Errorf("failed to get attestation doc after %d attempts: %w", maxRetries, lastErr)
}

func (c *Cache) handleError(message string, err error, attempt int) error {
	log.Printf("Attempt %d %s: %v", attempt, message, err)

	backoffDuration := time.Duration(math.Pow(backoffFactor, float64(attempt))) * time.Second
	time.Sleep(backoffDuration)

	return fmt.Errorf("%s: %w", message, err)
}

func (c *Cache) LoadDoc(ctx context.Context) {
	docBytes, err := c.getDoc(ctx)
	if err != nil {
		log.Printf("Could not get attestation doc: %v", err)
		return
	}

	log.Println("Evervault Attestation Document Cache: Document loaded")
	c.Set(docBytes)
}

func (c *Cache) pollAPI() {
	for {
		select {
		case <-c.ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
			defer cancel()

			c.LoadDoc(ctx)
		case <-c.stopPoll:
			c.ticker.Stop()
			return
		}
	}
}
