package attestation

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/evervault/evervault-go/models"
)

type PCRManager interface {
	Get() []models.PCRs
}

type StaticProvider struct {
	pcrs []models.PCRs
}

type PollingProvider struct {
	getPcrs  func() ([]models.PCRs, error)
	pcrs     []models.PCRs
	mutex    *sync.RWMutex
	ticker   *time.Ticker
	stopPoll chan bool
}

const pcrPollTimeout = 5 * time.Second

func NewCagePCRManager(cageDomain string, pollingInterval time.Duration, pcrs interface{}) (PCRManager, error) {

	switch data := pcrs.(type) {
	case func() ([]models.PCRs, error):
		cache := &PollingProvider{
			getPcrs:  data,
			pcrs:     []models.PCRs{},
			mutex:    &sync.RWMutex{},
			ticker:   time.NewTicker(pollingInterval),
			stopPoll: make(chan bool),
		}
		ctx, cancel := context.WithTimeout(context.Background(), pcrPollTimeout)
		defer cancel()

		cache.LoadDoc(ctx)

		go cache.pollAPI()

		return cache, nil
	case []models.PCRs:
		// TODO: remove mutex for static PCRs
		cache := &StaticProvider{
			pcrs: data,
		}
		return cache, nil
	default:
		return nil, errors.New("unsupported PCRs type, must be array or callback with type: func() ([]models.PCRs, error)")
	}
}

func (c *PollingProvider) Set(pcrs []models.PCRs) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pcrs = pcrs
}

func (c PollingProvider) Get() []models.PCRs {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.pcrs
}

func (c *StaticProvider) Get() []models.PCRs {
	return c.pcrs
}

func (c *PollingProvider) StopPolling() {
	c.stopPoll <- true
}

func (c *PollingProvider) LoadDoc(ctx context.Context) {
	pcrs, err := c.getPcrs()
	if err != nil {
		log.Printf("could not get pcrs doc: %v", err)
	}

	c.Set(pcrs)
}

func (c *PollingProvider) pollAPI() {
	for {
		select {
		case <-c.ticker.C:
			pcrs, err := c.getPcrs()
			if err != nil {
				log.Printf("couldn't get pcrs: %v", err)
			}

			c.Set(pcrs)
		case <-c.stopPoll:
			c.ticker.Stop()
			return
		}
	}
}
