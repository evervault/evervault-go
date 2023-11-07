package attestation

import (
	"log"
	"sync"
	"time"

	"github.com/evervault/evervault-go/types"
)

type PCRManager interface {
	Get() *[]types.PCRs
}

type StaticProvider struct {
	pcrs *[]types.PCRs
}

type PollingProvider struct {
	getPcrs  func() ([]types.PCRs, error)
	pcrs     *[]types.PCRs
	mutex    sync.RWMutex
	ticker   *time.Ticker
	stopPoll chan bool
}

func NewCagePCRManager(pollingInterval time.Duration, pcrs interface{}) (PCRManager, error) {
	switch data := pcrs.(type) {
	case func() ([]types.PCRs, error):
		emptyPCRs := []types.PCRs{}
		cache := &PollingProvider{
			getPcrs:  data,
			pcrs:     &emptyPCRs,
			mutex:    sync.RWMutex{},
			ticker:   time.NewTicker(pollingInterval),
			stopPoll: make(chan bool),
		}

		cache.Load()

		go cache.pollAPI()

		return cache, nil
	case []types.PCRs:
		cache := &StaticProvider{
			pcrs: &data,
		}

		return cache, nil
	default:
		return nil, types.ErrInvalidPCRProvider
	}
}

func (c *PollingProvider) Set(pcrs *[]types.PCRs) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pcrs = pcrs
}

func (c *PollingProvider) Get() *[]types.PCRs {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return c.pcrs
}

func (c *StaticProvider) Get() *[]types.PCRs {
	return c.pcrs
}

func (c *PollingProvider) StopPolling() {
	c.stopPoll <- true
}

func (c *PollingProvider) Load() {
	pcrs, err := c.getPcrs()
	if err != nil {
		log.Printf("could not get pcrs doc: %v", err)
	}

	c.Set(&pcrs)
}

func (c *PollingProvider) pollAPI() {
	for {
		select {
		case <-c.ticker.C:
			pcrs, err := c.getPcrs()
			if err != nil {
				log.Printf("couldn't get pcrs: %v", err)
			}

			c.Set(&pcrs)
		case <-c.stopPoll:
			c.ticker.Stop()
			return
		}
	}
}
