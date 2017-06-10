// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lb

import (
	"fmt"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
)

const (
	// MaxSyncAttempts is the number of attempts to synchronize with the
	// loadbalancer before giving up
	MaxSyncAttempts uint = 10

	// SyncInterval is the interval between regularly scheduled sync runs
	SyncInterval = time.Duration(60) * time.Second
)

// Configuration holds loadbalancer configuration which can then be
// synchronized with an implementation. The implementation needs to implement
// the LoadBalancer interface
type Configuration struct {
	mutex       sync.RWMutex
	lb          LoadBalancer
	quitSync    chan struct{}
	servicesSHA map[string]*Service
	servicesID  map[ServiceID]*Service
}

// NewConfiguration returns a new empty configuration hooked to a loadbalancer
// and starts a go subroutine which does regular synchronization with the
// loadbalancer
func NewConfiguration(lb LoadBalancer) *Configuration {
	cfg := &Configuration{
		lb:          lb,
		quitSync:    make(chan struct{}, 1),
		servicesSHA: map[string]*Service{},
		servicesID:  map[ServiceID]*Service{},
	}

	// schedule go subroutine to run sync routine
	cfg.syncScheduler()

	return cfg
}

// TearDown stops the synchronization go subroutine
func (c *Configuration) TearDown() {
	close(c.quitSync)
}

func (c *Configuration) syncScheduler() {
	log.Debugf("Starting service sync go subroutine for %+v", c)
	go func(c *Configuration) {
		for {
			select {
			case _, ok := <-c.quitSync:
				if !ok {
					log.Debugf("Stopping service sync go subroutine for %+v", c)
					break
				}
			case <-time.After(SyncInterval):
				c.Sync()
			}
		}
	}(c)
}

func (c *Configuration) AcquireGlobalID(f Frontend) (ServiceID, error) {
	return acquireGlobalID(f, 0)
}

func (c *Configuration) unlinkService(svc *Service) {
	log.Debugf("Removed service %s from loadbalancer configuration", svc)
	delete(c.servicesSHA, svc.SHA256)
	delete(c.servicesID, svc.ID)
}

func (c *Configuration) deleteService(svc *Service) {
	if err := c.lb.DeleteService(svc); err != nil {
		svc.syncAttempts++
		log.Warningf("Service sync: Unable to delete service %s: \"%s\". Will retry later", svc, err)
	} else {
		c.unlinkService(svc)
	}
}

// GetService returns a copy of a service found by its ID
func (c *Configuration) GetService(id ServiceID) (Service, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	svc, ok := c.servicesID[id]
	if !ok {
		return Service{}, fmt.Errorf("service %d not found", id)
	}

	return *svc, nil
}

// DeleteService removes a service from the configuration. If the service can't
// be deleted right away, then there will be MaxSyncAttempts number of
// synchronization attempts in the background before giving up.
func (c *Configuration) DeleteService(id ServiceID) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if svc, ok := c.servicesID[id]; ok {
		log.Debugf("Service %s is scheduled for deletion", svc)

		svc.Deleted = true
		svc.syncAttempts = 0

		// attempt immediate sync with loadbalancer
		c.deleteService(svc)
		return true
	} else {
		log.Debugf("QueueDeletion() called for service id %d which does not exist", id)
		return false
	}
}

func (c *Configuration) replaceService(svc *Service) {
	if err := c.lb.AddOrReplaceService(svc); err != nil {
		log.Warningf("Service sync: Unable to modify service \"%s\": %s. Will retry later", svc, err)
		svc.syncAttempts++
	} else {
		svc.OutOfSync = false
	}
}

// AddOrReplaceService adds a service to the configuration. If the a service
// with an identical ID already exists, the configuration will be updated. If
// the service configuration can not be synchronized to the loadbalancer, it
// will be attempted MaxSyncAttempts times in the background using Sync(). Once
// MaxSyncAttempts is reached, the service remains configured with the
// configuration and loadbalancer state being inconsistent. Any call to
// AddOrReplaceService() for a service will cause the sync attempt counter to
// be reset.
func (c *Configuration) AddOrReplaceService(newID ServiceID, f Frontend, b []Backend, cfg ServiceConfiguration) {
	svc := NewService(newID, f, b)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	oldSvc, ok := c.servicesID[newID]
	if ok {
		// If service already existed, remove old entry from map
		delete(c.servicesSHA, oldSvc.SHA256)
	}

	svc.OutOfSync = true
	svc.syncAttempts = 0

	c.servicesSHA[svc.SHA256] = &svc
	c.servicesID[svc.ID] = &svc

	log.Debugf("New service %+v in loadbalancer configuration", svc)

	// attempt immediate sync with loadbalancer
	c.replaceService(&svc)
}

// Sync synchronizes the configuration with the underlying loadbalancer. This
// function is automatically called from a go subroutine every SyncInterval
// seconds.
func (c *Configuration) Sync() {
	log.Debugf("Synchronizing service configuration with loadbalancer...")

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for _, svc := range c.servicesID {
		if svc.Deleted {
			if svc.syncAttempts > MaxSyncAttempts {
				log.Warningf("Reached max sync attempts while deleting service %s. "+
					"Giving up. Stale service may remain in the loadbalancer", svc)
				c.unlinkService(svc)
			} else {
				c.deleteService(svc)
			}
		} else if svc.OutOfSync {
			if svc.syncAttempts > MaxSyncAttempts {
				log.Warningf("Reached max sync attempts while modifying service %s. "+
					"Giving up. Old configuration remains in the loadbalancer", svc)
				c.unlinkService(svc)
			} else {
				c.replaceService(svc)
			}
		}
	}
}
