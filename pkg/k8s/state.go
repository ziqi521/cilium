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

package k8s

import (
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/lb"

	log "github.com/Sirupsen/logrus"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

var (
	// SyncInterval is the interval between regularly scheduled sync runs
	SyncInterval = time.Duration(1) * time.Minute

	// needResync is set to true if an indication is found that the locally
	// known services are out of sync with the Kubernetes API server.
	needResync = false
)

func scheduleResync() {
	log.Infof("k8s: Local state potentially out of sync with k8s API server. Scheduling re-sync...")
	needResync = true
}

// meta is a base type that must be embedded into all structures for which
// state is being managed
type meta struct {
	// modified is true when the object must be synchronized with the
	// datapath
	modified bool

	// deleted is true if the object has been marked for deletion
	deleted bool
}

type State struct {
	mutex      sync.Mutex
	lb         lb.LoadBalancerState
	services   map[ID]*K8sService
	lbServices map[lb.ServiceID]*K8sService
	ingresses  map[ID]*K8sIngress
	endpoints  map[ID]*K8sEndpoints
	quitSync   chan struct{}
}

// NewState returns a new state structure
func NewState(lbState lb.LoadBalancerState) *State {
	return &State{
		lb:         lbState,
		services:   map[ID]*K8sService{},
		lbServices: map[lb.ServiceID]*K8sService{},
		ingresses:  map[ID]*K8sIngress{},
		endpoints:  map[ID]*K8sEndpoints{},
	}
}

// NewSyncedState returns a new state structure with automatic syncing enabled
func NewSyncedState(lbState lb.LoadBalancerState) *State {
	state := NewState(lbState)
	state.syncScheduler()
	return state
}

func ignorePort(svc *K8sService, f *K8sFrontend, fmt string, err error) {
	log.Warningf("K8s: Ignoring port %s of service %s: %s", svc.ID.String(), f.GetPort(), err)
}

func (s *State) syncScheduler() {
	log.Debugf("Starting k8s state sync go subroutine %#v", s)
	go func(s *State) {
		for {
			select {
			case _, ok := <-s.quitSync:
				if !ok {
					log.Debugf("Stopping k8s state go subroutine %+v", s)
					break
				}
			case <-time.After(SyncInterval):
				s.Sync()
			}
		}
	}(s)
}

func (s *State) updateService(svc *K8sService) {
	// Resolve the service ID of all frontends which belong to this Kubernetes service
	//
	// TODO:
	//   - Avoid resolving already known IDs
	//   - IDs could be resolved in parallel
	for _, f := range svc.Frontends {
		// Skip frontends which have been deleted
		if f.deleted {
			continue
		}

		// If a frontend does not have a cluser wide ID yet, look it up
		// or allocate a new ID from the kvstore
		if f.ServiceID == 0 {
			svcID, err := s.lb.AcquireGlobalID(f.GetFrontend())
			if err != nil {
				log.Debugf("k8s: Unable to resolve ID for service frontend %s (%s): %s", f, svc, err)
				continue
			}

			if conflict, ok := s.lbServices[svcID]; ok {
				// The returned ID is already in
				log.Warningf("k8s: Service %s was resolved to ID %d which is already in use by service %s",
					svc, svcID, conflict)
				scheduleResync()
				continue
			}

			log.Debugf("k8s: Assigned service ID %d to frontend %s (%s)", svcID, f, svc)
			s.lbServices[svcID] = svc
			f.ServiceID = svcID
		}
	}

	// Configure all ready frontends
	allOK := true
	for _, f := range svc.Frontends {
		if f.ServiceID == 0 {
			allOK = false
			continue
		}

		// Skip frontends which have not been modified
		if !f.modified {
			continue
		}

		backends := []lb.Backend{}
		if eps, ok := s.endpoints[svc.ID]; ok {
			backends = eps.GetBackends(f)
		}

		cfg := lb.ServiceConfiguration{EnableRevNAT: true}
		s.lb.AddOrReplaceService(f.ServiceID, f.GetFrontend(), backends, cfg)
		f.modified = false
	}

	for _, f := range svc.Frontends {
		if f.deleted {
			s.deleteFrontend(svc, f)
		}
	}

	if allOK {
		svc.modified = false
	}
}

func (s *State) deleteFrontend(svc *K8sService, f *K8sFrontend) {
	if f.ServiceID == 0 {
		return
	}

	// Failure to delete indicates that a stale loadbalancer entry
	// may remain. Schedule a resync operation.
	if !s.lb.DeleteService(f.ServiceID) {
		log.Debugf("k8s: Failed to delete service %s, scheduling re-sync", f)
		scheduleResync()
	}

	delete(s.lbServices, f.ServiceID)
	delete(svc.Frontends, f.ID())

	log.Debugf("k8s: Deleted frontend %s (%s)", f, svc)
}

func (s *State) deleteService(svc *K8sService) {
	for _, f := range svc.Frontends {
		s.deleteFrontend(svc, f)
	}

	delete(s.services, svc.ID)

	log.Debugf("k8s: Deleted service %s", svc)
}

func (s *State) syncServices() {
	for _, svc := range s.services {
		if svc.deleted {
			s.deleteService(svc)
		} else if svc.modified {
			s.updateService(svc)
		}
	}
}

func (s *State) sync() {
	log.Debugf("k8s: Synchronizing k8s ingress/service/endpoints state...")
	s.syncServices()
}

// Sync synchronizes the maps Services, Ingresses, and Endpoints with a
// LoadbalancerConfiguration
func (s *State) Sync() {
	s.mutex.Lock()
	s.sync()
	s.mutex.Unlock()
}

func ignoreService(svc *v1.Service, err error) {
	log.Warningf("Ignoring k8s service %s/%s: %s", svc.Namespace, svc.Name, err)
}

func (s *State) scheduleServiceDeletion(id ID) {
	if svc, ok := s.services[id]; ok {
		// Schedule for deletion and attempt immediate deletion
		svc.deleted = true
		s.deleteService(svc)
	} else {
		// Deletion request for a service which we are unaware
		// of. Trigger full resync
		scheduleResync()
	}
}

// HandleServiceEvent needs to be called for add/delete/remove notifications of
// services from the API server. old is nil if service is added for the first
// time, new is nil if service is deleted, old and new are both set for
// modification events.
//
// The service resource contains the frontend portion and will depend on
// endpoints notification to retrieve/update the backend portion. Both
// notification types will trigger synchronization of state with the datapath.
func (s *State) HandleServiceEvent(old *v1.Service, new *v1.Service) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var newID ID

	if new != nil {
		newSvc, err := parseK8sService(new)
		if err != nil {
			ignoreService(new, err)
			return
		}

		if newSvc == nil {
			log.Infof("k8s: Ignoring headless service %s/%s, no action required", new.Namespace, new.Name)
			return
		}

		newID = NewK8sServiceID(new)
		svc, ok := s.services[newID]
		if !ok {
			// When the service is new, all frontends are modified
			for k := range newSvc.Frontends {
				newSvc.Frontends[k].modified = true
			}

			s.services[newID] = newSvc
			svc = s.services[newID]
		} else {
			svc.MergeConfiguration(newSvc)
		}

		svc.modified = true
		s.updateService(svc)
	}

	if old != nil {
		oldID := NewK8sServiceID(old)
		if new == nil {
			s.scheduleServiceDeletion(oldID)
		} else if newID.Equal(oldID) {
			log.Warningf("k8s: Received service event with conflicting IDs, old=%s new=%s. Scheduling resync...",
				oldID, newID)
			s.scheduleServiceDeletion(oldID)
		}
	}
}

// HandleEndpointsEvent needs to be called for add/delete/remove notifications
// of endpoints from the API server. old is nil if endpoints is added for the
// first time, new is nil if endpoints is deleted, old and new are both set for
// modification events.
//
// The endpoints resource contains the backends portion and will depend on
// service notification to retrieve/update the frontend portion. Both
// notification types will trigger synchronization of state with the datapath.
func (s *State) HandleEndpointEvent(old *v1.Endpoints, new *v1.Endpoints) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var newID ID

	if new != nil {
		endpoints, err := parseK8sEndpoints(new)
		if err != nil {
			log.Warningf("Ignoring k8s endpoints %s/%s: %s",
				new.Namespace, new.Name, err)
			return
		}

		endpoints.modified = true
		s.endpoints[endpoints.ID] = endpoints
		newID = endpoints.ID
	}

	if old != nil {
		id := DeriveK8sServiceID(old)

		if ep, ok := s.endpoints[id]; ok {
			// Mark for old service for deletion if old ID is
			// different from new ID
			if !id.Equal(newID) {
				ep.deleted = true
			}
		} else {
			// Deletion request for a endpoints which we are unaware of
			// FIXME: We have two options here:
			//  - create a new endpoints with Deleted = true
			//  - attempt direct removal from datapath
		}
	}

	s.sync()
}

// HandleIngressEvent needs to be called for add/delete/remove notifications of
// ingress resources from the API server. old is nil if ingress is added for
// the first time, new is nil if ingress is deleted, old and new are both set
// for modification events.
//
// The ingress resource contains a refernce to a service. Both ingress and
// service notification types will trigger synchronization of state with the
// datapath.
func (s *State) HandleIngressEvent(old *v1beta1.Ingress, new *v1beta1.Ingress) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var newID ID

	if new != nil {
		ingress, err := parseK8sIngress(new)
		if err != nil {
			log.Warningf("Ignoring k8s ingress %s/%s: %s",
				new.Namespace, new.Name, err)
			return
		}

		ingress.modified = true
		s.ingresses[ingress.ID] = ingress
		newID = ingress.ID
	}

	if old != nil {
		id := NewK8sIngressID(old)

		if ingress, ok := s.ingresses[id]; ok {
			// Mark for old ingress for deletion if old ID is
			// different from new ID
			if !id.Equal(newID) {
				ingress.deleted = true
			}
		} else {
			// Deletion request for a ingress which we are unaware of
			// FIXME: We have two options here:
			//  - create a new ingress with Deleted = true
			//  - attempt direct removal from datapath
		}
	}

	s.sync()
}
