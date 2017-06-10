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
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/lb"

	. "gopkg.in/check.v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"
)

type DummyLB struct {
	services map[lb.ServiceID]lb.Service
}

func NewDummyLB() DummyLB {
	return DummyLB{
		services: map[lb.ServiceID]lb.Service{},
	}
}

var (
	acquireID          = lb.ServiceID(0)
	acquireError error = nil
	acquireFunc        = defaultAcquire
	frontends          = map[string]lb.ServiceID{}
)

func defaultAcquire(f lb.Frontend) lb.ServiceID {
	id := f.ID()
	if f, ok := frontends[id]; ok {
		return f
	}

	acquireID++
	frontends[id] = acquireID
	return frontends[id]
}

func (dummy DummyLB) AcquireGlobalID(f lb.Frontend) (lb.ServiceID, error) {
	return acquireFunc(f), acquireError
}

func (dummy DummyLB) AddOrReplaceService(id lb.ServiceID, f lb.Frontend, b []lb.Backend, cfg lb.ServiceConfiguration) {
	dummy.services[id] = lb.NewService(id, f, b)
}

func (dummy DummyLB) DeleteService(id lb.ServiceID) bool {
	delete(dummy.services, id)
	return true
}

// TestDummyLB tests the DummyLB implementation itself
func (s *K8sSuite) TestDummyLB(c *C) {
	d := NewDummyLB()

	id := lb.ServiceID(10)
	_, ok := d.services[id]
	c.Assert(ok, Not(Equals), true)

	d.AddOrReplaceService(id, lb.Frontend{}, []lb.Backend{}, lb.ServiceConfiguration{})

	svc, ok := d.services[id]
	c.Assert(ok, Equals, true)
	c.Assert(svc.ID, Equals, id)

	d.DeleteService(id)

	_, ok = d.services[id]
	c.Assert(ok, Not(Equals), true)
}

// TestNormalService test addition of a regular clusterIP service, modification
// of the service and then deletion
func (s *K8sSuite) TestNormalService(c *C) {
	serviceName := "test"
	serviceNamespace := "default"
	svc := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: serviceNamespace,
		},
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
				{Name: "https", Port: 443, Protocol: "TCP"},
			},
		},
	}

	acquireFunc = defaultAcquire

	d := NewDummyLB()
	state := NewState(&d)
	state.HandleServiceEvent(nil, &svc)

	found, ok := state.services[NewID(serviceName, serviceNamespace)]
	c.Assert(ok, Equals, true)
	c.Assert(found, Not(IsNil))

	f, ok := found.Frontends["1.1.1.1:80/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(f.ServicePort.Port, Equals, int32(80))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))
	c.Assert(f.ServiceID, Not(Equals), 0)
	c.Assert(d.services[f.ServiceID].Frontend.IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(d.services[f.ServiceID].Frontend.Port, Equals, uint16(80))

	f, ok = found.Frontends["1.1.1.1:443/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(f.ServicePort.Port, Equals, int32(443))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))
	c.Assert(f.ServiceID, Not(Equals), 0)
	c.Assert(d.services[f.ServiceID].Frontend.IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(d.services[f.ServiceID].Frontend.Port, Equals, uint16(443))

	// IP/port/protocol that does not exist
	f, ok = found.Frontends["2.2.2.2:80/TCP"]
	c.Assert(ok, Not(Equals), true)
	c.Assert(f, IsNil)

	svcUpdate := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: serviceNamespace,
		},
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "2.2.2.2",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
				{Name: "http-1", Port: 81, Protocol: "TCP"},
				{Name: "https-1", Port: 444, Protocol: "TCP"},
			},
		},
	}

	state.HandleServiceEvent(nil, &svcUpdate)

	found, ok = state.services[NewID(serviceName, serviceNamespace)]
	c.Assert(ok, Equals, true)
	c.Assert(found, Not(IsNil))

	f, ok = found.Frontends["1.1.1.1:443/TCP"]
	c.Assert(ok, Not(Equals), true)
	c.Assert(f, IsNil)

	f, ok = found.Frontends["2.2.2.2:80/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("2.2.2.2"))
	c.Assert(f.ServicePort.Port, Equals, int32(80))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))
	c.Assert(f.ServiceID, Not(Equals), 0)
	c.Assert(d.services[f.ServiceID].Frontend.IP, DeepEquals, net.ParseIP("2.2.2.2"))
	c.Assert(d.services[f.ServiceID].Frontend.Port, Equals, uint16(80))

	f, ok = found.Frontends["2.2.2.2:81/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("2.2.2.2"))
	c.Assert(f.ServicePort.Port, Equals, int32(81))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))
	c.Assert(f.ServiceID, Not(Equals), 0)
	c.Assert(d.services[f.ServiceID].Frontend.IP, DeepEquals, net.ParseIP("2.2.2.2"))
	c.Assert(d.services[f.ServiceID].Frontend.Port, Equals, uint16(81))

	f, ok = found.Frontends["2.2.2.2:444/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("2.2.2.2"))
	c.Assert(f.ServicePort.Port, Equals, int32(444))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))
	c.Assert(f.ServiceID, Not(Equals), 0)
	c.Assert(d.services[f.ServiceID].Frontend.IP, DeepEquals, net.ParseIP("2.2.2.2"))
	c.Assert(d.services[f.ServiceID].Frontend.Port, Equals, uint16(444))

	state.HandleServiceEvent(&svcUpdate, nil)

	found, ok = state.services[NewID(serviceName, serviceNamespace)]
	c.Assert(ok, Not(Equals), true)
	c.Assert(found, IsNil)
}

// TestIgnoreHeadlessService tests that headless services are properly ignored
// by HandleServiceEvent
func (s *K8sSuite) TestIgnoreHeadlessService(c *C) {
	serviceName := "test"
	serviceNamespace := "default"
	svc := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: serviceNamespace,
		},
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "NONE",
		},
	}

	d := NewDummyLB()
	state := NewState(&d)
	state.HandleServiceEvent(nil, &svc)

	found, ok := state.services[NewID(serviceName, serviceNamespace)]
	c.Assert(ok, Equals, false)
	c.Assert(found, IsNil)
}

// TestIDConflict tests that if ID registration returns the same ID multiple
// times for different services that these services are not populated to the
// loadbalancer.
func (s *K8sSuite) TestIDConflict(c *C) {
	svc1 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
			},
		},
	}
	svc2 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test2",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "2.2.2.2",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
			},
		},
	}

	staticID := lb.ServiceID(10)

	// Set acquire behaviour to always return a static ID
	acquireFunc = func(f lb.Frontend) lb.ServiceID { return staticID }

	d := NewDummyLB()
	state := NewState(&d)

	needResync = false

	// insert service test1
	state.HandleServiceEvent(nil, &svc1)

	// test1 should be imported
	found, ok := state.services[NewID("test1", "default")]
	c.Assert(ok, Equals, true)
	c.Assert(found, Not(IsNil))
	c.Assert(needResync, Equals, false)

	// frontend must have been updated
	f, ok := found.Frontends["1.1.1.1:80/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.ServiceID, Equals, staticID)
	// and propagated to loadbalancer
	c.Assert(d.services[staticID].Frontend.IP, DeepEquals, net.ParseIP("1.1.1.1"))

	// insert service test2
	state.HandleServiceEvent(nil, &svc2)

	// test2 should exist as well
	found, ok = state.services[NewID("test2", "default")]
	c.Assert(ok, Equals, true)
	c.Assert(found, Not(IsNil))

	// failure should have triggered a needResync event
	c.Assert(needResync, Equals, true)

	f, ok = found.Frontends["2.2.2.2:80/TCP"]
	c.Assert(ok, Equals, true)
	// ID should not have been resolved
	c.Assert(f.ServiceID, Equals, lb.ServiceID(0))
}

// TestAcquireIDFailure tests that if ID registration fails, that these
// services are not populated, then when it recovers, it should resume
func (s *K8sSuite) TestAcquireIDFailure(c *C) {
	svc1 := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test1",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
			},
		},
	}

	// Set acquire behaviour to return an error
	acquireError = fmt.Errorf("error")
	acquireFunc = defaultAcquire

	d := NewDummyLB()
	state := NewState(&d)

	// insert service test1
	state.HandleServiceEvent(nil, &svc1)

	// test1 should be imported
	found, ok := state.services[NewID("test1", "default")]
	c.Assert(ok, Equals, true)
	c.Assert(found, Not(IsNil))

	// frontend should not have been added
	f, ok := found.Frontends["1.1.1.1:80/TCP"]
	c.Assert(ok, Equals, true)
	_, ok = d.services[f.ServiceID]
	c.Assert(ok, Equals, false)

	acquireError = nil

	// Manual sync
	state.Sync()

	// test1 should be imported
	found, ok = state.services[NewID("test1", "default")]
	c.Assert(ok, Equals, true)
	c.Assert(found, Not(IsNil))

	// frontend should not have been added
	f, ok = found.Frontends["1.1.1.1:80/TCP"]
	c.Assert(ok, Equals, true)
	svc, ok := d.services[f.ServiceID]
	c.Assert(ok, Equals, true)
	c.Assert(svc.Frontend.IP, DeepEquals, net.ParseIP("1.1.1.1"))
}
