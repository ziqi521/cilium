// Copyright 2020 Authors of Cilium
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

package hubble

import (
	"context"
	"fmt"
	"net"

	hubbleProto "github.com/cilium/hubble/api/v1/flow"
	hubbleV1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleIPCache "github.com/cilium/hubble/pkg/ipcache"
	hubbleEndpoint "github.com/cilium/hubble/pkg/parser/endpoint"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service"
)

type LocalIdentityGetter struct {
	allocator *cache.CachingIdentityAllocator
}

func NewLocalIdentityGetter(allocator *cache.CachingIdentityAllocator) *LocalIdentityGetter {
	return &LocalIdentityGetter{allocator: allocator}
}

func (getter *LocalIdentityGetter) GetIdentity(securityIdentity uint64) (*models.Identity, error) {
	ident := getter.allocator.LookupIdentityByID(context.Background(), identity.NumericIdentity(securityIdentity))
	if ident == nil {
		return nil, fmt.Errorf("identity %d not found", securityIdentity)
	}
	return ident.GetModel(), nil
}

type LocalEndpointDNSGetter struct {
	manager *endpointmanager.EndpointManager
}

func NewLocalEndpointDNSGetter(manager *endpointmanager.EndpointManager) *LocalEndpointDNSGetter {
	return &LocalEndpointDNSGetter{manager: manager}
}

func (getter *LocalEndpointDNSGetter) GetEndpoint(ip net.IP) (endpoint *hubbleV1.Endpoint, ok bool) {
	ep := getter.manager.LookupIP(ip)
	if ep == nil {
		return nil, false
	}
	return hubbleEndpoint.ParseEndpointFromModel(ep.GetModel()), true
}

func (getter *LocalEndpointDNSGetter) GetNamesOf(sourceEpID uint64, ip net.IP) []string {
	ep := getter.manager.LookupCiliumID(uint16(sourceEpID))
	if ep == nil {
		return nil
	}
	return ep.DNSHistory.LookupIP(ip)
}

type LocalIPGetter struct {
	ipCache *ipcache.IPCache
}

func NewLocalIPGetter(ipCache *ipcache.IPCache) *LocalIPGetter {
	return &LocalIPGetter{ipCache: ipCache}
}

func (getter *LocalIPGetter) GetIPIdentity(ip net.IP) (hubbleIPCache.IPIdentity, bool) {
	ipIdentity, ok := getter.ipCache.LookupByIP(ip.String())
	if !ok {
		return hubbleIPCache.IPIdentity{}, false
	}
	meta := getter.ipCache.GetK8sMetadata(ip.String())
	if meta == nil {
		return hubbleIPCache.IPIdentity{}, false
	}
	return hubbleIPCache.IPIdentity{
		Identity:  ipIdentity.ID,
		Namespace: meta.Namespace,
		PodName:   meta.PodName,
	}, true
}

type LocalServiceGetter struct {
	svc *service.Service
}

func NewLocalServiceGetter(svc *service.Service) *LocalServiceGetter {
	return &LocalServiceGetter{svc: svc}
}

func (g *LocalServiceGetter) GetServiceByAddr(ip net.IP, port uint16) (hubbleProto.Service, bool) {
	addr := loadbalancer.L3n4Addr{
		IP: ip,
		L4Addr: loadbalancer.L4Addr{
			Port: port,
		},
	}
	svc, ok := g.svc.GetDeepCopyServiceByAddr(addr)
	if !ok {
		return hubbleProto.Service{}, false
	}
	return hubbleProto.Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
	}, true
}

func (g *LocalServiceGetter) GetServiceByID(id int64) (hubbleProto.Service, bool) {
	svc, ok := g.svc.GetDeepCopyServiceByID(loadbalancer.ServiceID(id))
	if !ok {
		return hubbleProto.Service{}, false
	}
	return hubbleProto.Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
	}, true
}
