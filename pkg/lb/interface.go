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

// LoadBalancerState is the abstract interface
type LoadBalancerState interface {
	// AcquireGlobalID lookups or creates a global service ID
	AcquireGlobalID(f Frontend) (ServiceID, error)

	// AddOrReplaceService adds a frontend to the loadbalancer
	AddOrReplaceService(id ServiceID, f Frontend, b []Backend, cfg ServiceConfiguration)

	// DeleteService removes a service from the loadbalancer. Returns true
	// if the service was found and deleted
	DeleteService(id ServiceID) bool
}

// LoadBalancer is the low level interface of a loadbalancer implementation
type LoadBalancer interface {
	AddOrReplaceService(svc *Service) error
	DeleteService(svc *Service) error
}
