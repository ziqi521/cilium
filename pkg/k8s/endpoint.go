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

	"k8s.io/client-go/pkg/api/v1"
)

// DeriveK8sServiceID returns the Kubernetes service ID which corresponds to
// the provided Endpoints spec
func DeriveK8sServiceID(e *v1.Endpoints) ID {
	return NewID(e.Name, e.Namespace)
}

// K8sEndpoints is the internal representation of a Kubernetes endpoints
// resources.
type K8sEndpoints struct {
	meta

	// ID is the Kubernetes service ID this endpoints relates to
	ID ID

	// private copy of resource
	res v1.Endpoints

	// Backends is the list of backend configurations this endpoints
	// contains
	Backends []lb.Backend
}

// GetBackends returns the backends of a K8sEndpoints which match a K8sFrontend
func (k *K8sEndpoints) GetBackends(f *K8sFrontend) []lb.Backend {
	result := []lb.Backend{}

	for _, b := range k.Backends {
		// If TargetPort is a string it may refer to a name in the
		// EndpointPort or to a port in the Pod
		//
		// If specified, it needs to match the EndpointPort name in
		// order for this backend to be selected.
		// FIXME add suport for named pod ports.
		//
		// If TargetPort is an int, it must match the port number
		// specified in the EndpointPort
		if n := f.ServicePort.TargetPort.StrVal; n != "" {
			if b.Name != n {
				continue
			}
		} else if uint16(f.ServicePort.TargetPort.IntVal) != b.Port {
			continue
		}

		result = append(result, b)
	}

	return result
}

// parseK8sEndpointAddress parses a Kubernetes EndpointAddress and returns the
// resulting Backend structure or an error
func parseK8sEndpointAddress(a v1.EndpointAddress) (*lb.Backend, error) {
	ip := net.ParseIP(a.IP)
	if ip == nil {
		return nil, fmt.Errorf("invalid endpoint ip '%s'", a.IP)
	}

	// Currently unparsed:
	//   // Optional: Hostname of this endpoint
	//   // Meant to be used by DNS servers etc.
	//   // +optional
	//   Hostname string
	//
	//   // Optional: Node hosting this endpoint. This can be used to determine endpoints local to a node.
	//   // +optional
	//   NodeName *string
	//
	//   // Optional: The kubernetes object related to the entry point.
	//   TargetRef *ObjectReference

	return &lb.Backend{IP: ip}, nil
}

func validateEndpointPorts(e *v1.Endpoints) error {
	for _, sub := range e.Subsets {
		validator := lb.NewPortValidator("port.Name", "port.Port", true)
		for _, port := range sub.Ports {
			validator.Queue(port.Name, uint16(port.Port), string(port.Protocol))
		}

		if err := validator.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// parseK8sEndpoints validates and parses a Kubernets endpoints, returns:
//  - A valid K8sEndpoints with n backends
//  - error if the spec contained an error
func parseK8sEndpoints(e *v1.Endpoints) (*K8sEndpoints, error) {
	if err := validateEndpointPorts(e); err != nil {
		return nil, err
	}

	endpoints := &K8sEndpoints{
		ID:       DeriveK8sServiceID(e),
		Backends: []lb.Backend{},
	}

	for _, sub := range e.Subsets {
		for _, addr := range sub.Addresses {
			template, err := parseK8sEndpointAddress(addr)
			if err != nil {
				return nil, err
			}

			for _, port := range sub.Ports {
				// copy the template
				backend := *template

				backend.Port = uint16(port.Port)
				backend.Protocol = lb.NormalizeProtocol(string(port.Protocol))
				backend.Name = port.Name

				endpoints.Backends = append(endpoints.Backends, backend)
			}
		}
	}

	return endpoints, nil
}
