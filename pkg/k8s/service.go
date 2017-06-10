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
	"strings"

	"github.com/cilium/cilium/pkg/lb"

	"k8s.io/client-go/pkg/api/v1"
)

// NewK8sServiceID derives the ID of a k8s service from its spec
func NewK8sServiceID(svc *v1.Service) ID {
	return NewID(svc.Name, svc.Namespace)
}

// K8sFrontend describes each individual IP+port frontend which can be mapped
// to an lb.Frontend
type K8sFrontend struct {
	meta

	// ID is initially 0 and then populated with the related lb.Service
	ServiceID lb.ServiceID

	// IP is the clusterIP / nodeIP / ....
	IP net.IP

	// Copy of the ServicePort in K8sService.res
	ServicePort v1.ServicePort
}

// String returns a human readable identifier for the K8sFrontend
func (f *K8sFrontend) String() string {
	return fmt.Sprintf("%s:%d/%s (%d)", f.IP, f.GetPort(), f.ServicePort.Protocol, f.ID)
}

// ID returns an ID of a Kubernetes frontend that can be used as map key
func (f *K8sFrontend) ID() string {
	return fmt.Sprintf("%s:%d/%s", f.IP, f.GetPort(), f.ServicePort.Protocol)
}

// GetPort returns the port the service should listen on
func (f *K8sFrontend) GetPort() uint16 {
	return uint16(f.ServicePort.Port)
}

// GetFrontend returns a Frontend template representing the K8sFrontend
func (f *K8sFrontend) GetFrontend() lb.Frontend {
	return lb.Frontend{
		IP:       f.IP,
		Port:     f.GetPort(),
		Protocol: lb.Protocol(f.ServicePort.Protocol),
	}
}

// K8sService is the internal representation of a Kubernetes service
type K8sService struct {
	meta

	// ID identifies a Kubernetes services
	ID ID

	// internal copy of the original resource
	res v1.Service

	// Frontends is the list of frontend configurations
	Frontends map[string]*K8sFrontend
}

// String returns a human readable identifier of a Kubernetes service
func (s *K8sService) String() string {
	return fmt.Sprintf("%s/%s", s.res.Namespace, s.res.Name)
}

// Search looks for a duplicate of need and returns it
func (s *K8sService) Search(need *K8sFrontend) *K8sFrontend {
	id := need.ID()
	if _, ok := s.Frontends[id]; ok {
		return s.Frontends[id]
	}

	return nil
}

// MergeConfiguration merges a new Kubernetes service configuration into an
// existing service configuration and marks frontends as modified or deleted
func (s *K8sService) MergeConfiguration(newSvc *K8sService) {
	// Mark all existing frontends for deletion
	for key := range s.Frontends {
		s.Frontends[key].deleted = true
	}

	for _, newFrontend := range newSvc.Frontends {
		if existing := s.Search(newFrontend); existing != nil {
			existing.deleted = false
		} else {
			newFrontend.modified = true
			s.Frontends[newFrontend.ID()] = newFrontend
		}
	}

	s.res = newSvc.res
}

func validateServicePorts(svc *v1.Service) error {
	validator := lb.NewPortValidator("port.Name", "port.Port", true)
	for _, port := range svc.Spec.Ports {
		validator.Queue(port.Name, uint16(port.Port), string(port.Protocol))
	}

	if err := validator.Validate(); err != nil {
		return err
	}

	validator = lb.NewPortValidator("port.TargetPort (string)", "port.TargetPort (int)", false)
	for _, port := range svc.Spec.Ports {
		// If specified, TargetPort must be unique
		if port.TargetPort.StrVal != "" || port.TargetPort.IntVal != 0 {
			validator.Queue(port.TargetPort.StrVal, uint16(port.TargetPort.IntVal), string(port.Protocol))
		}
	}

	return validator.Validate()
}

func newClusterIP(svc *v1.Service) (map[string]*K8sFrontend, error) {
	m := map[string]*K8sFrontend{}

	ip, err := lb.ParseServiceIP(svc.Spec.ClusterIP)
	if err != nil {
		return nil, fmt.Errorf("invalid ClusterIP: %s", err)
	}

	for i, _ := range svc.Spec.Ports {
		f := &K8sFrontend{
			IP:          ip,
			ServicePort: svc.Spec.Ports[i],
		}
		m[f.ID()] = f
	}

	return m, nil
}

// parseK8sService validates and parses a Kubernets service, returns:
//  - A valid K8sService with n frontends
//  - nil if no service needs to be configured (headless service)
//  - error if the spec contained an error
func parseK8sService(svc *v1.Service) (*K8sService, error) {
	service := &K8sService{
		ID: NewK8sServiceID(svc),
	}

	if err := validateServicePorts(svc); err != nil {
		return nil, err
	}

	service.res = *svc

	switch svc.Spec.Type {
	case v1.ServiceTypeClusterIP:
		if strings.ToLower(svc.Spec.ClusterIP) == "none" || svc.Spec.ClusterIP == "" {
			return nil, nil
		}

		f, err := newClusterIP(svc)
		if err != nil {
			return nil, err
		}
		service.Frontends = f

	default:
		return nil, fmt.Errorf("unsupported type %s", svc.Spec.Type)
	}

	return service, nil
}
