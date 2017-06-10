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
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
)

// NewK8sIngressID returns the ID of an ingress resource
func NewK8sIngressID(i *v1beta1.Ingress) ID {
	return NewID(i.Name, i.Namespace)
}

// K8sService is the internal representation of a Kubernetes service
type K8sIngress struct {
	meta

	// ID identifies this ingress
	ID ID

	// internal copy of the original resource
	resource v1beta1.Ingress

	// ServiceName refers to the service to loadbalance to within the same namespace
	ServiceName string

	// Port to listen on
	Port uint16
}

// GetServiceID returns the service to which an ingress resource points to
func (i *K8sIngress) GetServiceID() ID {
	return NewID(i.ServiceName, i.resource.Namespace)
}

// parseK8sIngress parses an ingress spec and returns a K8sIngress or an error
func parseK8sIngress(ingress *v1beta1.Ingress) (*K8sIngress, error) {
	if ingress.Spec.Backend == nil {
		return nil, fmt.Errorf("only single service ingress supported for now")
	}

	if ingress.Spec.Backend.ServiceName == "" {
		return nil, fmt.Errorf("missing service name")
	}

	return &K8sIngress{
		ID:          NewID(ingress.Name, ingress.Namespace),
		resource:    *ingress,
		Port:        uint16(ingress.Spec.Backend.ServicePort.IntValue()),
		ServiceName: ingress.Spec.Backend.ServiceName,
	}, nil
}

func ingressIP() string {
	//if d.conf.IPv4Disabled {
	//return d.conf.HostV6Addr.String()
	//	return "1.1.1.1"
	//}

	//return d.conf.HostV4Addr.String()
	return "::1"
}

// UpdateStatus updates the status of an ingress
func (i *K8sIngress) UpdateStatus(client *kubernetes.Clientset) error {
	hostname, _ := os.Hostname()
	i.resource.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{
		{
			IP:       ingressIP(),
			Hostname: hostname,
		},
	}

	_, err := client.Extensions().Ingresses(i.resource.Namespace).UpdateStatus(&i.resource)
	if err != nil {
		return fmt.Errorf("unable to update status of ingress %s: %s", i.resource.Name, err)
	}

	return nil
}
