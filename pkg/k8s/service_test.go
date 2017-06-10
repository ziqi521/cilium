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
	"net"

	. "gopkg.in/check.v1"
	"k8s.io/client-go/pkg/api/v1"
)

func (s *K8sSuite) TestparseK8sService(c *C) {
	// invalid ClusterIP
	_, err := parseK8sService(&v1.Service{Spec: v1.ServiceSpec{ClusterIP: "invalid"}})
	c.Assert(err, Not(IsNil))

	// invalid ClusterIP IPv4
	_, err = parseK8sService(&v1.Service{Spec: v1.ServiceSpec{ClusterIP: "10..1.1.1"}})
	c.Assert(err, Not(IsNil))

	// invalid ClusterIP IPv6
	_, err = parseK8sService(&v1.Service{Spec: v1.ServiceSpec{ClusterIP: "b44d:::1"}})
	c.Assert(err, Not(IsNil))

	// invalid ServiceType
	_, err = parseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceType("invalid")}})
	c.Assert(err, Not(IsNil))

	// unsupported type: NodePort
	// FIXME
	_, err = parseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceTypeNodePort}})
	c.Assert(err, Not(IsNil))

	// unsupported type: LoadBalancer
	// FIXME
	_, err = parseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceTypeLoadBalancer}})
	c.Assert(err, Not(IsNil))

	// unsupported type: ExternalName
	// FIXME
	_, err = parseK8sService(&v1.Service{Spec: v1.ServiceSpec{Type: v1.ServiceTypeExternalName}})
	c.Assert(err, Not(IsNil))

	// headless service
	svc, err := parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "NONE",
		},
	})
	c.Assert(err, IsNil)
	c.Assert(svc, IsNil)

	// valid IPv4 ClusterIP, no ports
	_, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "10.1.1.1",
		},
	})
	c.Assert(err, IsNil)

	// valid IPv6 ClusterIP, no ports
	_, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "f00d::1",
		},
	})
	c.Assert(err, IsNil)

	// Missing port name for multiple ports
	_, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "", Port: 80},
				{Name: "", Port: 8080},
			},
		},
	})
	c.Assert(err, Not(IsNil))

	// Missing name for single port is valid
	_, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "", Port: 80, Protocol: "TCP"},
			},
		},
	})
	c.Assert(err, IsNil)

	// Unknown protocol
	_, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Protocol: "unknown_proto", Port: 80},
			},
		},
	})
	c.Assert(err, Not(IsNil))

	// Missing protocol
	_, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Protocol: ""},
			},
		},
	})
	c.Assert(err, Not(IsNil))

	// Valid ClusterIP with two ports
	svc, err = parseK8sService(&v1.Service{
		Spec: v1.ServiceSpec{
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.1.1.1",
			Ports: []v1.ServicePort{
				{Name: "http", Port: 80, Protocol: "TCP"},
				{Name: "https", Port: 443, Protocol: "TCP"},
			},
		},
	})
	c.Assert(err, IsNil)

	f, ok := svc.Frontends["1.1.1.1:80/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(f.ServicePort.Port, Equals, int32(80))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))

	f, ok = svc.Frontends["1.1.1.1:443/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(f.IP, DeepEquals, net.ParseIP("1.1.1.1"))
	c.Assert(f.ServicePort.Port, Equals, int32(443))
	c.Assert(f.ServicePort.Protocol, Equals, v1.Protocol("TCP"))
}
