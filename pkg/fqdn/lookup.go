// Copyright 2018 Authors of Cilium
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

package fqdn

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// DNSIPRecords mimics the RR data from an A or AAAA response.
// My kingdom for a DNS IP RR type that isn't hidden in the stdlib or has a
// million layers of type indirection.
type DNSIPRecords struct {
	// TTL is the time, in seconds, that these IPs are valid for
	TTL int

	// IPs are the IPs associated with a DNS Name
	IPs []net.IP
}

var (
	// dnsConfig is the general config. It must be set via SetDNSConfig otherwise
	// no lookups will actually happen.
	dnsConfig = &dns.ClientConfig{
		Servers: nil,
	}

	// clientUDP and clientTCP can be reused, and will coalesce multiple queries
	// for the same (Qname, Qtype, Qclass)
	clientUDP, clientTCP *dns.Client
)

// ConfigFromResolvConf parses the configuration in /etc/resolv.conf and sets
// the configuration for pkg/fqdn.
// nameservers and opt timeout are supported.
// search and ndots are NOT supported.
// This call is not thread safe.
func ConfigFromResolvConf() error {
	dnsConf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	SetDNSConfig(dnsConf)

	return nil
}

// SetDNSConfig store conf in pkg/fqdn as the global config. It also creates
// the global UDP and TCP clients used for DNS lookups in
// DNSLookupDefaultResolver.
// Only .Servers and .Timeout are utilized from conf.
// This call is not thread safe.
func SetDNSConfig(conf *dns.ClientConfig) {
	dnsConfig = conf

	clientUDP = &dns.Client{
		Net:            "udp",
		Timeout:        time.Duration(dnsConfig.Timeout) * time.Second,
		SingleInflight: true,
	}

	clientTCP = &dns.Client{
		Net:            "tcp",
		Timeout:        time.Duration(dnsConfig.Timeout) * time.Second,
		SingleInflight: true,
	}
}
