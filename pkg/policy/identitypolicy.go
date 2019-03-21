// Copyright 2019 Authors of Cilium
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

package policy

import (
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

type UUID string

type IdentityPolicy struct {
	Ingress DirectionalPolicy
	Egress  DirectionalPolicy
}

// DirectionalPolicy is the list of allowed identities described as label based
// selectors. If empty, no identities are whitelisted. In policy=always mode,
// this would drop everything, policy=auto and k8s mode, this will translate
// into default allow.
// Key is Port/Protocol
type DirectionalPolicy map[uint32]*IdentityPortPolicy // L3 allowed identities for ingress/egress.

func portPolicyKey(port uint16, proto u8proto.U8proto) uint32 {
	return uint32(port) | uint32(proto)<<16
}

func (ip *IdentityPolicy) getIdentityPortPolicy(port uint16, proto u8proto.U8proto, dir trafficdirection.TrafficDirection) *IdentityPortPolicy {
	key := portPolicyKey(port, proto)
	if dir == trafficdirection.Egress {
		return ip.Egress[key]
	}
	return ip.Ingress[key]
}

func (ip *IdentityPolicy) putIdentityPortPolicy(policy *IdentityPortPolicy) {
	key := portPolicyKey(policy.Port, policy.Protocol)
	if policy.Direction == trafficdirection.Egress {
		ip.Egress[key] = policy
	}
	ip.Ingress[key] = policy
}

type IdentityPortPolicy struct {
	// handler owns this policy.
	// Immutable
	handler *identityPolicyHandler

	//  Port is the L4, if not set, all ports apply
	// +optional
	// Immutable
	Port uint16

	// Protocol is the L4 protocol, if not set, all protocols apply
	// +optional
	// Immutable
	Protocol u8proto.U8proto

	// Direction is either Ingress or Egress
	// Incoming identity updates need this
	// Immutable
	Direction trafficdirection.TrafficDirection

	// AllowedIdentities is the list of referenced identity selectors.
	// Identity selectors are shared between all IdentityPolicy instances.
	//
	// The IdentitySelector pointer is used as a key. As duplicate usage of
	// the same IdentitySelector instances means that the identiy selector
	// is identical so the selection is guaranteed to be identical
	AllowedIdentities map[IdentitySelector]*AllowedIdentity

	// ContributingRules is the list of rule UUIDs that cause this identity
	// to be whitelisted
	ContributingRules []UUID
}

// AllowedIdentity contains an allow identity selector as whitelisted by one or
// more rules as selected by the IdentityPolicy which is owning this
// AllowedIdentity
type AllowedIdentity struct {
	ContributingRules []UUID
	// L7Policy for this IdentitySelector in this IdentityPortSelector
	L7Policy *api.L7Rules
	Selector IdentitySelector
}

// IdentitySelectorUpdated notifies the policy handler about an updated IdentitySelector
// Called while the global IdentitySelector write lock is held to ensure
func (ipp *IdentityPortPolicy) IdentitySelectorUpdated(event *identityUpdateEvent) {
	// Caller has initialized 'selector', 'adds', and 'dels'.
	// Fill in the identifying fields. Do not use a pointer here, as
	// a policy change could remove this port selector before this change is
	// processed, and we must not cause datapath updates to be generated in that case!
	event.port = ipp.Port
	event.protocol = ipp.Protocol
	event.direction = ipp.Direction

	ipp.handler.events <- event
}
