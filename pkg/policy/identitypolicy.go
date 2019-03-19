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
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/uuid"
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
type DirectionalPolicy map[int]IdentityPortSelector // L3 allowed identities for ingress/egress.

type IdentityPortSelector struct {
	//  Port is the L4, if not set, all ports apply
	// +optional
	Port uint16

	// Porotocol is the L4 protocol, if not set, all protocols apply
	// +optional
	Protocol u8proto.U8proto

	// L7 policy
	// +optional
	L7 L7Policy

	// AllowedIdentities is the list of referenced identity selectors.
	// Identity selectors are shared between all IdentityPolicy instances.
	//
	// The IdentitySelector pointer is used as a key. As duplicate usage of
	// the same IdentitySelector instances means that the identiy selector
	// is identical so the selection is guaranteed to be identical
	AllowedIdentities map[*IdentitySelector]AllowedIdentity

	// ContributingRules is the list of rule UUIDs that cause this identity
	// to be whitelisted
	ContributingRules []UUID
}

// AllowedIdentity contains an allow identity selector as whitelisted by one or
// more rules as selected by the IdentityPolicy which is owning this
// AllowedIdentity
type AllowedIdentity struct {
	PortSelector      *IdentityPortSelector
	ContributingRules []UUID
	Selector          *IdentitySelector
}

type L7Policy struct {
	ContributingRules []UUID
	Rules             *api.L7Rules
}

// --- ^^ incremental rule layer ^^ --

type IdentitySelector interface {
}

// IdentitySelector represents the mapping of an EndpointSelectorSlice to a
// slice of identities
type LabelIdentitySelector struct {
	Referals        map[*AllowedIdentity]struct{}
	Selector        api.EndpointSelectorSlice // incremental rule layer
	CachedSelection []*identity.Identity      // map to identity layer
}

type FQDNSelector struct {
	Referals        map[*AllowedIdentity]struct{}
	Selector        api.EndpointSelectorSlice     // fqdn:isovalent.com
	CachedSelection map[string]*identity.Identity // identity.String(): "cidr:1.1.1.1" -> identity of 1.1.1.1
}

// GetIdentitySelector returns the identity selector for a particular
// EndpointSelectorSlice. If an IdentitySelector with an identical
// EndpointSelectorSlice already exists, that IdentitySelector is returned, if
// it does not exist, it is created and added to the cache.
func GetIdentitySelector(selector api.EndpointSelectorSlice) *IdentitySelector {
	return nil
}
