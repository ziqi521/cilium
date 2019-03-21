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
	"crypto/sha512"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/api"
)

// IdentitySelector is used as a map key, so it must not be
// implemented by a map, slice, or a func, or a runtime panic will be
// triggered. In all cases below IdentitySelector is being implemented
// by structs.
type IdentitySelector interface {
	Matches(id *identity.Identity) bool
	Caches(nid identity.NumericIdentity) bool
}

// IdentitySelector represents the mapping of an EndpointSelector
// to a slice of identities. These mappings are updated via two
// different processes:
//
// 1. When policy rules are changed these are added and/or deleted
// depending on what selectors the rules contain. Cached selections of
// new IdentitySelectors are pre-populated from the set of currently
// known identities.
//
// 2. When reachacble identities appear or disappear, either via local
// allocation (CIDRs), or via the KV-store (remote endpoints). In this
// case all existing IdentitySelectors are walked through and their
// cached selections are updated as necessary.
//
// In both of the above cases the set of existing IdentitySelectors is
// write locked.
//
// To minimize the upkeep the identity selectors are shared accross
// all IdentityPolicies, so that only one copy exists for each
// EndpointSelector. Cilium API layer takes care of creating
// IdentitySelectors before distributing policy updates to various
// IdentityPolicies. The set of IdentitySelectors is read locked
// during an IdentityPolicy update so that the the policy is always
// updated using a coherent set of cached selections.  Each
// IdentityPolicy pools the needed updates to 'Referals' and makes the
// updates to the IdentitySelectors after the policy update while
// holding a write lock on identitySelectors.b

var (
	identitySelectorMutex lock.RWMutex
	// map key is SHA sum as a string, value is an interface
	// through which the pointed to value can be manipulated.
	identitySelectors = make(map[string]IdentitySelector)
)

type LabelIdentitySelector struct {
	Referals        map[*IdentityPortPolicy]struct{}
	Selector        api.EndpointSelector                  // incremental rule layer
	CachedSelection map[identity.NumericIdentity]struct{} // map to identity layer
}

func (l *LabelIdentitySelector) Matches(id *identity.Identity) bool {
	return l.Selector.Matches(id.LabelArray)
}

func (l *LabelIdentitySelector) Caches(nid identity.NumericIdentity) bool {
	_, exists := l.CachedSelection[nid]
	return exists
}

type FQDNSelector struct {
	Referals        map[*IdentityPortPolicy]struct{}
	Selector        api.EndpointSelector                // fqdn:isovalent.com
	CachedSelection map[string]identity.NumericIdentity // identity.String(): "cidr:1.1.1.1" -> identity of 1.1.1.1
}

func (f *FQDNSelector) Matches(id *identity.Identity) bool {
	return f.Selector.Matches(id.LabelArray)
}

func (l *FQDNSelector) Caches(nid identity.NumericIdentity) bool {
	for _, v := range l.CachedSelection {
		if v == nid {
			return true
		}
	}
	return false
}

// GetIdentitySelector returns the identity selector for a particular
// EndpointSelector. If an IdentitySelector with an identical
// EndpointSelector already exists, that IdentitySelector is returned, if
// it does not exist, it is created and added to the cache.
// 'idCache' is the collections of all known identities at the time the
// lock on this identity selectors cache was taken. If nil, no new
// entries can be created.
func GetIdentitySelectorLocked(selector api.EndpointSelector, idCache cache.IdentityCache) IdentitySelector {
	// Compute the map key by marshaling the k8s labelselector and taking a sha sum of it.
	data, err := selector.LabelSelector.Marshal()
	if err != nil {
		metrics.PolicyImportErrors.Inc()
		log.WithError(err).WithField(logfields.EndpointLabelSelector,
			logfields.Repr(selector.LabelSelector)).Error("unable to Marshal selector in label selector")
		return nil
	}
	sha := sha512.Sum512_256(data)
	key := string(sha[:])
	identitySelector, exists := identitySelectors[key]
	if exists {
		return identitySelector
	}

	// Identity cache is needed to create new entries.
	if idCache == nil {
		return nil
	}

	// Selectors are never modified once a rule is placed in the policy repository,
	// so no need to copy.

	// TODO: FQDNSelector

	newIdSel := &LabelIdentitySelector{
		Referals: make(map[*IdentityPortPolicy]struct{}),
		Selector: selector,
	}
	// Find all matching identities from the identity cache.
	// Identity cache manipulations will result in updates that
	// are processed once our lock is released.
	for numericID, lbls := range idCache {
		if selector.Matches(lbls) {
			newIdSel.CachedSelection[numericID] = struct{}{}
		}
	}

	identitySelectors[key] = newIdSel
	return newIdSel
}

type pendingUpdate struct {
	ref   *IdentityPortPolicy
	event *identityUpdateEvent
}

func SyncIdentitySelectors(added, deleted cache.IdentityCache) {
	// updates collects identity update events to be sent after unlocking
	var updates []pendingUpdate

	identitySelectorMutex.Lock()

	for _, sel := range identitySelectors {
		var adds, dels []identity.NumericIdentity
		switch idSel := sel.(type) {
		case LabelIdentitySelector:
			for numericID := range deleted {
				if _, exists := idSel.CachedSelection[numericID]; exists {
					dels = append(dels, numericID)
					delete(idSel.CachedSelection, numericID)
				}
			}
			for numericID, lbls := range added {
				if idSel.Selector.Matches(lbls) {
					adds = append(adds, numericID)
					idSel.CachedSelection[numericID] = struct{}{}
				}
			}
			if len(dels) > 0 || len(adds) > 0 {
				for ref := range idSel.Referals {
					updates = append(updates, pendingUpdate{
						ref: ref,
						event: &identityUpdateEvent{
							selector: selector,
							adds:     adds,
							dels:     dels,
						}})
				}
			}
		case FQDNSelector:
			// TODO
		}
	}
	identitySelectorMutex.Unlock()

	for update := range updates {
		update.ref.IdentitySelectorUpdated(update.event)
	}
}
