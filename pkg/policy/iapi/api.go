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

package iapi

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

// PolicyRevision is a monotonically increasing number that identifies
// different policy versions in the policy repository.
type PolicyRevision uint64

// L7Policy refers to an immutable L7 policy applicable to a port.
type L7Policy interface{}

// Subscription provides the interface through which a datapath
// interacts with the a network policy subscription.
type Subscription interface {
	// ID returns the numeric identity this subscription is about.
	ID() identity.NumericIdentity

	// GetUpdatesChannel returns a buffered channel on which
	// the datapath receives policy update events. In the
	// beginning of a subsciption the datapath is assumed to be in
	// a blank state. The policy package may cancel the
	// subscription by closing the returned channel.  The same
	// channel is returned if this is called multiple times. A closed
	// channel is returned if the subscription has already been
	// cancelled either by the policy package, or by the datapath
	// (via the Unsubscribe() call).
	//
	// The caller updates the datapath state as directed by
	// datapath update events produced as result of this
	// subscription on the returned channel.
	//
	// Datapath update events are grouped into transactions
	// identified by an IdentityPolicy revision number. The caller
	// informs the Subscription via the AckRevision() when
	// the transaction has been successfully implemented on the
	// datapath. Upon the policy package discretion this
	// subscription may be cancelled if the datapath fails to
	// implement a policy revision in a timely manner.
	//
	// The returned updates channel is buffered. If the updates
	// channel would block, the Subscription may coalesce multiple
	// policy update revisions together, identify the coalesced
	// transaction with the revision number of the latest policy
	// update being applied, and send it to the updates channel
	// when there is room in the channel. Upon the policy package
	// discretion this subscription may be cancelled if the caller
	// fails to unblock the updates channel within a reasonable
	// time.
	GetUpdatesChannel() <-chan DatapathUpdateTransaction

	// Unsubscribe is used to cancel the subscription.
	// Idempotent - safe to call when the subscription has already been
	// cancelled.
	Unsubscribe()

	// AckRevision is used to tell the policy package that a
	// policy revision received on the updates channel has been
	// realized by the datapath. Passing a revision that has not
	// been sent on the updates channel yet will cause the
	// subscription to be cancelled.
	AckRevision(revision PolicyRevision) error
}

type DatapathUpdateTransaction struct {
	// Policy revision implemented when this transaction has been
	// successfully applied to the datapath. Revision is strictly
	// increasing, so at most one DatapathUpdateTransaction is
	// sent for a specific Revision.
	Revision PolicyRevision

	// Ordered set of datapath update events needed to realize the
	// new policy revision. Must be executed in order they appear
	// in the slice.  Each DatapathDelta is immutable and must not
	// be modified by anyone after being exposed in any
	// DatapathUpdateTransaction.
	Deltas []*DatapathDelta
}

type DatapathOperation uint8

const (
	// Flush deletes all datapath state related to this
	// subscription. First operation on a new subscription is
	// always a Flush, but this can be sent also later.
	Flush DatapathOperation = iota
	// Upsert either inserts a new datapath policy entries, or updates
	// existing entries.
	Upsert
	// Delete removes a datapath policy entries.
	Delete
)

// DatapathDelta encodes changes to the datapath state that must be
// applied as part of the enveloping DatapathUpdateTransaction. A
// single Delete operation may cause multiple datapath map entries to
// be deleted, as a slice of numeric identities is passed in
// AllowedRemotesDelta. Similarly, a single Upsert operation may cause
// multiple datapath map entries to be created or modified, but all
// with the same L7 policy.
type DatapathDelta struct {
	// Operation is the kind of transformation that needs to be done to the
	// datapath policy.
	Operation DatapathOperation

	// Direction in which this delta applies.
	//
	// Not applicable on 'Flush' operation.
	Direction trafficdirection.TrafficDirection

	// Port is the L4. If zero this delta is for the wildcard L4
	// entry in the datapath.
	//
	// Not applicable on 'Flush' operation.
	Port uint16

	// Protocol is the L4 protocol. If zero this delta is for the
	// wildcard protocol entry in the datapath.
	//
	// Not applicable on 'Flush' operation.
	Protocol u8proto.U8proto

	// AllowedRemoteDelta lists the changing remote L3 numeric
	// identities. If empty, the change applies to the wildcard
	// entry on the datapath. Note that this may be a subset of
	// all remote identities allowed on this Port/Protocol as
	// different remotes may require different L7 policies, or
	// because the policy change only applies to a limited set of
	// remote identities. If empty, Port/Protocol must be set,
	// otherwise Port/Protocol may be given as zeroes.
	//
	// Not applicable on 'Flush' operation.
	AllowedRemotesDelta []identity.NumericIdentity

	// L7 policy applicable on this Port/Protocol for the given
	// set of AllowedRemotesDelta, or nil of there is no L7 policy
	// on this Port/Protocol for the given AllowedRemotesDelta.
	// If non-nil, the Port must be non-zero (no L7 policy on
	// wildcard L4).
	//
	// On a Delete operation this is nil, allowing for multiple
	// different L7 policies being deleted with a single delta.
	//
	// Each L7Policy is immutable and must not be modified by
	// anyone after being exposed in any DatapathDelta.
	//
	// Not applicable on 'Flush' operation.
	L7 *api.L7Rules
}
