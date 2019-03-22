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
	"github.com/cilium/cilium/pkg/policy/iapi"
)

// Subscribe asks the policy package to start producing datapath
// policy update events related to the given security identity
// 'id'. Multiple callers may subscribe with the same 'id'. The given
// 'id' may not change during the lifetime of the subscription; the
// subscription should be cancelled after policy updates on the given
// 'id' are no longer of interest to the caller.
//
// An error is returned if a subcription can not be made, otherwise a
// Subscription is returned.
func Subscribe(ID identity.NumericIdentity, name string) (iapi.Subscription, error) {
	handler := getHandler(ID)
	sub := newSubscription(handler, name)
	err := handler.EnqueueEvent(subscribeEvent{subscription: sub})
	return sub, err
}

// subscription implements the iapi.Subscription interface
type subscription struct {
	// handler for this subscription. This handler owns this subscription and
	// will manipulate all members without taking any locks.
	//
	// Immutable after initialization
	handler *identityPolicyHandler

	// Immutable after initialization
	name string

	// updates is the channel for sending datapath deltas implementing
	// new policy revisions.
	//
	// Immutable after initialization, but closed on unsubscribe.
	updates chan iapi.DatapathUpdateTransaction

	// nextTransaction is used to accumulate datapath deltas for a
	// pending update.  This can be placed on the 'updates'
	// channel at earliest when all the deltas implementing the
	// indicated policy revision are collected here. This means
	// that while this may contain a partial set of deltas needed
	// for the next policy revision, such partial set is never
	// sent on the 'updates' channel.  Multiple updates may be
	// coalesced together if the 'updates' channel is blocking.
	nextTransaction iapi.DatapathUpdateTransaction

	// updatedRevision is the last revision number sent on the
	// 'updates' channel.
	updatedRevision iapi.PolicyRevision

	// realizedRevision is the last acknowledged revision received
	// for this subscription.
	realizedRevision iapi.PolicyRevision
}

func newSubscription(handler *identityPolicyHandler, name string) *subscription {
	return &subscription{
		handler: handler,
		name:    name,
		updates: make(chan iapi.DatapathUpdateTransaction, 1),
	}
}

func (s *subscription) ID() identity.NumericIdentity {
	return s.handler.ID
}

// GetUpdatesChannel returns the channel from which the datapath updates can be
// read from.
func (s *subscription) GetUpdatesChannel() <-chan iapi.DatapathUpdateTransaction {
	// May return a closed channel, if the subscription has already been cancelled
	return s.updates
}

func (s *subscription) Unsubscribe() {
	// Ignoring error return, if the handler is already closed, it has no
	// subscriptions.
	s.handler.EnqueueEvent(unsubscribeEvent{subscription: s})
}

func (s *subscription) AckRevision(revision iapi.PolicyRevision) error {
	return s.handler.EnqueueEvent(ackRevisionEvent{subscription: s, revision: revision})
}

func (s *subscription) NackRevision(revision iapi.PolicyRevision, err error) error {
	return s.handler.EnqueueEvent(nackRevisionEvent{subscription: s, revision: revision, err: err})
}
