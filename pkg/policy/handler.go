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
	"fmt"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/iapi"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// Set of running handlers, one for each locally present security identity
	handlerMutex lock.Mutex
	handlers     = make(map[identity.NumericIdentity]*identityPolicyHandler)
)

func getHandler(ID identity.NumericIdentity) *identityPolicyHandler {
	handlerMutex.Lock()
	handler, exists := handlers[ID]
	if !exists {
		handler = newIdentityPolicyHandler(ID)
		handlers[ID] = handler
	}
	handlerMutex.Unlock()
	return handler
}

type identityPolicyHandler struct {
	// id is the security identity which this handler takes care of.
	//
	// Immutable after initialization.
	ID identity.NumericIdentity

	// events is the channel for sending policy events to the handler,
	// such as acknowledgements for realized policy revisions from
	// the datapath.
	//
	// Immutable after initialization. Never closed.
	events chan interface{}

	// done is closed when the handler exits
	done chan struct{}

	// The remaining fields are only accessed by the handler

	// nextTransaction is used to accumulate datapath deltas for a
	// pending update.  This can be placed on the 'updates'
	// channel at earliest when all the deltas implementing the
	// indicated policy revision are collected here. This means
	// that while this may contain a partial set of deltas needed
	// for the next policy revision, such partial set is never
	// sent on the 'updates' channel.  Multiple updates may be
	// coalesced together if the 'updates' channel is blocking.
	nextTransaction iapi.DatapathUpdateTransaction

	// Set of subscriptions on this identity
	subscriptions map[*subscription]struct{}

	//
	// Incremental policy for this handler
	//
	policy IdentityPolicy
}

//
// Definitions of handler events.
//
// Types with '_' suffix are used only for composing the actual event
// types, never sent on the events channel as such.
//
type exitEvent struct{}

type funcEvent struct {
	fn   func()
	done chan struct{}
}

type subscribeEvent struct {
	// subscription identifies the subscription this event is about
	subscription *subscription
}

type unsubscribeEvent struct {
	// subscription identifies the subscription this event is about
	subscription *subscription
}

type ackRevisionEvent struct {
	// subscription identifies the subscription this event is about
	subscription *subscription

	// revision is the PolicyRevision being acknowledged as
	// realized by the datapath.
	revision iapi.PolicyRevision
}

type nackRevisionEvent struct {
	// subscription identifies the subscription this event is about
	subscription *subscription

	// revision is the PolicyRevision being acknowledged as
	// realized by the datapath.
	revision iapi.PolicyRevision

	err error
}

// identityUpdateEvents are received when cached numeric identities of an IdentitySelector
// change. The IdentitySelector is already changed, but this event allows incremental
// datapath updates to be generated corresponsing to the change.
// Immutable, i.e., read-only. The slices are potentially sent to multiple handlers!
type identityUpdateEvent struct {
	port      uint16
	protocol  u8proto.U8proto
	direction trafficdirection.TrafficDirection
	selector  IdentitySelector
	adds      []identity.NumericIdentity
	dels      []identity.NumericIdentity
}

func newIdentityPolicyHandler(ID identity.NumericIdentity) *identityPolicyHandler {
	handler := &identityPolicyHandler{
		ID:            ID,
		events:        make(chan interface{}, 10),
		done:          make(chan struct{}),
		subscriptions: make(map[*subscription]struct{}),
	}

	// Start handling events
	go handler.handle()

	return handler
}

func (h *identityPolicyHandler) Exit() {
	h.events <- exitEvent{}
}

// EnqueueEvent posts an event to the handler's event queue, blocking
// uptil the event can be placed in the queue.
func (h *identityPolicyHandler) EnqueueEvent(event interface{}) error {
	select {
	case <-h.done:
		return fmt.Errorf("Handler finished")
	case h.events <- event:
		return nil
	}
}

func (h *identityPolicyHandler) postFunction(fn func()) error {
	done := make(chan struct{})

	// Wrap function into an event
	err := h.EnqueueEvent(funcEvent{fn: fn, done: done})
	if err == nil {
		// Wait until done.
		<-done
	}
	return err
}

func (h *identityPolicyHandler) Subscriptions() ([]iapi.Subscription, error) {
	var subs []iapi.Subscription
	err := h.postFunction(func() {
		for sub := range h.subscriptions {
			subs = append(subs, sub)
		}
	})
	return subs, err
}

func (h *identityPolicyHandler) handle() {
	// Always flush the datapath to begin with
	h.nextTransaction.Deltas = append(h.nextTransaction.Deltas, &iapi.DatapathDelta{Operation: iapi.Flush})

	stop := false
Loop:
	for !stop {
		// wait for the first datapath delta to be produced
		select {
		case e := <-h.events:
			if h.handleEvent(e) == false {
				break Loop
			}
			if len(h.nextTransaction.Deltas) == 0 {
				continue Loop
			}
		}

		// Check if there are more events to be processed before issuing a datapath
		// transaction.
		select {
		case e := <-h.events:
			stop = !h.handleEvent(e)
		default:
		}

		h.nextTransaction.Revision++ // XXX
		for sub := range h.subscriptions {
			// this may block
			sub.updates <- h.nextTransaction
		}
		// Re-slice to an empty slice
		h.nextTransaction.Deltas = h.nextTransaction.Deltas[:0]
	}
	close(h.done)
}

// handleEvent returns false if the handler must stop.
func (h *identityPolicyHandler) handleEvent(e interface{}) bool {
	switch event := e.(type) {

	//
	// Identity selector update events
	//

	case identityUpdateEvent:
		// locate the identity port selector
		ipp := h.policy.getIdentityPortPolicy(event.port, event.protocol, event.direction)
		if ipp == nil {
			log.Debugf("Port policy for identity update can not be found (%v)", e)
			break
		}
		ai := ipp.AllowedIdentities[event.selector]
		if ai == nil {
			log.Debugf("IdentitySelector not used by port policy any more")
			break
		}
		h.appendIdentityUpdateDeltas(ipp, ai, event.adds, event.dels)

	//
	// Internal events
	//

	case funcEvent:
		event.fn()
		close(event.done)

	//
	// Events from the handler owner (e.g., Identity)
	//

	case exitEvent:
		log.Debugf("Identity policy handler for numeric identity %d exiting.", h.ID)
		h.unsubscribe(nil)
		return false

	//
	// Events from the users (e.g., Endpoint)
	//

	case subscribeEvent:
		h.subscribe(event.subscription)

	case unsubscribeEvent:
		if h.unsubscribe(event.subscription) {
			return false
		}

	//
	// Events from the subscribers (e.g., Datapath)
	//

	case ackRevisionEvent:
		// Ack must be for more recent revision than the last one,
		// and not more recent than what has been sent in the updates
		// channel.
		if event.revision > event.subscription.realizedRevision &&
			event.revision <= event.subscription.updatedRevision {
			event.subscription.realizedRevision = event.revision
		} else {
			log.Warningf("Invalid ack revision (%d), previous: %d, last update: %d",
				event.revision, event.subscription.realizedRevision,
				event.subscription.updatedRevision)
			if h.unsubscribe(event.subscription) {
				return false
			}
		}

	case nackRevisionEvent:
		log.Warningf("Datapath policy update failed (revision %d: %s), unsubscribing.",
			event.revision, event.err)
		if h.unsubscribe(event.subscription) {
			return false
		}

	default:
		log.Warningf("Unknown event type %v", event)
	}
	return true
}

func (h *identityPolicyHandler) subscribe(sub *subscription) {
	// Make subscribe idempotent by checking if subscription does not already exist
	if _, exists := h.subscriptions[sub]; !exists {
		h.subscriptions[sub] = struct{}{}
	}
}

// nil subscription will unsubscribe all subscriptions.
// returns true if there are no more subscriptions
func (h *identityPolicyHandler) unsubscribe(sub *subscription) bool {
	// Make unsubscribe idempotent by pairing updates channel
	// close with deletion of the subscription from the
	// subscriptions map, and only closing if the subscrition
	// still is in the map.
	if sub == nil {
		for sub = range h.subscriptions {
			close(sub.updates)
			delete(h.subscriptions, sub)
		}
	} else {
		if _, exists := h.subscriptions[sub]; exists {
			close(sub.updates)
			delete(h.subscriptions, sub)
		}
	}
	return len(h.subscriptions) == 0
}

// handleIdentityUpdateEvent generates datapath delta updates based on changed identities
// Called by the policy handler only!
func (h *identityPolicyHandler) appendIdentityUpdateDeltas(ipp *IdentityPortPolicy, ai *AllowedIdentity, adds, dels []identity.NumericIdentity) {
	var deletes []identity.NumericIdentity
	// Make sure we do not delete identities that may have been
	// added to the policy while this event was queued
	if len(dels) > 0 {
		for _, nid := range dels {
			if !ai.Selector.Caches(nid) {
				deletes = append(deletes, nid)
			}
		}
	}
	if len(deletes) > 0 {
		h.nextTransaction.Deltas = append(h.nextTransaction.Deltas, &iapi.DatapathDelta{
			Operation:           iapi.Delete,
			Direction:           ipp.Direction,
			Port:                ipp.Port,
			Protocol:            ipp.Protocol,
			AllowedRemotesDelta: deletes,
		})
	}

	var additions []identity.NumericIdentity
	// Make sure we do not add identities that may have been
	// deleted from the policy while this event was queued
	if len(adds) > 0 {
		for _, nid := range adds {
			if ai.Selector.Caches(nid) {
				additions = append(additions, nid)
			}
		}
	}
	if len(additions) > 0 {
		h.nextTransaction.Deltas = append(h.nextTransaction.Deltas, &iapi.DatapathDelta{
			Operation:           iapi.Upsert,
			Direction:           ipp.Direction,
			Port:                ipp.Port,
			Protocol:            ipp.Protocol,
			AllowedRemotesDelta: additions,
			L7Policy:            ai.L7Policy,
		})
	}
}
