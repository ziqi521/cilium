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

package lb

import (
	"fmt"

	. "gopkg.in/check.v1"
)

type TestLB struct{}

func (t TestLB) DeleteService(svc *Service) error {
	return nil
}

func (t TestLB) AddOrReplaceService(svc *Service) error {
	return nil
}

func (s *LBSuite) TestConfigurationAddDelete(c *C) {
	id := ServiceID(10)
	cfg := NewConfiguration(TestLB{})

	// service should not exist
	_, err := cfg.GetService(id)
	c.Assert(err, Not(IsNil))

	// add service
	cfg.AddOrReplaceService(id, Frontend{}, []Backend{}, ServiceConfiguration{})

	// service should exist
	svc, err := cfg.GetService(id)
	c.Assert(err, IsNil)
	c.Assert(svc.ID, Equals, id)
	c.Assert(svc.OutOfSync, Equals, false)
	c.Assert(svc.Deleted, Equals, false)

	// replace service
	cfg.AddOrReplaceService(id, Frontend{}, []Backend{}, ServiceConfiguration{})

	// service should still exist
	svc, err = cfg.GetService(id)
	c.Assert(err, IsNil)
	c.Assert(svc.ID, Equals, id)
	c.Assert(svc.OutOfSync, Equals, false)
	c.Assert(svc.Deleted, Equals, false)

	// delete service
	queued := cfg.DeleteService(id)
	c.Assert(queued, Equals, true)

	// service should be gone
	_, err = cfg.GetService(id)
	c.Assert(err, Not(IsNil))
}

type TestLBFail struct{}

var lbError error

func (t TestLBFail) DeleteService(svc *Service) error { return lbError }

func (t TestLBFail) AddOrReplaceService(svc *Service) error { return lbError }

func (s *LBSuite) TestConfigurationSync(c *C) {
	// tests that deletion succeeds if loadbalancer comes back in time

	id1, id2 := ServiceID(1), ServiceID(20000)
	cfg := NewConfiguration(TestLBFail{})

	// service should not exist
	_, err := cfg.GetService(id1)
	c.Assert(err, Not(IsNil))

	lbError = nil

	// add services
	cfg.AddOrReplaceService(id1, Frontend{}, []Backend{}, ServiceConfiguration{})
	cfg.AddOrReplaceService(id2, Frontend{}, []Backend{}, ServiceConfiguration{})

	// service should exist
	svc, err := cfg.GetService(id1)
	c.Assert(err, IsNil)
	c.Assert(svc.ID, Equals, id1)
	c.Assert(svc.OutOfSync, Equals, false)
	c.Assert(svc.Deleted, Equals, false)

	svc, err = cfg.GetService(id2)
	c.Assert(err, IsNil)
	c.Assert(svc.ID, Equals, id2)
	c.Assert(svc.OutOfSync, Equals, false)
	c.Assert(svc.Deleted, Equals, false)

	// let DeleteService in loadbalancer fail
	lbError = fmt.Errorf("error")

	// schedule both services for deletion, immediate delete will fail
	queued := cfg.DeleteService(id1)
	c.Assert(queued, Equals, true)
	queued = cfg.DeleteService(id2)
	c.Assert(queued, Equals, true)

	// attempt to sync (delete) just up to the MaxSyncAttempts
	for i := uint(0); i < (MaxSyncAttempts - 1); i++ {
		svc, err = cfg.GetService(id1)
		c.Assert(err, IsNil)
		c.Assert(svc.ID, Equals, id1)
		c.Assert(svc.Deleted, Equals, true)
		cfg.Sync()
	}

	// let DeleteService in loadbalancer succeed
	lbError = nil
	cfg.Sync()

	// services should be gone
	_, err = cfg.GetService(id1)
	c.Assert(err, Not(IsNil))
	_, err = cfg.GetService(id2)
	c.Assert(err, Not(IsNil))
}

func (s *LBSuite) TestConfigurationSyncMaxAttempts(c *C) {
	// tests that deletion succeeds if loadbalancer does not come back in time

	id1, id2 := ServiceID(1), ServiceID(20000)
	cfg := NewConfiguration(TestLBFail{})

	lbError = nil

	// add services
	cfg.AddOrReplaceService(id1, Frontend{}, []Backend{}, ServiceConfiguration{})
	cfg.AddOrReplaceService(id2, Frontend{}, []Backend{}, ServiceConfiguration{})

	// let DeleteService in loadbalancer fail
	lbError = fmt.Errorf("error")

	// schedule both services for deletion, immediate delete will fail
	queued := cfg.DeleteService(id1)
	c.Assert(queued, Equals, true)
	queued = cfg.DeleteService(id2)
	c.Assert(queued, Equals, true)

	// sync MaxSyncAttempts times
	for i := uint(0); i <= MaxSyncAttempts; i++ {
		cfg.Sync()
	}

	// MaxSyncAttempts must have been reached, and services should be gone
	_, err := cfg.GetService(id1)
	c.Assert(err, Not(IsNil))
	_, err = cfg.GetService(id2)
	c.Assert(err, Not(IsNil))
}
