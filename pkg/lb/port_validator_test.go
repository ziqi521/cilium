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
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LBSuite struct{}

var _ = Suite(&LBSuite{})

func (s *LBSuite) TestPortValidator(c *C) {
	// invalid protocol name
	v := NewPortValidator("a", "b", true)
	v.Queue("foo", 80, "invalid")
	c.Assert(v.Validate(), Not(IsNil))

	// duplicate port number
	v = NewPortValidator("a", "b", true)
	v.Queue("foo1", 80, "TCP")
	v.Queue("foo2", 80, "TCP")
	c.Assert(v.Validate(), Not(IsNil))

	// duplicate port name
	v = NewPortValidator("a", "b", true)
	v.Queue("http", 80, "TCP")
	v.Queue("http", 8080, "TCP")
	c.Assert(v.Validate(), Not(IsNil))

	// missing port name with more than one port
	v = NewPortValidator("a", "b", true)
	v.Queue("", 80, "TCP")
	v.Queue("http", 8080, "TCP")
	c.Assert(v.Validate(), Not(IsNil))

	// valid missing port name with one port
	v = NewPortValidator("a", "b", true)
	v.Queue("", 80, "TCP")
	c.Assert(v.Validate(), IsNil)

	// valid multi port definition
	v = NewPortValidator("a", "b", true)
	v.Queue("http", 80, "TCP")
	v.Queue("https", 443, "TCP")
	c.Assert(v.Validate(), IsNil)
}
