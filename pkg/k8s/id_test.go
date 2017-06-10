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
	. "gopkg.in/check.v1"
)

func (s *K8sSuite) TestIDEqual(c *C) {
	id1 := ID{Name: "foo", Namespace: "foo"}
	id2 := ID{Name: "bar", Namespace: "foo"}
	id3 := ID{Name: "foo", Namespace: "bar"}

	tests := []struct {
		a      ID
		b      ID
		result bool
	}{
		{id1, id1, true}, {id1, id2, false}, {id1, id3, false},
		{id2, id1, false}, {id2, id2, true}, {id2, id3, false},
		{id3, id1, false}, {id3, id2, false}, {id3, id3, true},
	}

	for _, test := range tests {
		c.Assert(test.a.Equal(test.b), Equals, test.result)
	}
}
