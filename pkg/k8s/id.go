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

// ID uniquely identifies a Kubernetes resource in the cluster
type ID struct {
	Name      string
	Namespace string
}

// String returns the human readable version of an ID
func (i *ID) String() string {
	return i.Namespace + "/" + i.Name
}

// Equal returns true if both services IDs are equal
func (i *ID) Equal(o ID) bool {
	return i != nil && i.Name != "" && i.Name == o.Name && i.Namespace == o.Namespace
}

// NewID returns an ID for a given name in a namespace
func NewID(name, namespace string) ID {
	return ID{Name: name, Namespace: namespace}
}
