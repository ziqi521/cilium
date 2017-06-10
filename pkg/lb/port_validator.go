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
)

type portSpec struct {
	name     string
	protocol string
	port     uint16
}

// PortValidator will validate a list of port definition to ensure the
// following constraints:
// - the same port name is only specified once
// - the same port number is only specified once
// - the protocol is valid (ValidateProtocol() returns true)
//
// If requireName is set:
// - if more than one port is defined, each port must have a valid name
type PortValidator struct {
	nameField   string
	numberField string
	requireName bool
	spec        []portSpec
}

// NewPortValidator returns a new port validator. nameField is the name of the
// field carrying the port name, numberField is the name of the field carrying
// the port number, requireName must be true if either name or port are mandatory
func NewPortValidator(nameField, numberField string, requireName bool) *PortValidator {
	return &PortValidator{
		nameField:   nameField,
		numberField: numberField,
		requireName: requireName,
		spec:        []portSpec{},
	}
}

// Queue schedule a port definition for validation
func (pv *PortValidator) Queue(portName string, portNumber uint16, protocol string) {
	pv.spec = append(pv.spec, portSpec{
		port:     portNumber,
		name:     portName,
		protocol: protocol,
	})
}

// Validate returns nil if the all enqueued port definition are valid as
// defined or an error
func (pv *PortValidator) Validate() error {
	portsName := map[string]bool{}
	portsNumber := map[string]bool{}

	for _, port := range pv.spec {
		if err := ValidateProtocol(port.protocol); err != nil {
			return err
		}

		if port.name == "" && pv.requireName {
			if len(pv.spec) > 1 {
				return fmt.Errorf("%s must be specified if more than one port is specified", pv.nameField)
			}

			port.name = "default"
		}

		if port.name == "" && port.port == 0 && pv.requireName {
			return fmt.Errorf("either %s or %s must be be provided", pv.nameField, pv.numberField)
		}

		if port.name != "" {
			p := port.protocol + ":" + port.name
			if _, ok := portsName[p]; ok {
				return fmt.Errorf("%s '%s' must be unique", pv.nameField, port.name)
			}

			portsName[p] = true
		}

		if port.port != 0 {
			p := fmt.Sprintf("%s:%d", port.protocol, port.port)

			if _, ok := portsNumber[p]; ok {
				return fmt.Errorf("%s '%d' must be unique", pv.numberField, port.port)
			}

			portsNumber[p] = true
		}
	}

	return nil
}
