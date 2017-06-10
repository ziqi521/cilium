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

// FIXME: Cleanup this file

package lb

import (
	"encoding/json"
	"path"
	"strconv"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/kvstore"

	log "github.com/Sirupsen/logrus"
)

type FrontendID struct {
	Frontend
	ID ServiceID
}

func (f *FrontendID) GetL3n4AddrID() types.L3n4AddrID {
	return types.L3n4AddrID{
		L3n4Addr: types.L3n4Addr{
			IP: f.IP,
			L4Addr: types.L4Addr{
				Protocol: types.L4Type(f.Protocol),
				Port:     f.Port,
			},
		},
		ID: f.ID,
	}
}

func getMaxServiceID() (uint32, error) {
	return kvstore.Client.GetMaxID(common.LastFreeServiceIDKeyPath, common.FirstFreeServiceID)
}

// gasNewL3n4AddrID gets and sets a new L3n4Addr ID. If baseID is different than zero,
// KVStore tries to assign that ID first.
func gasNewL3n4AddrID(f *FrontendID, baseID uint32) error {
	if baseID == 0 {
		var err error
		baseID, err = getMaxServiceID()
		if err != nil {
			return err
		}
	}

	addr := f.GetL3n4AddrID()

	return kvstore.Client.GASNewL3n4AddrID(common.ServiceIDKeyPath, baseID, addr)
}

func acquireGlobalID(f Frontend, baseID int) (ServiceID, error) {
	log.Debugf("Resolving service %+v", f)

	sha256Sum := f.SHA256Sum()
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)

	// Lock that sha256Sum
	lockKey, err := kvstore.Client.LockPath(svcPath)
	if err != nil {
		return 0, err
	}
	defer lockKey.Unlock()

	// After lock complete, get svc's path
	rmsg, err := kvstore.Client.GetValue(svcPath)
	if err != nil {
		return 0, err
	}

	sl4KV := FrontendID{}
	if rmsg != nil {
		if err := json.Unmarshal(rmsg, &sl4KV); err != nil {
			return 0, err
		}
	}
	if sl4KV.ID == 0 {
		sl4KV.L3n4Addr = Frontend
		if err := gasNewL3n4AddrID(&sl4KV, 0); err != nil {
			return 0, err
		}
		if err = kvstore.Client.SetValue(svcPath, sl4KV); err != nil {
			return 0, err
		}
	}

	return sl4KV.ID, err
}

func updateL3n4AddrIDRef(id ServiceID, FrontendID FrontendID) error {
	key := path.Join(common.ServiceIDKeyPath, strconv.FormatUint(uint64(id), 10))
	return kvstore.Client.SetValue(key, FrontendID)
}

func getL3n4AddrID(keyPath string) (*FrontendID, error) {
	rmsg, err := kvstore.Client.GetValue(keyPath)
	if err != nil {
		return nil, err
	}
	if rmsg == nil {
		return nil, nil
	}

	var FrontendID FrontendID
	if err := json.Unmarshal(rmsg, &FrontendID); err != nil || FrontendID.ID == 0 {
		return nil, err
	}
	return &FrontendID, nil
}

// GetL3n4AddrID returns the L3n4AddrID that belongs to the given id.
func GetL3n4AddrID(id uint32) (*FrontendID, error) {
	strID := strconv.FormatUint(uint64(id), 10)
	return getL3n4AddrID(path.Join(common.ServiceIDKeyPath, strID))
}

// GetL3n4AddrIDBySHA256 returns the L3n4AddrID that have the given SHA256SUM.
func GetL3n4AddrIDBySHA256(sha256sum string) (*FrontendID, error) {
	return getL3n4AddrID(path.Join(common.ServicesKeyPath, sha256sum))
}

// DeleteL3n4AddrIDByUUID deletes the L3n4AddrID belonging to the given id.
func DeleteL3n4AddrIDByUUID(id uint32) error {
	FrontendID, err := GetL3n4AddrID(id)
	if err != nil {
		return err
	}
	if FrontendID == nil {
		return nil
	}

	return DeleteL3n4AddrIDBySHA256(FrontendID.SHA256Sum())
}

// DeleteL3n4AddrIDBySHA256 deletes the L3n4AddrID that belong to the serviceL4ID'
// sha256Sum.
func DeleteL3n4AddrIDBySHA256(sha256Sum string) error {
	if sha256Sum == "" {
		return nil
	}
	svcPath := path.Join(common.ServicesKeyPath, sha256Sum)
	// Lock that sha256Sum
	lockKey, err := kvstore.Client.LockPath(svcPath)
	if err != nil {
		return err
	}
	defer lockKey.Unlock()

	// After lock complete, get label's path
	rmsg, err := kvstore.Client.GetValue(svcPath)
	if err != nil {
		return err
	}
	if rmsg == nil {
		return nil
	}

	var FrontendID FrontendID
	if err := json.Unmarshal(rmsg, &FrontendID); err != nil {
		return err
	}
	oldL3n4ID := FrontendID.ID
	FrontendID.ID = 0

	// update the value in the kvstore
	if err := updateL3n4AddrIDRef(oldL3n4ID, FrontendID); err != nil {
		return err
	}

	return kvstore.Client.SetValue(svcPath, FrontendID)
}
