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

package main

import (
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/service"
	"github.com/cilium/cilium/common/types"
	"github.com/cilium/cilium/pkg/apierror"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/lb"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	log "github.com/Sirupsen/logrus"
	"github.com/go-openapi/runtime/middleware"
)

func addIngress() {
	var host net.IP
	if d.conf.IPv4Disabled {
		host = d.conf.HostV6Addr
	} else {
		host = d.conf.HostV4Addr
	}
	ingressSvcInfo := types.NewK8sServiceInfo(host)
	ingressSvcInfo.Ports[types.FEPortName(ingress.Spec.Backend.ServicePort.StrVal)] = fePort

	syncIngress := func(ingressSvcInfo *types.K8sServiceInfo) error {
		d.loadBalancer.K8sIngress[svcName] = ingressSvcInfo

		if err := d.syncExternalLB(&svcName, nil, nil); err != nil {
			return fmt.Errorf("Unable to add ingress service %s: %s", svcName, err)
		}
		return nil
	}
}

func modIngress() {
	// Add RevNAT to the BPF Map for non-LB nodes when a LB node update the
	// ingress status with its address.
	if !d.conf.IsLBEnabled() {
		port := newIngress.Spec.Backend.ServicePort.IntValue()
		for _, loadbalancer := range newIngress.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(loadbalancer.IP)
			if ingressIP == nil {
				continue
			}
			feAddr, err := types.NewL3n4Addr(types.TCP, ingressIP, uint16(port))
			if err != nil {
				log.Errorf("Error while creating a new L3n4Addr: %s. Ignoring ingress %s/%s...", err, newIngress.Namespace, newIngress.Name)
				continue
			}
			feAddrID, err := d.PutL3n4Addr(*feAddr, 0)
			if err != nil {
				log.Errorf("Error while getting a new service ID: %s. Ignoring ingress %s/%s...", err, newIngress.Namespace, newIngress.Name)
				continue
			}
			log.Debugf("Got service ID %d for ingress %s/%s", feAddrID.ID, newIngress.Namespace, newIngress.Name)

			if err := d.RevNATAdd(feAddrID.ID, feAddrID.L3n4Addr); err != nil {
				log.Errorf("Unable to add reverse NAT ID for ingress %s/%s: %s", newIngress.Namespace, newIngress.Name, err)
			}
		}
		return
	}

	if oldIngress.Spec.Backend.ServiceName == newIngress.Spec.Backend.ServiceName &&
		oldIngress.Spec.Backend.ServicePort == newIngress.Spec.Backend.ServicePort {
		return
	}

	d.ingressAddFn(newObj)
}

func deleteIngress() {
	// Remove RevNAT from the BPF Map for non-LB nodes.
	if !d.conf.IsLBEnabled() {
		port := ing.Spec.Backend.ServicePort.IntValue()
		for _, loadbalancer := range ing.Status.LoadBalancer.Ingress {
			ingressIP := net.ParseIP(loadbalancer.IP)
			if ingressIP == nil {
				continue
			}
			feAddr, err := types.NewL3n4Addr(types.TCP, ingressIP, uint16(port))
			if err != nil {
				log.Errorf("Error while creating a new L3n4Addr: %s. Ignoring ingress %s/%s...", err, ing.Namespace, ing.Name)
				continue
			}
			// This is the only way that we can get the service's ID
			// without accessing the KVStore.
			svc := d.svcGetBySHA256Sum(feAddr.SHA256Sum())
			if svc != nil {
				if err := d.RevNATDelete(svc.FE.ID); err != nil {
					log.Errorf("Error while removing RevNAT for ID %d for ingress %s/%s: %s", svc.FE.ID, ing.Namespace, ing.Name, err)
				}
			}
		}
		return
	}

	d.loadBalancer.K8sMU.Lock()
	defer d.loadBalancer.K8sMU.Unlock()

	ingressSvcInfo, ok := d.loadBalancer.K8sIngress[svcName]
	if !ok {
		return
	}

	// Get all active endpoints for the service specified in ingress
	k8sEP, ok := d.loadBalancer.K8sEndpoints[svcName]
	if !ok {
		return
	}

	err := d.delK8sSVCs(svcName, ingressSvcInfo, k8sEP)
	if err != nil {
		log.Errorf("Unable to delete K8s ingress: %s", err)
		return
	}
	delete(d.loadBalancer.K8sIngress, svcName)
}

func (lb *LoadBalancer) syncDatapath() {
}

func (lb *LoadBalancer) Sync() {
	if !d.conf.IsLBEnabled() {
		// Add operations don't matter to non-LB nodes.
		return
	}

	deleteSN := func(delSN k8sServiceID) {
		svc, ok := d.loadBalancer.K8sServices[delSN]
		if !ok {
			delete(d.loadBalancer.K8sEndpoints, delSN)
			return
		}

		endpoint, ok := d.loadBalancer.K8sEndpoints[delSN]
		if !ok {
			delete(d.loadBalancer.K8sServices, delSN)
			return
		}

		if err := d.delK8sSVCs(svc, endpoint); err != nil {
			log.Errorf("Unable to delete k8s service: %s", err)
			return
		}

		delete(d.loadBalancer.K8sServices, delSN)
		delete(d.loadBalancer.K8sEndpoints, delSN)
	}

	addSN := func(addSN k8s.ServiceID) {
		svcInfo, ok := d.loadBalancer.K8sServices[addSN]
		if !ok {
			return
		}

		endpoint, ok := d.loadBalancer.K8sEndpoints[addSN]
		if !ok {
			return
		}

		if err := d.addK8sSVCs(addSN, svcInfo, endpoint); err != nil {
			log.Errorf("Unable to add K8s service: %s", err)
		}
	}

	if delSN != nil {
		// Clean old services
		deleteSN(*delSN)
	}
	if newSN != nil {
		// Add new services
		addSN(*newSN)
	}

	if d.conf.IsLBEnabled() {
		if err := d.syncExternalLB(&endpoints.ID, nil, nil); err != nil {
			log.Errorf("Unable to add endpoints on ingress service %s: %s", id, err)
			return
		}
	}
}

func (d *Daemon) syncExternalLB(newSN, modSN, delSN *k8s.ServiceID) error {
	deleteSN := func(delSN k8s.ServiceID) error {
		ingSvc, ok := d.loadBalancer.K8sIngress[delSN]
		if !ok {
			return nil
		}

		endpoint, ok := d.loadBalancer.K8sEndpoints[delSN]
		if !ok {
			return nil
		}

		if err := d.delK8sSVCs(delSN, ingSvc, endpoint); err != nil {
			return err
		}

		delete(d.loadBalancer.K8sServices, delSN)
		return nil
	}

	addSN := func(addSN k8s.ServiceID) error {
		ingressSvcInfo, ok := d.loadBalancer.K8sIngress[addSN]
		if !ok {
			return nil
		}

		k8sEP, ok := d.loadBalancer.K8sEndpoints[addSN]
		if !ok {
			return nil
		}

		err := d.addK8sSVCs(addSN, ingressSvcInfo, k8sEP)
		if err != nil {
			return err
		}
		return nil
	}

	if delSN != nil {
		// Clean old services
		return deleteSN(*delSN)
	}
	if modSN != nil {
		// Re-add modified services
		return addSN(*modSN)
	}
	if newSN != nil {
		// Add new services
		return addSN(*newSN)
	}
	return nil
}

// addSVC2BPFMap adds the given bpf service to the bpf maps. If addRevNAT is set, adds the
// RevNAT value (feCilium.L3n4Addr) to the lb's RevNAT map for the given feCilium.ID.
func (d *Daemon) addSVC2BPFMap(feCilium types.L3n4AddrID, feBPF lbmap.ServiceKey,
	besBPF []lbmap.ServiceValue, addRevNAT bool) error {

	err := lbmap.AddSVC2BPFMap(feBPF, besBPF, addRevNAT, int(feCilium.ID))
	if err != nil {
		if addRevNAT {
			delete(d.loadBalancer.RevNATMap, feCilium.ID)
		}
		return err
	}
	if addRevNAT {
		d.loadBalancer.RevNATMap[feCilium.ID] = *feCilium.L3n4Addr.DeepCopy()
	}
	return nil
}

// SVCAdd is the public method to add services. We assume the ID provided is not in
// synced with the KVStore. If that's the case the service won't be used and an error is
// returned to the caller.
//
// Returns true if service was created
func (d *Daemon) SVCAdd(feL3n4Addr types.L3n4AddrID, be []types.LBBackEnd, addRevNAT bool) (bool, error) {
	if feL3n4Addr.ID == 0 {
		return false, fmt.Errorf("invalid service ID 0")
	}
	// Check if the service is already registered with this ID.
	feAddr, err := GetL3n4AddrID(uint32(feL3n4Addr.ID))
	if err != nil {
		return false, fmt.Errorf("unable to get the service with ID %d: %s", feL3n4Addr.ID, err)
	}
	if feAddr == nil {
		feAddr, err = PutL3n4Addr(feL3n4Addr.L3n4Addr, uint32(feL3n4Addr.ID))
		if err != nil {
			return false, fmt.Errorf("unable to put the service %s: %s", feL3n4Addr.L3n4Addr.String(), err)
		}
		// This won't be atomic so we need to check if the baseID, feL3n4Addr.ID was given to the service
		if feAddr.ID != feL3n4Addr.ID {
			return false, fmt.Errorf("the service provided %s is already registered with ID %d, please select that ID instead of %d", feL3n4Addr.L3n4Addr.String(), feAddr.ID, feL3n4Addr.ID)
		}
	}

	feAddr256Sum := feAddr.L3n4Addr.SHA256Sum()
	feL3n4Addr256Sum := feL3n4Addr.L3n4Addr.SHA256Sum()

	if feAddr256Sum != feL3n4Addr256Sum {
		return false, fmt.Errorf("service ID %d is already registered to service %s, please choose a different ID", feL3n4Addr.ID, feAddr.String())
	}

	return d.svcAdd(feL3n4Addr, be, addRevNAT)
}

func (d *Daemon) AddOrReplaceService(svc Service) error {
	// Convert service to lbmap.ServiceKey and []lbmap.ServiceValue
	fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return err
	}

	d.BPFMapMU.Lock()
	defer d.BPFMapMU.Unlock()

	return d.addSVC2BPFMap(svc.Frontend.GetL3n4Addr(), fe, besValues,
		svc.config.EnableRevNAT)
}

// svcAdd adds a service from the given feL3n4Addr (frontend) and LBBackEnd (backends).
// If addRevNAT is set, the RevNAT entry is also created for this particular service.
// If any of the backend addresses set in bes have a different L3 address type than the
// one set in fe, it returns an error without modifying the bpf LB map. If any backend
// entry fails while updating the LB map, the frontend won't be inserted in the LB map
// therefore there won't be any traffic going to the given backends.
// All of the backends added will be DeepCopied to the internal load balancer map.
func (d *Daemon) svcAdd(feL3n4Addr types.L3n4AddrID, bes []types.LBBackEnd, addRevNAT bool) (bool, error) {
	// We will move the slice to the loadbalancer map which have a mutex. If we don't
	// copy the slice we might risk changing memory that should be locked.
	beCpy := []types.LBBackEnd{}
	for _, v := range bes {
		beCpy = append(beCpy, v)
	}

	svc := types.LBSVC{
		FE:     feL3n4Addr,
		BES:    beCpy,
		Sha256: feL3n4Addr.L3n4Addr.SHA256Sum(),
	}

	fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
	if err != nil {
		return false, err
	}

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err = d.addSVC2BPFMap(feL3n4Addr, fe, besValues, addRevNAT)
	if err != nil {
		return false, err
	}

	return d.loadBalancer.AddOrReplaceService(svc), nil
}

type putServiceID struct {
	d *Daemon
}

func NewPutServiceIDHandler(d *Daemon) PutServiceIDHandler {
	return &putServiceID{d: d}
}

func (h *putServiceID) Handle(params PutServiceIDParams) middleware.Responder {
	log.Debugf("PUT /service/{id} request: %+v", params)

	f, err := types.NewL3n4AddrFromModel(params.Config.FrontendAddress)
	if err != nil {
		return apierror.Error(PutServiceIDInvalidFrontendCode, err)
	}

	frontend := types.L3n4AddrID{
		L3n4Addr: *f,
		ID:       types.ServiceID(params.Config.ID),
	}

	backends := []types.LBBackEnd{}
	for _, v := range params.Config.BackendAddresses {
		b, err := types.NewLBBackEndFromBackendModel(v)
		if err != nil {
			return apierror.Error(PutServiceIDInvalidBackendCode, err)
		}
		backends = append(backends, *b)
	}

	revnat := false
	if params.Config.Flags != nil {
		revnat = params.Config.Flags.DirectServerReturn
	}

	// FIXME
	// Add flag to indicate whether service should be registered in
	// global key value store

	if created, err := h.d.SVCAdd(frontend, backends, revnat); err != nil {
		return apierror.Error(PutServiceIDFailureCode, err)
	} else if created {
		return NewPutServiceIDCreated()
	} else {
		return NewPutServiceIDOK()
	}
}

type deleteServiceID struct {
	d *Daemon
}

func NewDeleteServiceIDHandler(d *Daemon) DeleteServiceIDHandler {
	return &deleteServiceID{d: d}
}

func (h *deleteServiceID) Handle(params DeleteServiceIDParams) middleware.Responder {
	log.Debugf("DELETE /service/{id} request: %+v", params)

	d := h.d
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	svc, ok := d.loadBalancer.SVCMapID[types.ServiceID(params.ID)]
	if !ok {
		return NewDeleteServiceIDNotFound()
	}

	// FIXME: How to handle error?
	DeleteL3n4AddrIDByUUID(uint32(params.ID))

	if err := h.d.svcDelete(svc); err != nil {
		return apierror.Error(DeleteServiceIDFailureCode, err)
	}

	return NewDeleteServiceIDOK()
}

// Deletes a service by the frontend address
func (d *Daemon) svcDeleteByFrontend(frontend *types.L3n4Addr) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	svc, ok := d.loadBalancer.SVCMap[frontend.SHA256Sum()]
	if !ok {
		return fmt.Errorf("Service frontend not found %+v", frontend)
	}
	return d.svcDelete(&svc)
}

func (d *Daemon) svcDelete(svc *types.LBSVC) error {
	var svcKey lbmap.ServiceKey
	if !svc.FE.IsIPv6() {
		svcKey = lbmap.NewService4Key(svc.FE.IP, svc.FE.Port, 0)
	} else {
		svcKey = lbmap.NewService6Key(svc.FE.IP, svc.FE.Port, 0)
	}

	svcKey.SetBackend(0)

	if err := lbmap.DeleteService(svcKey); err != nil {
		return err
	}

	d.loadBalancer.DeleteService(svc)

	return nil
}

type getServiceID struct {
	daemon *Daemon
}

func NewGetServiceIDHandler(d *Daemon) GetServiceIDHandler {
	return &getServiceID{daemon: d}
}

func (h *getServiceID) Handle(params GetServiceIDParams) middleware.Responder {
	log.Debugf("GET /service/{id} request: %+v", params)

	d := h.daemon

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	if svc, ok := d.loadBalancer.SVCMapID[types.ServiceID(params.ID)]; ok {
		return NewGetServiceIDOK().WithPayload(svc.GetModel())
	}
	return NewGetServiceIDNotFound()
}

// SVCGetBySHA256Sum returns a DeepCopied frontend with its backends.
func (d *Daemon) svcGetBySHA256Sum(feL3n4SHA256Sum string) *types.LBSVC {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	v, ok := d.loadBalancer.SVCMap[feL3n4SHA256Sum]
	if !ok {
		return nil
	}
	// We will move the slice from the loadbalancer map which have a mutex. If
	// we don't copy the slice we might risk changing memory that should be
	// locked.
	beCpy := []types.LBBackEnd{}
	for _, v := range v.BES {
		beCpy = append(beCpy, v)
	}
	return &types.LBSVC{
		FE:  *v.FE.DeepCopy(),
		BES: beCpy,
	}
}

type getService struct {
	d *Daemon
}

func NewGetServiceHandler(d *Daemon) GetServiceHandler {
	return &getService{d: d}
}

func (h *getService) Handle(params GetServiceParams) middleware.Responder {
	log.Debugf("GET /service request: %+v", params)

	list := []*models.Service{}

	h.d.loadBalancer.BPFMapMU.RLock()
	defer h.d.loadBalancer.BPFMapMU.RUnlock()

	for _, v := range h.d.loadBalancer.SVCMap {
		list = append(list, v.GetModel())
	}

	return NewGetServiceOK().WithPayload(list)
}

// RevNATAdd deep copies the given revNAT address to the cilium lbmap with the given id.
func (d *Daemon) RevNATAdd(id types.ServiceID, revNAT types.L3n4Addr) error {
	revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(id, revNAT)

	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	err := lbmap.UpdateRevNat(revNATK, revNATV)
	if err != nil {
		return err
	}

	d.loadBalancer.RevNATMap[id] = *revNAT.DeepCopy()
	return nil
}

// RevNATDelete deletes the revNatKey from the local bpf map.
func (d *Daemon) RevNATDelete(id types.ServiceID) error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil
	}

	var revNATK lbmap.RevNatKey
	if !revNAT.IsIPv6() {
		revNATK = lbmap.NewRevNat4Key(uint16(id))
	} else {
		revNATK = lbmap.NewRevNat6Key(uint16(id))
	}

	err := lbmap.DeleteRevNat(revNATK)
	// TODO should we delete even if err is != nil?
	if err == nil {
		delete(d.loadBalancer.RevNATMap, id)
	}
	return err
}

// RevNATDeleteAll deletes all RevNAT4, if IPv4 is enabled on daemon, and all RevNAT6
// stored on the daemon and on the bpf maps.
func (d *Daemon) RevNATDeleteAll() error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	if !d.conf.IPv4Disabled {
		if err := lbmap.RevNat4Map.DeleteAll(); err != nil {
			return err
		}
	}
	if err := lbmap.RevNat6Map.DeleteAll(); err != nil {
		return err
	}
	// TODO should we delete even if err is != nil?

	d.loadBalancer.RevNATMap = map[types.ServiceID]types.L3n4Addr{}
	return nil
}

// RevNATGet returns a DeepCopy of the revNAT found with the given ID or nil if not found.
func (d *Daemon) RevNATGet(id types.ServiceID) (*types.L3n4Addr, error) {
	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	revNAT, ok := d.loadBalancer.RevNATMap[id]
	if !ok {
		return nil, nil
	}
	return revNAT.DeepCopy(), nil
}

// RevNATDump dumps a DeepCopy of the cilium's loadbalancer.
func (d *Daemon) RevNATDump() ([]types.L3n4AddrID, error) {
	dump := []types.L3n4AddrID{}

	d.loadBalancer.BPFMapMU.RLock()
	defer d.loadBalancer.BPFMapMU.RUnlock()

	for k, v := range d.loadBalancer.RevNATMap {
		dump = append(dump, types.L3n4AddrID{
			ID:       k,
			L3n4Addr: *v.DeepCopy(),
		})
	}

	return dump, nil
}

// SyncLBMap syncs the bpf lbmap with the daemon's lb map. All bpf entries will overwrite
// the daemon's LB map. If the bpf lbmap entry has a different service ID than the
// KVStore's ID, that entry will be updated on the bpf map accordingly with the new ID
// retrieved from the KVStore.
func (d *Daemon) SyncLBMap() error {
	d.loadBalancer.BPFMapMU.Lock()
	defer d.loadBalancer.BPFMapMU.Unlock()

	newSVCMap := types.SVCMap{}
	newSVCMapID := types.SVCMapID{}
	newRevNATMap := types.RevNATMap{}
	failedSyncSVC := []types.LBSVC{}
	failedSyncRevNAT := map[types.ServiceID]types.L3n4Addr{}

	parseSVCEntries := func(key bpf.MapKey, value bpf.MapValue) {
		svcKey := key.(lbmap.ServiceKey)
		//It's the frontend service so we don't add this one
		if svcKey.GetBackend() == 0 {
			return
		}
		svcValue := value.(lbmap.ServiceValue)
		fe, be, err := lbmap.ServiceKeynValue2FEnBE(svcKey, svcValue)
		if err != nil {
			log.Errorf("%s", err)
			return
		}

		newSVCMap.AddFEnBE(fe, be, svcKey.GetBackend())
	}

	parseRevNATEntries := func(key bpf.MapKey, value bpf.MapValue) {
		revNatK := key.(lbmap.RevNatKey)
		revNatV := value.(lbmap.RevNatValue)
		fe, err := lbmap.RevNatValue2L3n4AddrID(revNatK, revNatV)
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		newRevNATMap[fe.ID] = fe.L3n4Addr
	}

	addSVC2BPFMap := func(oldID types.ServiceID, svc types.LBSVC) error {
		// check if the reverser nat is present on the bpf map and update the
		// reverse nat key and delete the old one.
		revNAT, ok := newRevNATMap[oldID]
		if ok {
			revNATK, revNATV := lbmap.L3n4Addr2RevNatKeynValue(svc.FE.ID, revNAT)
			err := lbmap.UpdateRevNat(revNATK, revNATV)
			if err != nil {
				return fmt.Errorf("Unable to add revNAT: %s: %s."+
					" This entry will be removed from the bpf's LB map.", revNAT.String(), err)
			}

			// Remove the old entry from the bpf map.
			revNATK, _ = lbmap.L3n4Addr2RevNatKeynValue(oldID, revNAT)
			if err := lbmap.DeleteRevNat(revNATK); err != nil {
				log.Warningf("Unable to remove old rev NAT entry with ID %d: %s", oldID, err)
			}

			delete(newRevNATMap, oldID)
			newRevNATMap[svc.FE.ID] = revNAT
		}

		fe, besValues, err := lbmap.LBSVC2ServiceKeynValue(svc)
		if err != nil {
			return fmt.Errorf("Unable to create a BPF key and values for service FE: %s and backends: %+v. Error: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), svc.BES, err)
		}

		err = d.addSVC2BPFMap(svc.FE, fe, besValues, false)
		if err != nil {
			return fmt.Errorf("Unable to add service FE: %s: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.String(), err)
		}
		return nil
	}

	if !d.conf.IPv4Disabled {
		// lbmap.RRSeq4Map is updated as part of Service4Map and does
		// not need separate dump.
		lbmap.Service4Map.Dump(lbmap.Service4DumpParser, parseSVCEntries)
		lbmap.RevNat4Map.Dump(lbmap.RevNat4DumpParser, parseRevNATEntries)
	}

	// lbmap.RRSeq6Map is updated as part of Service6Map and does not need
	// separate dump.
	lbmap.Service6Map.Dump(lbmap.Service6DumpParser, parseSVCEntries)
	lbmap.RevNat6Map.Dump(lbmap.RevNat6DumpParser, parseRevNATEntries)

	// Let's check if the services read from the lbmap have the same ID set in the
	// KVStore.
	for k, svc := range newSVCMap {
		kvL3n4AddrID, err := PutL3n4Addr(svc.FE.L3n4Addr, 0)
		if err != nil {
			log.Errorf("Unable to retrieve service ID of: %s from KVStore: %s."+
				" This entry will be removed from the bpf's LB map.", svc.FE.L3n4Addr.String(), err)
			failedSyncSVC = append(failedSyncSVC, svc)
			delete(newSVCMap, k)
			continue
		}

		if svc.FE.ID != kvL3n4AddrID.ID {
			log.Infof("Service ID was out of sync, got new ID %d -> %d", svc.FE.ID, kvL3n4AddrID.ID)
			oldID := svc.FE.ID
			svc.FE.ID = kvL3n4AddrID.ID
			if err := addSVC2BPFMap(oldID, svc); err != nil {
				log.Errorf("%s", err)

				failedSyncSVC = append(failedSyncSVC, svc)
				delete(newSVCMap, k)

				revNAT, ok := newRevNATMap[svc.FE.ID]
				if ok {
					// Revert the old revNAT
					newRevNATMap[oldID] = revNAT
					failedSyncRevNAT[svc.FE.ID] = revNAT
					delete(newRevNATMap, svc.FE.ID)
				}
				continue
			}
			newSVCMap[k] = svc
			newSVCMapID[svc.FE.ID] = &svc
		}
	}

	// Clean services and rev nats that failed while restoring
	for _, svc := range failedSyncSVC {
		log.Debugf("Removing service: %s", svc.FE)
		feL3n4 := svc.FE
		var svcKey lbmap.ServiceKey
		if !feL3n4.IsIPv6() {
			svcKey = lbmap.NewService4Key(feL3n4.IP, feL3n4.Port, 0)
		} else {
			svcKey = lbmap.NewService6Key(feL3n4.IP, feL3n4.Port, 0)
		}

		svcKey.SetBackend(0)

		if err := lbmap.DeleteService(svcKey); err != nil {
			log.Warningf("Unable to clean service %s from BPF map: %s", svc.FE, err)
		}
	}

	for id, revNAT := range failedSyncRevNAT {
		log.Debugf("Removing revNAT: %s", revNAT)
		var revNATK lbmap.RevNatKey
		if !revNAT.IsIPv6() {
			revNATK = lbmap.NewRevNat4Key(uint16(id))
		} else {
			revNATK = lbmap.NewRevNat6Key(uint16(id))
		}

		if err := lbmap.DeleteRevNat(revNATK); err != nil {
			log.Warningf("Unable to clean rev NAT %s from BPF map: %s", revNAT, err)
		}
	}

	d.loadBalancer.SVCMap = newSVCMap
	d.loadBalancer.SVCMapID = newSVCMapID
	d.loadBalancer.RevNATMap = newRevNATMap

	return nil
}

func getUniqPorts(svcPorts map[types.FEPortName]*types.FEPort) map[uint16]bool {
	// We are not discriminating the different L4 protocols on the same L4
	// port so we create the number of unique sets of service IP + service
	// port.
	uniqPorts := map[uint16]bool{}
	for _, svcPort := range svcPorts {
		uniqPorts[svcPort.Port] = true
	}
	return uniqPorts
}

func (d *Daemon) delK8sSVCs(id k8s.K8sServiceID, svc k8s.K8sService, se *types.K8sServiceEndpoint) error {
	isSvcIPv4 := svcInfo.FEIP.To4() != nil
	if err := areIPsConsistent(!d.conf.IPv4Disabled, isSvcIPv4, id, se); err != nil {
		return err
	}

	repPorts := getUniqPorts(svcInfo.Ports)

	for _, svcPort := range svcInfo.Ports {
		if !repPorts[svcPort.Port] {
			continue
		}
		repPorts[svcPort.Port] = false

		if svcPort.ID != 0 {
			if err := d.DeleteL3n4AddrIDByUUID(uint32(svcPort.ID)); err != nil {
				log.Warningf("Error while cleaning service ID: %s", err)
			}
		}

		fe, err := types.NewL3n4Addr(svcPort.Protocol, svcInfo.FEIP, svcPort.Port)
		if err != nil {
			log.Errorf("Error while creating a New L3n4AddrID: %s. Ignoring service %v...", err, svcInfo)
			continue
		}

		if err := d.svcDeleteByFrontend(fe); err != nil {
			log.Warningf("Error deleting service %+v, %s", fe, err)
		} else {
			log.Debugf("# cilium lb delete-service %s %d 0", svcInfo.FEIP, svcPort.Port)
		}

		if err := d.RevNATDelete(svcPort.ID); err != nil {
			log.Warningf("Error deleting reverse NAT %+v, %s", svcPort.ID, err)
		} else {
			log.Debugf("# cilium lb delete-rev-nat %d", svcPort.ID)
		}
	}
	return nil
}

func areIPsConsistent(ipv4Enabled, isSvcIPv4 bool, svc k8s.K8sServiceID, se *types.K8sServiceEndpoint) error {
	if isSvcIPv4 {
		if !ipv4Enabled {
			return fmt.Errorf("Received an IPv4 kubernetes service but IPv4 is "+
				"disabled in the cilium daemon. Ignoring service %+v", svc)
		}

		for epIP := range se.BEIPs {
			//is IPv6?
			if net.ParseIP(epIP).To4() == nil {
				return fmt.Errorf("Not all endpoints IPs are IPv4. Ignoring IPv4 service %+v", svc)
			}
		}
	} else {
		for epIP := range se.BEIPs {
			//is IPv4?
			if net.ParseIP(epIP).To4() != nil {
				return fmt.Errorf("Not all endpoints IPs are IPv6. Ignoring IPv6 service %+v", svc)
			}
		}
	}
	return nil
}
