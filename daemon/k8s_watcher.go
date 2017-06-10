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
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/labels"

	log "github.com/Sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
)

const (
	k8sErrLogTimeout = time.Minute
)

var (
	k8sLogMessagesTimer     = time.NewTimer(k8sErrLogTimeout)
	firstK8sErrorLogMessage sync.Once
)

func init() {
	// Replace error handler with our own
	runtime.ErrorHandlers = []func(error){
		k8sErrorHandler,
	}
}

// k8sErrorHandler handles the error messages on a non verbose way by omitting
// same error messages for a timeout defined with k8sErrLogTimeout.
func k8sErrorHandler(e error) {
	if e == nil {
		return
	}
	// Omitting the 'connection refused' common messages
	if strings.Contains(e.Error(), "connection refused") {
		firstK8sErrorLogMessage.Do(func() {
			// Reset the timer for the first message
			log.Error(e)
			k8sLogMessagesTimer.Reset(k8sErrLogTimeout)
		})
		select {
		case <-k8sLogMessagesTimer.C:
			log.Error(e)
			k8sLogMessagesTimer.Reset(k8sErrLogTimeout)
		default:
		}
		return
	}
	// Still log other error messages
	log.Error(e)
}

func (d *Daemon) createThirdPartyResources() error {
	// TODO: Retry a couple of times

	res := &v1beta1.ThirdPartyResource{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cilium-network-policy." + k8s.ThirdPartyResourceGroup,
		},
		Description: "Cilium network policy rule",
		Versions: []v1beta1.APIVersion{
			{Name: k8s.ThirdPartyResourceVersion},
		},
	}

	_, err := d.k8sClient.Extensions().ThirdPartyResources().Create(res)
	if err != nil && !errors.IsAlreadyExists(err) {
		return err
	}

	return nil
}

// EnableK8sWatcher watches for policy, services and endpoint changes on the kurbenetes
// api server defined in the receiver's daemon k8sClient. Re-syncs all state from the
// kubernetes api server at the given reSyncPeriod duration.
func (d *Daemon) EnableK8sWatcher(reSyncPeriod time.Duration) error {
	if !d.conf.IsK8sEnabled() {
		return nil
	}

	if err := d.createThirdPartyResources(); err != nil {
		return fmt.Errorf("Unable to create third party resource: %s", err)
	}

	tprClient, err := k8s.CreateTPRClient(d.conf.K8sEndpoint, d.conf.K8sCfgPath)
	if err != nil {
		return fmt.Errorf("Unable to create third party resource client: %s", err)
	}

	_, policyController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Extensions().RESTClient(),
			"networkpolicies", v1.NamespaceAll, fields.Everything()),
		&v1beta1.NetworkPolicy{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.addK8sNetworkPolicy,
			UpdateFunc: d.updateK8sNetworkPolicy,
			DeleteFunc: d.deleteK8sNetworkPolicy,
		},
	)
	go policyController.Run(wait.NeverStop)

	_, svcController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Core().RESTClient(),
			"services", v1.NamespaceAll, fields.Everything()),
		&v1.Service{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.serviceAddFn,
			UpdateFunc: d.serviceModFn,
			DeleteFunc: d.serviceDelFn,
		},
	)
	go svcController.Run(wait.NeverStop)

	_, endpointController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Core().RESTClient(),
			"endpoints", v1.NamespaceAll, fields.Everything()),
		&v1.Endpoints{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.endpointsAddFn,
			UpdateFunc: d.endpointsModFn,
			DeleteFunc: d.endpointsDelFn,
		},
	)
	go endpointController.Run(wait.NeverStop)

	_, ingressController := cache.NewInformer(
		cache.NewListWatchFromClient(d.k8sClient.Extensions().RESTClient(),
			"ingresses", v1.NamespaceAll, fields.Everything()),
		&v1beta1.Ingress{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.ingressAddFn,
			UpdateFunc: d.ingressModFn,
			DeleteFunc: d.ingressDelFn,
		},
	)
	go ingressController.Run(wait.NeverStop)

	_, ciliumRulesController := cache.NewInformer(
		cache.NewListWatchFromClient(tprClient, "ciliumnetworkpolicies",
			v1.NamespaceAll, fields.Everything()),
		&k8s.CiliumNetworkPolicy{},
		reSyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    d.addCiliumNetworkPolicy,
			UpdateFunc: d.updateCiliumNetworkPolicy,
			DeleteFunc: d.deleteCiliumNetworkPolicy,
		},
	)
	go ciliumRulesController.Run(wait.NeverStop)

	return nil
}

func (d *Daemon) addK8sNetworkPolicy(obj interface{}) {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		log.Errorf("Ignoring invalid k8s NetworkPolicy addition")
		return
	}
	rules, err := k8s.ParseNetworkPolicy(k8sNP)
	if err != nil {
		log.Errorf("Error while parsing kubernetes network policy %+v: %s", obj, err)
		return
	}

	opts := AddOptions{Replace: true}
	if err := d.PolicyAdd(rules, &opts); err != nil {
		log.Errorf("Error while adding kubernetes network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Kubernetes network policy '%s' successfully add", k8sNP.Name)
}

func (d *Daemon) updateK8sNetworkPolicy(oldObj interface{}, newObj interface{}) {
	log.Debugf("Modified policy %+v->%+v", oldObj, newObj)
	d.addK8sNetworkPolicy(newObj)
}

func (d *Daemon) deleteK8sNetworkPolicy(obj interface{}) {
	k8sNP, ok := obj.(*v1beta1.NetworkPolicy)
	if !ok {
		log.Errorf("Ignoring invalid k8s NetworkPolicy deletion")
		return
	}

	labels := labels.ParseSelectLabelArray(k8s.ExtractPolicyName(k8sNP))

	if err := d.PolicyDelete(labels); err != nil {
		log.Errorf("Error while deleting kubernetes network policy %+v: %s", labels, err)
	} else {
		log.Infof("Kubernetes network policy '%s' successfully removed", k8sNP.Name)
	}
}

func (d *Daemon) serviceAddFn(obj interface{}) {
	if service, ok := obj.(*v1.Service); !ok {
		log.Warningf("k8s: Ignoring k8s service addition: not of type v1.Service")
	} else {
		log.Debugf("Adding k8s service %+v", service)
		d.k8sState.HandleServiceEvent(nil, service)
	}
}

func (d *Daemon) serviceModFn(oldObj interface{}, newObj interface{}) {
	oldService, ok := oldObj.(*v1.Service)
	if !ok {
		log.Warningf("k8s: Ignoring k8s service modification: old service not of type v1.Service")
		return
	}

	newService, ok := newObj.(*v1.Service)
	if !ok {
		log.Warningf("k8s: Ignoring k8s service modification: new service not of type v1.Service")
		return
	}

	log.Debugf("Updating k8s service from: %+v to: %+v", oldService, newService)
	d.k8sState.HandleServiceEvent(oldService, newService)
}

func (d *Daemon) serviceDelFn(obj interface{}) {
	if service, ok := obj.(*v1.Service); !ok {
		log.Warningf("k8s: Ignoring k8s service deletion: not of type v1.Service")
	} else {
		log.Debugf("k8s: Deleting k8s service %+v", service)
		d.k8sState.HandleServiceEvent(service, nil)
	}
}

func (d *Daemon) endpointsAddFn(obj interface{}) {
	if ep, ok := obj.(*v1.Endpoints); !ok {
		log.Warningf("Ignoring k8s endpoints addition: not of type v1.Endpoints")
	} else {
		log.Debugf("Adding k8s endpoints %+v", ep)
		d.HandleEndpointsEvent(nil, ep)
	}
}

func (d *Daemon) endpointsModFn(oldObj interface{}, newObj interface{}) {
	oldEP, ok := oldObj.(*v1.Endpoints)
	if !ok {
		log.Warningf("Ignoring k8s endpoints modification: oldObj not of type v1.Endpoints")
		return
	}

	newEP, ok := newObj.(*v1.Endpoints)
	if !ok {
		log.Warningf("Ignoring k8s endpoints modification: newObj not of type v1.Endpoints")
		return
	}

	log.Debugf("Updating k8s endpoints from: %+v to: %+v", oldEP, newEP)
	d.HandleEndpointsEvent(oldEP, newEP)
}

func (d *Daemon) endpointsDelFn(obj interface{}) {
	if ep, ok := obj.(*v1.Endpoints); !ok {
		log.Warningf("Ignoring k8s endpoints deletion: not of type v1.Endpoints")
	} else {
		log.Debugf("Deleting k8s endpoints %+v", ep)
		d.HandleEndpointsEvent(ep, nil)
	}
}

func (d *Daemon) ingressAddFn(obj interface{}) {
	if ingress, ok := obj.(*v1beta1.Ingress); !ok {
		log.Warningf("Ignoring k8s ingress addition: not of type v1beta1.Ingress")
	} else {
		log.Debugf("Adding k8s ingress %+v", ingress)
		d.HandleIngressEvent(nil, ingress)
	}
}

func (d *Daemon) ingressModFn(oldObj interface{}, newObj interface{}) {
	oldIngress, ok := oldObj.(*v1beta1.Ingress)
	if !ok {
		log.Warningf("Ignoring k8s ingress modification: oldObj not of type v1beta1.Ingress")
		return
	}

	newIngress, ok := newObj.(*v1beta1.Ingress)
	if !ok {
		log.Warningf("Ignoring k8s ingress modification: newObj not of type v1beta1.Ingress")
		return
	}

	log.Debugf("Updating k8s ingress from: %+v to: %+v", oldIngress, newIngress)
	d.HandleIngressEventd(oldIngress, newIngress)
}

func (d *Daemon) ingressDelFn(obj interface{}) {
	if ingress, ok := obj.(*v1beta1.Ingress); !ok {
		log.Warningf("Ignoring k8s ingress deletion: not of type v1beta1.Ingress")
	} else {
		log.Debugf("Deleting k8s ingress %+v", ingress)
		d.HandleIngressEvent(ingress, nil)
	}
}

func (d *Daemon) addCiliumNetworkPolicy(obj interface{}) {
	rule, ok := obj.(*k8s.CiliumNetworkPolicy)
	if !ok {
		log.Warningf("Invalid third-party objected, expected CiliumNetworkPolicy, got %+v", obj)
		return
	}

	log.Debugf("Adding k8s TPR CiliumNetworkPolicy %+v", rule)

	rules, err := rule.Parse()
	if err != nil {
		log.Warningf("Ignoring invalid third-party policy rule: %s", err)
		return
	}

	// Delete an eventual existing rule with matching label
	d.PolicyDelete(rules[0].Labels)

	opts := AddOptions{Replace: true}
	if err := d.PolicyAdd(rules, &opts); err != nil {
		log.Warningf("Error while adding kubernetes network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Imported third-party policy rule '%s'", rule.Metadata.Name)
}

func (d *Daemon) deleteCiliumNetworkPolicy(obj interface{}) {
	rule, ok := obj.(*k8s.CiliumNetworkPolicy)
	if !ok {
		log.Warningf("Invalid third-party objected, expected CiliumNetworkPolicy, got %+v", obj)
		return
	}

	log.Debugf("Deleting k8s TPR CiliumNetworkPolicy %+v", rule)

	rules, err := rule.Parse()
	if err != nil {
		log.Warningf("Ignoring invalid third-party policy rule: %s", err)
		return
	}

	if err := d.PolicyDelete(rules[0].Labels); err != nil {
		log.Warningf("Error while adding kubernetes network policy %+v: %s", rules, err)
		return
	}

	log.Infof("Deleted third-party policy rule '%s'", rule.Metadata.Name)
}

func (d *Daemon) updateCiliumNetworkPolicy(oldObj interface{}, newObj interface{}) {
	// FIXME
	d.deleteCiliumNetworkPolicy(oldObj)
	d.addCiliumNetworkPolicy(newObj)
}
