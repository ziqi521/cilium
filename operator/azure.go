// Copyright 2020 Authors of Cilium
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
	"context"
	"fmt"

	apiMetrics "github.com/cilium/cilium/pkg/api/metrics"
	azureAPI "github.com/cilium/cilium/pkg/azure/api"
	azureIPAM "github.com/cilium/cilium/pkg/azure/ipam"
	"github.com/cilium/cilium/pkg/ipam"
	ipamMetrics "github.com/cilium/cilium/pkg/ipam/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/pkg/errors"
)

// startAzureAllocator starts the Azure IP allocator
func startAzureAllocator(clientQPSLimit float64, clientBurst int) (*ipam.NodeManager, error) {
	var (
		azMetrics azureAPI.MetricsAPI
		iMetrics  ipam.MetricsAPI
	)

	log.Info("Starting Azure IP allocator...")

	subscriptionID := option.Config.AzureSubscriptionID
	if subscriptionID == "" {
		log.Debug("SubscriptionID was not specified via CLI, retrieving it via Azure IMS")
		subID, err := azureAPI.GetSubscriptionID(context.TODO())
		if err != nil {
			return nil, errors.Wrap(err, "Azure subscription ID was not specified via CLI and retrieving it from the Azure IMS was not possible")
		}
		subscriptionID = subID
		log.WithField("subscriptionID", subscriptionID).Debug("Detected subscriptionID via Azure IMS")
	}

	resourceGroupName := option.Config.AzureResourceGroup
	if resourceGroupName == "" {
		log.Debug("ResourceGroupName was not specified via CLI, retrieving it via Azure IMS")
		rgName, err := azureAPI.GetResourceGroupName(context.TODO())
		if err != nil {
			return nil, errors.Wrap(err, "Azure resource group name was not specified via CLI and retrieving it from the Azure IMS was not possible")
		}
		resourceGroupName = rgName
		log.WithField("resourceGroupName", resourceGroupName).Debug("Detected resource group name via Azure IMS")
	}

	if option.Config.EnableMetrics {
		azMetrics = apiMetrics.NewPrometheusMetrics(metricNamespace, "azure", registry)
		iMetrics = ipamMetrics.NewPrometheusMetrics(metricNamespace, registry)
	} else {
		azMetrics = &apiMetrics.NoOpMetrics{}
		iMetrics = &ipamMetrics.NoOpMetrics{}
	}

	azureClient, err := azureAPI.NewClient(subscriptionID, resourceGroupName, azMetrics, clientQPSLimit, clientBurst)
	if err != nil {
		return nil, fmt.Errorf("unable to create Azure client: %s", err)
	}
	instances := azureIPAM.NewInstancesManager(azureClient)
	nodeManager, err := ipam.NewNodeManager(instances, &ciliumNodeUpdateImplementation{}, iMetrics, option.Config.ParallelAllocWorkers, false)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Azure node manager: %s", err)
	}

	nodeManager.Start(context.TODO())

	return nodeManager, nil
}
