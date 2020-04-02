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

package api

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/api/helpers"
	"github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/pkg/errors"

	"github.com/Azure/azure-sdk-for-go/services/compute/mgmt/2019-07-01/compute"
	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2019-09-01/network"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
)

const (
	userAgent = "cilium"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "azure-api")

// Client represents an Azure API client
type Client struct {
	resourceGroup   string
	interfaces      network.InterfacesClient
	virtualnetworks network.VirtualNetworksClient
	vmscalesets     compute.VirtualMachineScaleSetsClient
	vms             compute.VirtualMachineScaleSetVMsClient
	limiter         *helpers.ApiLimiter
	metricsAPI      MetricsAPI
}

// MetricsAPI represents the metrics maintained by the Azure API client
type MetricsAPI interface {
	ObserveAPICall(call, status string, duration float64)
	ObserveRateLimit(operation string, duration time.Duration)
}

// NewClient returns a new Azure client
func NewClient(subscriptionID, resourceGroup string, metrics MetricsAPI, rateLimit float64, burst int) (*Client, error) {
	c := &Client{
		resourceGroup:   resourceGroup,
		interfaces:      network.NewInterfacesClient(subscriptionID),
		virtualnetworks: network.NewVirtualNetworksClient(subscriptionID),
		vmscalesets:     compute.NewVirtualMachineScaleSetsClient(subscriptionID),
		vms:             compute.NewVirtualMachineScaleSetVMsClient(subscriptionID),
		metricsAPI:      metrics,
		limiter:         helpers.NewApiLimiter(metrics, rateLimit, burst),
	}

	// Authorizer based on environment variables
	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return nil, err
	}

	c.interfaces.Authorizer = authorizer
	_ = c.interfaces.AddToUserAgent(userAgent)
	c.virtualnetworks.Authorizer = authorizer
	_ = c.virtualnetworks.AddToUserAgent(userAgent)
	c.vmscalesets.Authorizer = authorizer
	_ = c.vmscalesets.AddToUserAgent(userAgent)
	c.vms.Authorizer = authorizer
	_ = c.vms.AddToUserAgent(userAgent)

	return c, nil
}

// deriveStatus returns a status string
func deriveStatus(err error) string {
	if err != nil {
		return "Failed"
	}

	return "OK"
}

// describeNetworkInterfaces lists all Azure Interfaces
func (c *Client) describeNetworkInterfaces(ctx context.Context) ([]network.Interface, error) {
	var networkInterfaces []network.Interface

	c.limiter.Limit(ctx, "VirtualMachineScaleSets.ListAll")
	sinceStart := spanstat.Start()
	result, err := c.vmscalesets.ListComplete(ctx, c.resourceGroup)
	c.metricsAPI.ObserveAPICall("VirtualMachineScaleSets.ListAll", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	for result.NotDone() {
		if err != nil {
			return nil, err
		}

		scaleset := result.Value()
		err = result.Next()

		if scaleset.Name == nil {
			continue
		}

		c.limiter.Limit(ctx, "Interfaces.ListAll")
		sinceStart := spanstat.Start()
		result2, err2 := c.interfaces.ListVirtualMachineScaleSetNetworkInterfacesComplete(ctx, c.resourceGroup, *scaleset.Name)
		c.metricsAPI.ObserveAPICall("Interfaces.ListVirtualMachineScaleSetNetworkInterfacesComplete", deriveStatus(err2), sinceStart.Seconds())
		if err2 != nil {
			return nil, err2
		}

		for result2.NotDone() {
			if err2 != nil {
				return nil, err2
			}

			networkInterfaces = append(networkInterfaces, result2.Value())
			err2 = result2.Next()
		}
	}

	return networkInterfaces, nil
}

// parseInterfaces parses a network.Interface as returned by the Azure API
// converts it into a types.AzureInterface
func parseInterface(iface *network.Interface) (instanceID string, i *types.AzureInterface) {
	i = &types.AzureInterface{}

	if iface.VirtualMachine != nil && iface.VirtualMachine.ID != nil {
		instanceID = strings.ToLower(*iface.VirtualMachine.ID)
	}

	if iface.MacAddress != nil {
		// Azure API reports MAC addresses as AA-BB-CC-DD-EE-FF
		i.MAC = strings.ReplaceAll(*iface.MacAddress, "-", ":")
	}

	if iface.ID != nil {
		i.ID = *iface.ID
	}

	if iface.NetworkSecurityGroup != nil {
		if iface.NetworkSecurityGroup.ID != nil {
			i.SecurityGroup = *iface.NetworkSecurityGroup.ID
		}
	}

	if iface.IPConfigurations != nil {
		for _, ip := range *iface.IPConfigurations {
			if ip.PrivateIPAddress != nil {
				addr := types.AzureAddress{
					IP:    *ip.PrivateIPAddress,
					State: strings.ToLower(string(ip.ProvisioningState)),
				}

				if ip.Subnet != nil {
					addr.Subnet = *ip.Subnet.ID
				}

				i.Addresses = append(i.Addresses, addr)
			}
		}
	}

	return
}

// GetInstances returns the list of all instances including all attached
// interfaces as instanceMap
func (c *Client) GetInstances(ctx context.Context) (*ipamTypes.InstanceMap, error) {
	instances := ipamTypes.NewInstanceMap()

	networkInterfaces, err := c.describeNetworkInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	for _, iface := range networkInterfaces {
		if id, azureInterface := parseInterface(&iface); id != "" {
			instances.Update(id, ipamTypes.InterfaceRevision{Resource: azureInterface})
		}
	}

	return instances, nil
}

// describeVpcs lists all VPCs
func (c *Client) describeVpcs(ctx context.Context) ([]network.VirtualNetwork, error) {
	var vpcs []network.VirtualNetwork

	c.limiter.Limit(ctx, "VirtualNetworks.List")

	sinceStart := spanstat.Start()
	result, err := c.virtualnetworks.ListComplete(ctx, c.resourceGroup)
	c.metricsAPI.ObserveAPICall("Interfaces.ListAll", deriveStatus(err), sinceStart.Seconds())
	if err != nil {
		return nil, err
	}

	for result.NotDone() {
		if err != nil {
			return nil, err
		}

		vpcs = append(vpcs, result.Value())
		err = result.Next()
	}

	return vpcs, nil
}

func parseSubnet(subnet *network.Subnet) (s *ipamTypes.Subnet) {
	s = &ipamTypes.Subnet{ID: *subnet.ID}
	if subnet.Name != nil {
		s.Name = *subnet.Name
	}

	if subnet.AddressPrefix != nil {
		c, err := cidr.ParseCIDR(*subnet.AddressPrefix)
		if err != nil {
			return nil
		}
		s.CIDR = c
	}

	return
}

// GetVpcsAndSubnets retrieves and returns all Vpcs
func (c *Client) GetVpcsAndSubnets(ctx context.Context) (ipamTypes.VirtualNetworkMap, ipamTypes.SubnetMap, error) {
	vpcs := ipamTypes.VirtualNetworkMap{}
	subnets := ipamTypes.SubnetMap{}

	vpcList, err := c.describeVpcs(ctx)
	if err != nil {
		return nil, nil, err
	}

	for _, v := range vpcList {
		if v.ID == nil {
			continue
		}

		vpc := &ipamTypes.VirtualNetwork{ID: *v.ID}
		vpcs[vpc.ID] = vpc

		if v.Subnets != nil {
			for _, subnet := range *v.Subnets {
				if subnet.ID == nil {
					continue
				}
				if s := parseSubnet(&subnet); s != nil {
					subnets[*subnet.ID] = s
				}
			}
		}
	}

	return vpcs, subnets, nil
}

// AssignPrivateIpAddresses assigns the IPs to the interface as specified by
// the interfaceID. The provided IPs must belong to the subnet as specified by
// the subnet ID.
func (c *Client) AssignPrivateIpAddresses(ctx context.Context, subnetID, interfaceID string, addresses int) error {
	log.Debugf("Extracting vmss + instance id from interfaceId %+v", interfaceID)
	extraction, err := extractVMSSNameAndInstanceID(interfaceID)
	if err != nil {
		return err
	}

	intfName := "eth1"

	res, err := c.vms.Get(ctx, c.resourceGroup, extraction.vmssName, extraction.instanceID, compute.InstanceView)
	if err != nil {
		return errors.Wrapf(err, "failed to get VM %s from VMSS %s", extraction.instanceID, extraction.vmssName)
	}

	var netIfConfig compute.VirtualMachineScaleSetNetworkConfiguration
	for _, networkInterfaceConfiguration := range *res.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
		if to.String(networkInterfaceConfiguration.Name) == intfName {
			netIfConfig = networkInterfaceConfiguration
			break
		}
	}

	ipConfigurations := make([]compute.VirtualMachineScaleSetIPConfiguration, 0, addresses)
	for i := 0; i <= addresses; i++ {
		ipConfigurations = append(ipConfigurations,
			compute.VirtualMachineScaleSetIPConfiguration{
				Name: to.StringPtr(generateIpConfigName()),
				VirtualMachineScaleSetIPConfigurationProperties: &compute.VirtualMachineScaleSetIPConfigurationProperties{
					PrivateIPAddressVersion: compute.IPv4,
					Subnet:                  &compute.APIEntityReference{ID: to.StringPtr(subnetID)},
				},
			},
		)
	}

	ipConfigs := append(*netIfConfig.IPConfigurations, ipConfigurations...)
	netIfConfig.IPConfigurations = &ipConfigs
	for i, networkInterfaceConfiguration := range *res.NetworkProfileConfiguration.NetworkInterfaceConfigurations {
		if to.String(networkInterfaceConfiguration.Name) == intfName {
			(*res.NetworkProfileConfiguration.NetworkInterfaceConfigurations)[i] = netIfConfig
		}
	}

	_, err = c.vms.Update(ctx, c.resourceGroup, extraction.vmssName, extraction.instanceID, res)
	return err
}

type vmssNameAndInstanceID struct {
	vmssName   string
	instanceID string
}

func extractVMSSNameAndInstanceID(interfaceID string) (vmssNameAndInstanceID, error) {
	extractions := vmssNameAndInstanceID{}
	interfaceIDRegexp := regexp.MustCompile("^/subscriptions/.*/resourceGroups/.*/providers/Microsoft.Compute/virtualMachineScaleSets/(?P<vmssName>.*)/virtualMachines/(?P<instanceID>.*)/networkInterfaces/.*$")
	matches := interfaceIDRegexp.FindStringSubmatch(interfaceID)
	if len(matches) == 3 {
		extractions.vmssName = matches[1]
		extractions.instanceID = matches[2]
		return extractions, nil
	}
	return extractions, fmt.Errorf("could not find a vmss + instance id match in interface id %s", interfaceID)
}

func generateIpConfigName() string {
	return "Cilium-" + String(4)
}

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func String(length int) string {
	return StringWithCharset(length, charset)
}
