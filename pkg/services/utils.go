package services

import (
	"net"
	"strconv"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"k8s.io/klog/v2"
)

// getClusterIPs return an array with the ClusterIPs present in the service
// for backward compatibility with versions < 1.20
// we need to handle the case where only ClusterIP exist
func getClusterIPs(service *v1.Service) []string {
	if len(service.Spec.ClusterIPs) > 0 {
		return service.Spec.ClusterIPs
	}
	if len(service.Spec.ClusterIP) > 0 && service.Spec.ClusterIP != v1.ClusterIPNone {
		return []string{service.Spec.ClusterIP}
	}
	return []string{}
}

// isIPService returns true if the Services uses IP
// i.e. is not a DNS Service like Headless or ExternalName
func isIPService(service *v1.Service) bool {
	if service.Spec.Type == v1.ServiceTypeExternalName {
		return false
	}

	if len(service.Spec.ClusterIP) > 0 &&
		service.Spec.ClusterIP != v1.ClusterIPNone {
		return true
	}
	return false
}

// return the endpoints that belong to the IPFamily as a slice of IP:Port
func getLbEndpoints(slices []*discovery.EndpointSlice, svcPort v1.ServicePort, family v1.IPFamily) []string {
	// return an empty object so the caller don't have to check for nil and can use it as an iterator
	if len(slices) == 0 {
		return []string{}
	}
	// Endpoint Slices are allowed to have duplicate endpoints
	// we use a set to deduplicate endpoints
	lbEndpoints := sets.NewString()
	for _, slice := range slices {
		klog.V(4).Infof("Getting endpoints for slice %s", slice.Name)
		// Only return addresses that belong to the requested IP family
		if slice.AddressType != discovery.AddressType(family) {
			klog.V(4).Infof("Slice %s with different IP Family endpoints, requested: %s received: %s",
				slice.Name, slice.AddressType, family)
			continue
		}

		// build the list of endpoints in the slice
		for _, port := range slice.Ports {
			// If Service port name set it must match the name field in the endpoint
			if svcPort.Name != "" && svcPort.Name != *port.Name {
				klog.V(5).Infof("Slice %s with different Port name, requested: %s received: %s",
					slice.Name, svcPort.Name, *port.Name)
				continue
			}

			// Skip ports that doesn't match the protocol
			if *port.Protocol != svcPort.Protocol {
				klog.V(5).Infof("Slice %s with different Port protocol, requested: %s received: %s",
					slice.Name, svcPort.Protocol, *port.Protocol)
				continue
			}

			for _, endpoint := range slice.Endpoints {
				// Skip endpoints that are not ready
				if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					klog.V(4).Infof("Slice endpoints Not Ready")
					continue
				}
				for _, ip := range endpoint.Addresses {
					klog.V(4).Infof("Adding slice %s endpoints: %s %d", slice.Name, ip, *port.Port)
					lbEndpoints.Insert(net.JoinHostPort(ip, strconv.Itoa(int(*port.Port))))
				}
			}
		}
	}

	klog.V(4).Infof("LB Endpoints for %s are: %v", slices[0].Labels[discovery.LabelServiceName], lbEndpoints.List())
	return lbEndpoints.List()
}

func getNodeIPs() ([]string, error) {
	return []string{}, nil
}
