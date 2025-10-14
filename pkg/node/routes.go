
package node

import (
	"errors"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

func syncRoute(node *v1.Node) error {
	nodeIPs, err := GetNodeHostIPs(node)
	if err != nil {
		return err
	}

	for _, nodeIP := range nodeIPs {
		// check if nodeIP is reachable, this happens when nodes are in the same l2 domain
		// Environments like GCE implement IP alias, and assign /24 to the VMs so there is
		// no l2 domain for the instances, and the traffic is handled by the underneath SDN
		routes, err := netlink.RouteGet(nodeIP)
		if err != nil {
			return err
		}
		klog.V(7).Infof("Routes to Node %s : %v", nodeIP, routes)
		addRoute := true
		for _, route := range routes {
			if route.Gw != nil {
				klog.V(2).Infof("Route to Node %s via %s, no direct routing needed, if pods can not communicate please configure your router correctly", nodeIP, route.Gw.String())
				addRoute = false
				break
			}
		}

		if !addRoute {
			continue
		}

		for _, podCIDR := range node.Spec.PodCIDRs {
			// parse subnet
			dst, err := netlink.ParseIPNet(podCIDR)
			if err != nil {
				return err
			}

			if netutils.IsIPv6(nodeIP) != netutils.IsIPv6CIDR(dst) {
				// skip different IP families
				continue
			}

			// Check if the route exists to the other node's PodCIDR
			routeToDst := netlink.Route{Dst: dst, Gw: nodeIP}
			routes, err := netlink.RouteListFiltered(nl.GetIPFamily(nodeIP), &routeToDst, netlink.RT_FILTER_DST)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return err
			}
			// Add route if not present
			if len(routes) == 0 {
				klog.Infof("Adding route %v \n", dst)
				if err := netlink.RouteAdd(&routeToDst); err != nil {
					return err
				}
			} else if len(routes) > 0 && !routes[0].Gw.Equal(nodeIP) {
				klog.Infof("Replaceing route %v \n", dst)
				if err := netlink.RouteReplace(&routeToDst); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func deleteRoutes(node *v1.Node) error {
	nodeIPs, err := GetNodeHostIPs(node)
	if err != nil {
		return err
	}

	for _, nodeIP := range nodeIPs {
		for _, podCIDR := range node.Spec.PodCIDRs {
			// parse subnet
			dst, err := netlink.ParseIPNet(podCIDR)
			if err != nil {
				return err
			}
			if netutils.IsIPv6(nodeIP) != netutils.IsIPv6CIDR(dst) {
				// skip different IP families
				continue
			}

			// Check if the route exists to the other node's PodCIDR
			routeToDst := netlink.Route{Dst: dst, Gw: nodeIP}
			route, err := netlink.RouteListFiltered(nl.GetIPFamily(nodeIP), &routeToDst, netlink.RT_FILTER_DST)
			if err != nil && !errors.Is(err, unix.EINTR) {
				return err
			}

			// Remove route if exist
			if len(route) > 0 {
				klog.Infof("Removing route %v \n", routeToDst)
				if err := netlink.RouteDel(&routeToDst); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
