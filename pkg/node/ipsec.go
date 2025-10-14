/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package node

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"

	v1 "k8s.io/api/core/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

const (
	ipsecIface   = "knet-xfrm0"
	ipsecIfaceID = 1001
	spi          = 1001
	// use the serviceaccount token as key for encryption
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

func getKey() ([]byte, error) {
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, err
	}
	return token[:16], nil
}

func (c *NodeController) initIPsec() error {
	xfrm := &netlink.Xfrmi{
		LinkAttrs: netlink.LinkAttrs{
			Name: ipsecIface,
		},
		Ifid: ipsecIfaceID,
	}

	if err := netlink.LinkAdd(xfrm); err != nil {
		klog.Infof("failed to add XFRM interface: %v", err)
	}

	if err := netlink.LinkSetUp(xfrm); err != nil {
		return fmt.Errorf("failed to set up XFRM interface: %v", err)
	}
	for _, podCIDR := range c.localPodCIDRs {
		_, cidr, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return err
		}
		_, ones := cidr.Mask.Size()
		cidr.Mask = net.CIDRMask(ones, ones)
		// use the network address as IP of the interface
		if err := netlink.AddrAdd(xfrm, &netlink.Addr{IPNet: cidr}); err != nil {
			return fmt.Errorf("failed to add address to xfrm interface: %v", err)
		}
	}
	return nil
}

// instructions from https://blog.hansenpartnership.com/figuring-out-how-ipsec-transforms-work-in-linux/
func (c *NodeController) syncIPSecPolicies(node *v1.Node) error {
	errs := []error{}
	nodeIPs, err := GetNodeHostIPs(node)
	if err != nil {
		return err
	}

	key, err := getKey()
	if err != nil {
		return err
	}

	for _, nodeIP := range nodeIPs {
		for _, podCIDR := range node.Spec.PodCIDRs {
			// check PodCIDR is the same IP family
			if netutils.IsIPv6CIDRString(podCIDR) != netutils.IsIPv6(nodeIP) {
				continue
			}

			var srcIP net.IP
			for _, ip := range c.localPodIPs {
				if netutils.IsIPv6CIDRString(podCIDR) == netutils.IsIPv6(ip) {
					srcIP = ip
					break
				}
			}

			if srcIP == nil {
				continue
			}

			var srcNet *net.IPNet
			for _, cidr := range c.localPodCIDRs {
				if netutils.IsIPv6CIDRString(podCIDR) == netutils.IsIPv6CIDRString(cidr) {
					_, ipnet, err := net.ParseCIDR(cidr)
					if err != nil {
						return err
					}
					srcNet = ipnet
					break
				}
			}
			if srcNet == nil {
				continue
			}

			_, dstNet, err := net.ParseCIDR(podCIDR)
			if err != nil {
				return err
			}

			link, err := netlink.LinkByName(ipsecIface)
			if err != nil {
				return fmt.Errorf("failed to get link by name: %v", err)
			}

			route := &netlink.Route{
				Dst:       dstNet,
				LinkIndex: link.Attrs().Index,
			}

			// Check if the route already exists.
			existingRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, route, netlink.RT_FILTER_DST)
			if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
				return fmt.Errorf("failed to list routes: %v", err)
			}

			if len(existingRoutes) == 0 {
				// Route does not exist, add it.
				if err := netlink.RouteAdd(route); err != nil {
					return fmt.Errorf("failed to add route: %v", err)
				}
			} else if existingRoutes[0].LinkIndex != link.Attrs().Index {
				if err := netlink.RouteReplace(route); err != nil {
					return fmt.Errorf("failed to replace route: %v", err)
				}
			}

			// state transform for encapsulation
			state := &netlink.XfrmState{
				Src:   srcIP,
				Dst:   nodeIP,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Spi:   int(spi),
				Ifid:  ipsecIfaceID,
				Crypt: &netlink.XfrmStateAlgo{
					Name: "cbc(aes)",
					Key:  key,
				},
			}

			err = netlink.XfrmStateAdd(state)
			if err != nil {
				klog.Infof("failed to add xfrm state %v : %v", state, err)
				if err := netlink.XfrmStateUpdate(state); err != nil {
					errs = append(errs, fmt.Errorf("failed to update XFRM state: %v", err))
				}
			}

			// automatic decapsulation
			state = &netlink.XfrmState{
				Src:   nodeIP,
				Dst:   srcIP,
				Proto: netlink.XFRM_PROTO_ESP,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Spi:   int(spi),
				Ifid:  ipsecIfaceID,
				Crypt: &netlink.XfrmStateAlgo{
					Name: "cbc(aes)",
					Key:  key,
				},
			}
			err = netlink.XfrmStateAdd(state)
			if err != nil {
				klog.Infof("failed to add xfrm state %v : %v", state, err)
				if err := netlink.XfrmStateUpdate(state); err != nil {
					errs = append(errs, fmt.Errorf("failed to update XFRM state: %v", err))
				}
			}

			// required policy for encapsulation
			policy := &netlink.XfrmPolicy{
				Src:  srcNet,
				Dst:  dstNet,
				Dir:  netlink.XFRM_DIR_OUT,
				Ifid: ipsecIfaceID,
				Tmpls: []netlink.XfrmPolicyTmpl{{
					Src:   srcIP,
					Dst:   nodeIP,
					Proto: netlink.XFRM_PROTO_ESP,
					Mode:  netlink.XFRM_MODE_TUNNEL,
					Spi:   int(spi),
				}},
			}
			// Look for a specific policy
			sp, err := netlink.XfrmPolicyGet(policy)
			if err != nil {
				klog.Infof("failed to get xfrm policy %v : %v", policy, err)
			}
			if sp != nil {
				klog.V(4).InfoS("xfrm policy already exist", "policy", sp)
			} else {
				err = netlink.XfrmPolicyAdd(policy)
				if err != nil {
					errs = append(errs, fmt.Errorf("failed to add xfrm policy %v : %v", policy, err))
				}
			}

			// policy to allow passing of decapsulated packets
			policy = &netlink.XfrmPolicy{
				Dst:  srcNet,
				Dir:  netlink.XFRM_DIR_IN,
				Ifid: ipsecIfaceID,
				Tmpls: []netlink.XfrmPolicyTmpl{{
					Proto: netlink.XFRM_PROTO_ESP,
					Mode:  netlink.XFRM_MODE_TUNNEL,
					Spi:   int(spi),
				}},
			}
			err = netlink.XfrmPolicyAdd(policy)
			if err != nil {
				klog.Infof("failed to add xfrm policy %v : %v", policy, err)
				if err = netlink.XfrmPolicyUpdate(policy); err != nil {
					errs = append(errs, fmt.Errorf("failed to update XFRM policy: %v", err))
				}
			}

			// policy to allow passing of decapsulated packets
			policy = &netlink.XfrmPolicy{
				Dst:  srcNet,
				Dir:  netlink.XFRM_DIR_FWD,
				Ifid: ipsecIfaceID,
				Tmpls: []netlink.XfrmPolicyTmpl{{
					Proto: netlink.XFRM_PROTO_ESP,
					Mode:  netlink.XFRM_MODE_TUNNEL,
					Spi:   int(spi),
				}},
			}
			err = netlink.XfrmPolicyAdd(policy)
			if err != nil {
				klog.Infof("failed to add xfrm policy %v : %v", policy, err)
				if err := netlink.XfrmPolicyUpdate(policy); err != nil {
					errs = append(errs, fmt.Errorf("failed to update XFRM policy: %v", err))
				}
			}
		}
	}
	return utilerrors.NewAggregate(errs)
}

func deleteIPSecPolicies(node *v1.Node) error {
	errs := []error{}

	nodeIPs, err := GetNodeHostIPs(node)
	if err != nil {
		return err
	}

	for _, nodeIP := range nodeIPs {
		for _, podCIDR := range node.Spec.PodCIDRs {
			// check PodCIDR is the same IP family
			if netutils.IsIPv6CIDRString(podCIDR) != netutils.IsIPv6(nodeIP) {
				continue
			}

			family := netlink.FAMILY_V4
			if netutils.IsIPv6(nodeIP) {
				family = netlink.FAMILY_V6
			}

			_, dstNet, err := net.ParseCIDR(podCIDR)
			if err != nil {
				return err
			}

			states, err := netlink.XfrmStateList(family)
			if err != nil {
				return fmt.Errorf("failed to get all the xfrm states: %v", err)
			}

			for _, state := range states {
				if state.Dst.Equal(nodeIP) {
					err := netlink.XfrmStateDel(&state)
					if err != nil {
						errs = append(errs, fmt.Errorf("failed to delete xfrm state %s: %v", state.String(), err))

					}
					break
				}
			}

			policies, err := netlink.XfrmPolicyList(family)
			if err != nil {
				return fmt.Errorf("failed to get all the xfrm states: %v", err)
			}

			for _, policy := range policies {
				if policy.Dst.String() == dstNet.String() {
					err := netlink.XfrmPolicyDel(&policy)
					if err != nil {
						errs = append(errs, fmt.Errorf("failed to delete xfrm policy %s: %v", policy.String(), err))
					}
					break
				}
			}
		}
	}
	return utilerrors.NewAggregate(errs)
}

func cleanIPSecPolicies() error {
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get all the xfrm states: %v", err)
	}

	for _, state := range states {
		if state.Ifid == ipsecIfaceID {
			err := netlink.XfrmStateDel(&state)
			if err != nil {
				klog.Infof("failed to delete xfrm state %s : %v", state.String(), err)
			}
		}
	}

	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get all the xfrm states: %v", err)
	}

	for _, policy := range policies {
		if policy.Ifid == ipsecIfaceID {
			err := netlink.XfrmPolicyDel(&policy)
			if err != nil {
				klog.Infof("failed to delete xfrm policy %s: %v", policy.String(), err)
			}
		}
	}
	return nil
}

func cleanIPSecInterface() error {
	ifaces, err := netlink.LinkList()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface.Attrs().Name == ipsecIface {
			return netlink.LinkDel(iface)
		}
		xfrmi, ok := iface.(*netlink.Xfrmi)
		if !ok {
			continue
		}
		if xfrmi.Ifid == ipsecIfaceID {
			return netlink.LinkDel(iface)
		}
	}
	return nil
}
