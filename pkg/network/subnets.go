// SPDX-License-Identifier: APACHE-2.0

package network

import (
	"net"
	"strings"
)

// SplitCIDRs given a comma separated list with CIDRS it returns 2 slice of strings per IP family
func SplitCIDRs(cidrs string) ([]string, []string) {
	if cidrs == "" {
		return nil, nil
	}
	subnets := strings.Split(cidrs, ",")
	return SplitCIDRslice(subnets)
}

func SplitCIDRslice(cidrs []string) ([]string, []string) {
	var v4subnets, v6subnets []string
	for _, subnet := range cidrs {
		if isIPv6CIDRString(subnet) {
			v6subnets = append(v6subnets, subnet)
		} else {
			v4subnets = append(v4subnets, subnet)
		}
	}
	return v4subnets, v6subnets
}

// isIPv6CIDRString returns if cidr is IPv6.
// This assumes cidr is a valid CIDR.
func isIPv6CIDRString(cidr string) bool {
	ip, _, _ := net.ParseCIDR(cidr)
	return ip != nil && ip.To4() == nil
}
