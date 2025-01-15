// SPDX-License-Identifier: APACHE-2.0

package network

import (
	"net"
	"net/netip"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
)

// CIDRsToPrefix given a comma separated list with CIDRS it returns a slice of netip.Prefixes and remove duplicates
func CIDRsToPrefix(cidrs string) []netip.Prefix {
	if cidrs == "" {
		return nil
	}
	subnets := strings.Split(cidrs, ",")
	result := sets.New[netip.Prefix]()
	for _, subnet := range subnets {
		prefix, err := netip.ParsePrefix(subnet)
		if err != nil {
			continue
		}
		result.Insert(prefix)
	}
	return result.UnsortedList()
}

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

// isNotContained returns true if the prefix is not contained in any
// of the passed prefixes.
func isNotContained(prefix netip.Prefix, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		// skip same prefix
		if prefix == p {
			continue
		}
		// 192.168.0.0/24 is contained within 192.168.0.0/16
		if prefix.Overlaps(p) && prefix.Bits() >= p.Bits() {
			return false
		}
	}
	return true
}

// TopLevelPrefixes given a list of prefixes return only the top level prefixes
// It returns an IPv4 and IPv6 list.
func TopLevelPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, []netip.Prefix) {
	tree := NewIPTree[bool]()
	for _, prefix := range prefixes {
		tree.InsertPrefix(prefix, true)
	}
	v4 := tree.TopLevelPrefixes(false)
	v6 := tree.TopLevelPrefixes(true)

	return keys(v4), keys(v6)
}

// Keys returns the keys of the map m.
// The keys will be an indeterminate order.
func keys[M ~map[K]V, K comparable, V any](m M) []K {
	r := make([]K, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}
