/*
Copyright 2019 The Kubernetes Authors.

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

package main

import (
	"net"
	"strings"
)

// splitCIDRs given a comma separated list with CIDRS it returns 2 slice of strings per IP family
func splitCIDRs(cidrs string) ([]string, []string) {
	if cidrs == "" {
		return nil, nil
	}
	subnets := strings.Split(cidrs, ",")
	return splitCIDRslice(subnets)
}

func splitCIDRslice(cidrs []string) ([]string, []string) {
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
