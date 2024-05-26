package apis

import (
	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// IPFamily defines kindnet networking operating model
type IPFamily int

const (
	// Family type definitions
	AllFamily       IPFamily = unix.AF_UNSPEC
	IPv4Family      IPFamily = unix.AF_INET
	IPv6Family      IPFamily = unix.AF_INET6
	DualStackFamily IPFamily = unix.AF_UNSPEC

	// nftables Chains and Sets that can be accessed from any controller
	NATPostroutingChain = "nat-postrouting"
	MasqueradeChain     = "masquerade"

	PodRangesV4Set  = "pod-ranges-v4"
	PodRangesV6Set  = "pod-ranges-v6"
	ServiceIPsV4Set = "service-ips-v4"
	ServiceIPsV6Set = "service-ips-v6"
)

var (
	// read only table value to be used from any controller
	KindnetTable = &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   "kindnet",
	}
)
