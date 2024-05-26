package net

import (
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

// GetMTU returns the MTU used for the IP family
func GetMTU(ipFamily int) (int, error) {
	iface, err := getDefaultGwIf(ipFamily)
	if err != nil {
		return 0, err
	}
	mtu, err := getInterfaceMTU(iface)
	if err != nil {
		return 0, err
	}
	return mtu, nil
}

// getInterfaceMTU finds the mtu for the interface
func getInterfaceMTU(iface string) (int, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, inter := range interfaces {
		if inter.Name == iface {
			return inter.MTU, nil
		}
	}
	return 0, fmt.Errorf("no %s device found", iface)
}

func getDefaultGwIf(ipFamily int) (string, error) {
	routes, err := netlink.RouteList(nil, ipFamily)
	if err != nil {
		return "", err
	}

	for _, r := range routes {
		// no multipath
		if len(r.MultiPath) == 0 {
			if r.Gw == nil {
				continue
			}
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				log.Printf("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			return intfLink.Attrs().Name, nil
		}

		// multipath, use the first valid entry
		// xref: https://github.com/vishvananda/netlink/blob/6ffafa9fc19b848776f4fd608c4ad09509aaacb4/route.go#L137-L145
		for _, nh := range r.MultiPath {
			if nh.Gw == nil {
				continue
			}
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				log.Printf("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			return intfLink.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("not routes found")
}

// IsLocalIP returns true if given IP belongs to the current host
// It returns false if is not local or if is not able to detect it.
func IsLocalIP(nodeIP net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.Equal(nodeIP) {
			return true
		}
	}
	return false
}
