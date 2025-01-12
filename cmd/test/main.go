package main

import (
	"fmt"
	"net"
	"sort"

	"github.com/vishvananda/netlink"
)

func main() {
	fmt.Println("DEFAULT GW", GetDefaultGwInterface(netlink.FAMILY_ALL))

	fmt.Println("DEFAULT MTU", getDefaultGwInterfaceMTU())

}

func GetDefaultGwInterface(ipFamily int) string {
	routes, err := netlink.RouteList(nil, ipFamily)
	if err != nil {
		return ""
	}

	for _, r := range routes {
		fmt.Printf("1 route %s\n", r.String())
	}
	return ""
}

func getDefaultGwInterfaceMTU() int {
	_, defaultDst, _ := net.ParseCIDR("0.0.0.0/0")
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Dst: defaultDst}, netlink.RT_FILTER_DST)
	if err != nil {
		return 0
	}
	if len(routes) == 0 {
		return 0
	}
	// use the route with higher priority
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Priority < routes[j].Priority
	})
	// use the mtu of the first interface
	for _, r := range routes {
		fmt.Printf("2 route %s\n", r.String())

		intfLink, err := netlink.LinkByIndex(r.LinkIndex)
		if err != nil {
			fmt.Printf("Failed to get interface link for route %v : %v", r, err)
			continue
		}
		return intfLink.Attrs().MTU
	}
	return 0
}
