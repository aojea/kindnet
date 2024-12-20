// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

/* cni config management */

type CNIController struct {
	nodeName string

	client    clientset.Interface
	workqueue workqueue.TypedRateLimitingInterface[string]

	nodeLister  corelisters.NodeLister
	nodesSynced cache.InformerSynced
}

// GetMTU returns the MTU used for the IP family
func GetMTU(ipFamily int) (int, error) {
	iface, err := GetDefaultGwInterface(ipFamily)
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

func GetDefaultGwInterface(ipFamily int) (string, error) {
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

const (
	// cniConfigPath is where kindnetd will write the computed CNI config
	cniConfigPath = "/etc/cni/net.d"

	cniConfigFile = "10-kindnet.conflist"

	// cniConfig is static as it will get the values from the daemon
	cniConfig = `
{
	"cniVersion": "0.4.0",
	"name": "kindnet",
	"plugins": [
		{
			"type": "cni-kindnet"
		}
	]
}
`
)

func WriteCNIConfig() (err error) {
	f, err := os.CreateTemp("", cniConfigFile)
	if err != nil {
		return err
	}

	tmpName := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmpName)
		}
	}()

	if _, err := f.WriteString(cniConfig); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, filepath.Join(cniConfigPath, cniConfigFile))
}
