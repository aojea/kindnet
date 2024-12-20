// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"k8s.io/utils/ptr"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// Only implement the minimum functionality defined by CNI required Kubernetes use cases.
// Create veth pair and request an IP to the kindnet daemon that manages the IPAM.
// This allows to add or remove new ranges without having to write on disk.
const (
	pluginName = "cni-kindnet"
	socketPath = "/run/cni-kindnet.sock"
	// containerd hardcodes this value
	// https://github.com/containerd/containerd/blob/23500b8015c6f5c624ec630fd1377a990e9eccfb/internal/cri/server/helpers.go#L68
	defaultInterface = "eth0"
)

type CNIResponse struct {
	IPs []string `json:"ips"`
	MTU int      `json:"mtu"`
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if args.Netns == "" {
		return nil
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	// return an ordered comma separated list of IPs
	resp, err := client.Get("http://kidndet/cni/ipam")
	if err != nil {
		return fmt.Errorf("failed to connect to kindnet daemon: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("invalid kindnet response: %w", err)
	}

	var response CNIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to load CNI response: %v", err)
	}

	result := current.Result{
		CNIVersion: "0.4.0", // implement the minimum necessary to work in kubernetes
		IPs:        nil,     // Container runtimes in kubernetes only care about this field
		Interfaces: []*current.Interface{
			{Name: defaultInterface},
		},
	}

	for _, address := range response.IPs {
		ip := net.ParseIP(address)
		if ip == nil {
			return fmt.Errorf("invalid ip address %s", address)
		}
		version := "4"
		mask := 32
		if ip.To4() == nil {
			version = "6"
			mask = 128
		}
		result.IPs = append(result.IPs,
			&current.IPConfig{
				Version:   version,
				Interface: ptr.To(0), // there is only one interface
				Address:   net.IPNet{IP: ip, Mask: net.CIDRMask(mask, mask)},
			},
		)
	}

	if len(result.IPs) == 0 {
		return errors.New("no IPs available")
	}

	containerNs, err := netns.GetFromPath(args.Netns)
	if err != nil {
		return fmt.Errorf("could not get network namespace from path %s for network device %s : %w", args.Netns, args.IfName, err)
	}

	mtu := 1500
	if response.MTU > 0 {
		mtu = response.MTU
	}

	ifName := getInterfaceName()

	link := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
			MTU:  mtu,
		},
		PeerName:      defaultInterface,
		PeerNamespace: netlink.NsFd(containerNs),
	}

	if err := netlink.LinkAdd(link); err != nil {
		return fmt.Errorf("fail to add interface on namespace %s : %v", args.Netns, err)
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set interface %s up: %v", ifName, err)
	}

	// don't accept Router Advertisements
	_ = os.WriteFile(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", ifName), []byte(strconv.Itoa(0)), 0640)

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if args.Netns == "" {
		return nil
	}

	containerNs, err := netns.GetFromPath(args.Netns)
	if err != nil {
		return fmt.Errorf("could not get network namespace from path %s for network device %s : %w", args.Netns, args.IfName, err)
	}
	// to avoid golang problem with goroutines we create the socket in the
	// namespace and use it directly
	nhNs, err := netlink.NewHandleAt(containerNs)
	if err != nil {
		// namespace no longer exist
		return nil
	}

	nsLink, err := nhNs.LinkByName(args.IfName)
	if err != nil {
		// interface is no present so no need to delete
		return nil
	}

	err = nhNs.LinkDel(nsLink)
	// in case there is a race since we already checked
	if err != nil && err == ip.ErrLinkNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to delete %q: %v", args.IfName, err)
	}
	return nil
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add: cmdAdd,
		Del: cmdDel,
	}, version.All, bv.BuildString(pluginName))
}

func getInterfaceName() string {
	rndString := make([]byte, 8)
	_, err := rand.Read(rndString)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("knet%x", rndString)
}
