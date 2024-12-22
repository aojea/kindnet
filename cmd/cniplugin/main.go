// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/aojea/kindnet/pkg/apis"
	"golang.org/x/sys/unix"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/040"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"k8s.io/utils/ptr"
)

// Only implement the minimum functionality defined by CNI required Kubernetes use cases.
// Create veth pair and request an IP to the kindnet daemon that manages the IPAM.
// This allows to add or remove new ranges without having to write on disk.
// It uses IP unnumbered to simplify the system and avoid dealing with classes and gateways
// xref: https://gist.github.com/aojea/571c29f1b35e5c411f8297a47227d39d

const (
	pluginName = "cni-kindnet"
	// containerd hardcodes this value
	// https://github.com/containerd/containerd/blob/23500b8015c6f5c624ec630fd1377a990e9eccfb/internal/cri/server/helpers.go#L68
	defaultInterface = "eth0"
	ipamURL          = "http://kindnet/ipam"
)

var (
	defaultV4gw = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 0)}
	defaultV6gw = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 0)}
)

func cmdAdd(args *skel.CmdArgs) error {
	conf := types.NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if args.Netns == "" {
		return nil
	}

	// IPAM is provided via an unix socket to allow dynamic configuration
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", apis.SocketPath)
			},
		},
	}

	// return an ordered comma separated list of IPs
	resp, err := client.Get(ipamURL)
	if err != nil {
		return fmt.Errorf("failed to connect to kindnet daemon: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("invalid kindnet response: %w", err)
	}

	var response apis.NetworkConfig
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
		return fmt.Errorf("no IPs available: %#v", result)
	}

	containerNs, err := netns.GetFromPath(args.Netns)
	if err != nil {
		return fmt.Errorf("could not get network namespace from path %s for network device %s : %w", args.Netns, args.IfName, err)
	}

	rootNs, err := netns.Get()
	if err != nil {
		return err
	}
	defer rootNs.Close()

	/*
		mtu := 1500
		if response.MTU > 0 {
			mtu = response.MTU
		}
	*/
	ifName := getInterfaceName()
	// to avoid golang problem with goroutines we create the socket in the
	// namespace and use it directly
	nhNs, err := netlink.NewHandleAt(containerNs)
	if err != nil {
		return err
	}

	flags := unix.NLM_F_CREATE | unix.NLM_F_EXCL | unix.NLM_F_ACK
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, flags)
	// Get a netlink socket in current namespace
	s, err := nl.GetNetlinkSocketAt(containerNs, rootNs, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("could not get network namespace handle: %w", err)
	}
	req.Sockets = map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: s},
	}

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	req.AddData(msg)

	nameData := nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(defaultInterface))
	req.AddData(nameData)

	// mtuData := nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(uint32(mtu)))
	// req.AddData(mtuData)

	// base namespace the container
	val := nl.Uint32Attr(uint32(containerNs))
	attr := nl.NewRtAttr(unix.IFLA_NET_NS_FD, val)
	req.AddData(attr)

	linkInfo := nl.NewRtAttr(unix.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated("veth"))

	// peer
	data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
	peer := data.AddRtAttr(nl.VETH_INFO_PEER, nil)
	nl.NewIfInfomsgChild(peer, unix.AF_UNSPEC)
	peer.AddRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(ifName))

	// valRoot := nl.Uint32Attr(uint32(rootNs))
	// peer.AddRtAttr(unix.IFLA_NET_NS_FD, valRoot)

	req.AddData(linkInfo)

	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return fmt.Errorf("fail to add interface on namespace %s : %v", args.Netns, err)
	}

	// don't accept Router Advertisements
	_ = os.WriteFile(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", ifName), []byte(strconv.Itoa(0)), 0640)

	nsLink, err := nhNs.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("could not get interface %s on namespace %s : %w", defaultInterface, args.Netns, err)
	}

	hostLink, err := netlink.LinkByName(defaultInterface)
	if err != nil {
		return fmt.Errorf("could not get interface %s on namespace %s : %w", defaultInterface, args.Netns, err)
	}

	// only set the default gateway once per IP family
	v4set := false
	v6set := false
	for _, ipconfig := range result.IPs {
		address := &netlink.Addr{IPNet: &ipconfig.Address}
		err = nhNs.AddrAdd(nsLink, address)
		if err != nil {
			return fmt.Errorf("could not add address %s on namespace %s : %w", ipconfig.Address.String(), args.Netns, err)
		}

		// set the default gateway inside the container
		if ipconfig.Version == "6" && !v6set {
			route := netlink.Route{LinkIndex: nsLink.Attrs().Index, Dst: defaultV6gw}
			if err := nhNs.RouteAdd(&route); err != nil {
				return fmt.Errorf("could not add default route on namespace %s : %w", args.Netns, err)
			}
			v6set = true
		} else if ipconfig.Version == "4" && !v4set {
			route := netlink.Route{LinkIndex: nsLink.Attrs().Index, Dst: defaultV4gw}
			if err := nhNs.RouteAdd(&route); err != nil {
				return fmt.Errorf("could not add default route on namespace %s : %w", args.Netns, err)
			}
			v4set = true
		}

		// set the route from the host to the network namespace
		route := netlink.Route{LinkIndex: hostLink.Attrs().Index, Dst: address.IPNet}
		if err := netlink.RouteAdd(&route); err != nil {
			return fmt.Errorf("could not add default route on namespace %s : %w", args.Netns, err)
		}
	}

	if err = nhNs.LinkSetUp(nsLink); err != nil {
		return fmt.Errorf("failed to set interface %s up: %v", ifName, err)
	}

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
	if err != nil {
		return fmt.Errorf("failed to delete %q: %v", args.IfName, err)
	}
	return nil
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add: cmdAdd,
		Del: cmdDel,
	}, version.All, "CNI plugin kindnet v0.1")
}

func getInterfaceName() string {
	rndString := make([]byte, 4)
	_, err := rand.Read(rndString)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("knet%x", rndString)
}
