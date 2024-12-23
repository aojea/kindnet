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
	"net/netip"
	"os"
	"strconv"

	"github.com/aojea/kindnet/pkg/apis"
	"golang.org/x/sys/unix"
	"sigs.k8s.io/knftables"

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
	pluginName    = apis.PluginName
	hostPortMapv4 = apis.HostPortMapv4
	hostPortMapv6 = apis.HostPortMapv6
	// containerd hardcodes this value
	// https://github.com/containerd/containerd/blob/23500b8015c6f5c624ec630fd1377a990e9eccfb/internal/cri/server/helpers.go#L68
	defaultInterface = "eth0"
	ipamURL          = "http://kindnet/ipam"
)

var (
	// IPAM is provided via an unix socket to allow dynamic configuration
	client = http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", apis.SocketPath)
			},
		},
	}
)

// release does not return an error because if kindnetd is not available
// it will reconcile the allocated IPs so no need to block Pod deletion
func release(id string) *apis.NetworkConfig {
	// create a new DELETE request
	req, err := http.NewRequest(http.MethodDelete, ipamURL+"?id="+id, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error releasing network for container id %s : %v", id, err)
		return nil
	}

	// send the request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error releasing network for container id %s : %v", id, err)
		return nil
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error releasing network for container id %s : %v", id, err)
		return nil
	}

	var response apis.NetworkConfig
	if err := json.Unmarshal(body, &response); err != nil {
		fmt.Fprintf(os.Stderr, "error releasing network for container id %s : %v", id, err)
		return nil
	}

	return &response
}

// PortMapEntry corresponds to a single entry in the port_mappings argument,
// see CNI CONVENTIONS.md
type PortMapEntry struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIP        string `json:"hostIP,omitempty"`
}

type PortMapConf struct {
	types.NetConf
	RuntimeConfig struct {
		PortMaps []PortMapEntry `json:"portMappings,omitempty"`
	} `json:"runtimeConfig,omitempty"`
}

func cmdAdd(args *skel.CmdArgs) (err error) {
	var containerIPv4, containerIPv6 string

	conf := PortMapConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if args.Netns == "" {
		return nil
	}

	// return an ordered comma separated list of IPs
	resp, err := client.Get(ipamURL + "?id=" + args.ContainerID)
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
			containerIPv6 = address
		} else {
			containerIPv4 = address
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

	mtu := 1500
	if response.MTU > 0 {
		mtu = response.MTU
	}

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

	mtuData := nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(uint32(mtu)))
	req.AddData(mtuData)

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

	valRoot := nl.Uint32Attr(uint32(rootNs))
	peer.AddRtAttr(unix.IFLA_NET_NS_FD, valRoot)

	req.AddData(linkInfo)

	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return fmt.Errorf("fail to add interface on namespace %s : %v", args.Netns, err)
	}

	// don't accept Router Advertisements
	_ = os.WriteFile(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", ifName), []byte(strconv.Itoa(0)), 0640)

	// best effort to set the loopback interface up
	loLink, err := nhNs.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("could not get interface loopback on namespace %s : %w", args.Netns, err)
	}
	_ = nhNs.LinkSetUp(loLink)

	nsLink, err := nhNs.LinkByName(defaultInterface)
	if err != nil {
		return fmt.Errorf("could not get interface %s on namespace %s : %w", defaultInterface, args.Netns, err)
	}

	if err = nhNs.LinkSetUp(nsLink); err != nil {
		return fmt.Errorf("failed to set interface %s up: %v", defaultInterface, err)
	}

	hostLink, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("could not get interface %s on namespace %s : %w", ifName, args.Netns, err)
	}

	if err = netlink.LinkSetUp(hostLink); err != nil {
		return fmt.Errorf("failed to set interface %s up: %v", ifName, err)
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

		routeGw := netlink.Route{
			LinkIndex: nsLink.Attrs().Index,
			Flags:     int(netlink.FLAG_ONLINK), // no need to arp
		}
		// set the default gateway inside the container
		if ipconfig.Version == "6" && !v6set {
			ip := net.ParseIP(response.GatewayV6)
			if ip == nil {
				return fmt.Errorf("invalid ip address %s", address)
			}
			routeGw.Gw = ip
			routeGw.Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 0)}
			if err := nhNs.RouteAdd(&routeGw); err != nil {
				return fmt.Errorf("could not add default route on namespace %s : %w", args.Netns, err)
			}
			// set the route from the host to the network namespace
			route := netlink.Route{
				LinkIndex: hostLink.Attrs().Index,
				Src:       ip,
				Dst:       address.IPNet,
			}
			if err := netlink.RouteAdd(&route); err != nil {
				return fmt.Errorf("could not add route to the container interface %s : %w", hostLink.Attrs().Name, err)
			}
			v6set = true
		} else if ipconfig.Version == "4" && !v4set {
			ip := net.ParseIP(response.GatewayV4)
			if ip == nil {
				return fmt.Errorf("invalid ip address %s", address)
			}
			routeGw.Gw = ip
			routeGw.Dst = &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 0)}
			if err := nhNs.RouteAdd(&routeGw); err != nil {
				return fmt.Errorf("could not add default route on namespace %s : %w", args.Netns, err)
			}
			// set the route from the host to the network namespace
			route := netlink.Route{
				LinkIndex: hostLink.Attrs().Index,
				Src:       ip,
				Dst:       address.IPNet,
			}
			if err := netlink.RouteAdd(&route); err != nil {
				return fmt.Errorf("could not add route to the container interface %s : %w", hostLink.Attrs().Name, err)
			}
			v4set = true
		}
	}

	// portmaps
	if len(conf.RuntimeConfig.PortMaps) > 0 {
		// Write nftables for the portmap functionality
		nft, err := knftables.New(knftables.InetFamily, pluginName)
		if err != nil {
			return fmt.Errorf("portmap failure, can not start nftables:%v", err)
		}

		tx := nft.NewTransaction()
		// Set up this container
		for _, e := range conf.RuntimeConfig.PortMaps {
			if e.HostIP != "" {
				ip, err := netip.ParseAddr(e.HostIP)
				if err != nil {
					continue
				}

				if ip.Is4() && containerIPv4 != "" {
					tx.Add(&knftables.Element{
						Map:   hostPortMapv4,
						Key:   []string{e.HostIP, e.Protocol, strconv.Itoa(e.HostPort)},
						Value: []string{containerIPv4, strconv.Itoa(e.ContainerPort)},
					})
				} else if ip.Is6() && containerIPv6 != "" {
					tx.Add(&knftables.Element{
						Map:   hostPortMapv6,
						Key:   []string{e.HostIP, e.Protocol, strconv.Itoa(e.HostPort)},
						Value: []string{containerIPv6, strconv.Itoa(e.ContainerPort)},
					})
				}
			} else {
				if containerIPv4 != "" {
					tx.Add(&knftables.Element{
						Map:   hostPortMapv4,
						Key:   []string{"0.0.0.0/0", e.Protocol, strconv.Itoa(e.HostPort)},
						Value: []string{containerIPv4, strconv.Itoa(e.ContainerPort)},
					})
				} else if containerIPv6 != "" {
					tx.Add(&knftables.Element{
						Map:   hostPortMapv6,
						Key:   []string{"::/0", e.Protocol, strconv.Itoa(e.HostPort)},
						Value: []string{containerIPv6, strconv.Itoa(e.ContainerPort)},
					})
				}
			}

		}
		err = nft.Run(context.Background(), tx)
		if err != nil {
			return fmt.Errorf("failed to add nftables for portmaps %s: %v", tx.String(), err)
		}
	}

	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	conf := PortMapConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if args.Netns == "" {
		return nil
	}

	var v4, v6 bool
	response := release(args.ContainerID)
	for _, address := range response.IPs {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			continue
		}
		if ip.Is4() {
			v4 = true
		} else if ip.Is6() {
			v6 = true
		}
	}
	// if we don't have an answer we need to make our best to clean
	// us much as possible to not leak entries on the map
	// TODO: Hostports are better handled via kindnetd but watching all
	// pods on the node to get the data from the pod.Spec.Containers[*]
	// is expensive and we try to avoid it.
	blindMode := (!v4 && !v6)

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

	// portmaps
	if len(conf.RuntimeConfig.PortMaps) > 0 {
		nft, err := knftables.New(knftables.InetFamily, pluginName)
		if err != nil {
			return fmt.Errorf("portmap failure, can not start nftables:%v", err)
		}

		tx := nft.NewTransaction()

		// Set up this container
		for _, e := range conf.RuntimeConfig.PortMaps {
			if e.HostIP != "" {
				ip, err := netip.ParseAddr(e.HostIP)
				if err != nil {
					continue
				}

				if (ip.Is4() && v4) || blindMode {
					tx.Delete(&knftables.Element{
						Map: hostPortMapv4,
						Key: []string{e.HostIP, e.Protocol, strconv.Itoa(e.HostPort)},
					})
				} else if (ip.Is6() && v6) || blindMode {
					tx.Delete(&knftables.Element{
						Map: hostPortMapv6,
						Key: []string{e.HostIP, e.Protocol, strconv.Itoa(e.HostPort)},
					})
				}
			} else {
				if v4 || blindMode {
					tx.Delete(&knftables.Element{
						Map: hostPortMapv4,
						Key: []string{"0.0.0.0/0", e.Protocol, strconv.Itoa(e.HostPort)},
					})
				}
				if v6 || blindMode {
					tx.Delete(&knftables.Element{
						Map: hostPortMapv6,
						Key: []string{"::/0", e.Protocol, strconv.Itoa(e.HostPort)},
					})
				}
			}
		}

		err = nft.Run(context.Background(), tx)
		if err != nil && !blindMode {
			return fmt.Errorf("failed to remove nftables for portmaps %s: %v", tx.String(), err)
		}
	}
	return nil
}

func main() {
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add: cmdAdd,
		Del: cmdDel,
	},
		version.PluginSupports("0.1.0", "0.2.0", "0.3.0", "0.3.1", "0.4.0"),
		"CNI plugin "+pluginName,
	)
}

func getInterfaceName() string {
	rndString := make([]byte, 4)
	_, err := rand.Read(rndString)
	if err != nil {
		panic(err)
	}

	return fmt.Sprintf("knet%x", rndString)
}
