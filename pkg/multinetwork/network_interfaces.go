// SPDX-License-Identifier: APACHE-2.0

package multinetwork

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
	resourceapi "k8s.io/api/resource/v1beta1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"k8s.io/utils/set"
)

// InterfaceMode represents the operating mode of a network interface.
type InterfaceMode string

const (
	// number of max number of virtual interfaces: macvlan, ipvlan, vlan, ...
	maxCapacity = 100
	// TrunkMode indicates a trunk network interface, allowing for multiple sub-interfaces.
	// It can also be used as an access mode
	TrunkMode InterfaceMode = "Trunk"

	// AccessMode indicates an access network interface, no sub-interfaces allowed.
	AccessMode InterfaceMode = "Access"

	// HybridMode indicates an interface can be used as Access or Trunk.
	HybridMode InterfaceMode = "Hybrid"
)

var (
	dns1123LabelNonValid = regexp.MustCompile("[^a-z0-9-]")
)

func netdevToDRAdev(ifName string, mode InterfaceMode) (*resourceapi.Device, error) {
	device := resourceapi.Device{
		Name: ifName,
		Basic: &resourceapi.BasicDevice{
			Attributes: make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute),
			Capacity:   make(map[resourceapi.QualifiedName]resourceapi.DeviceCapacity),
		},
	}

	// normalize the name because interface names may contain invalid
	// characters as object names
	if len(validation.IsDNS1123Label(ifName)) > 0 {
		klog.V(2).Infof("normalizing iface %s name", ifName)
		device.Name = "normalized-" + dns1123LabelNonValid.ReplaceAllString(ifName, "-")
	}
	device.Basic.Attributes["name"] = resourceapi.DeviceAttribute{StringValue: &ifName}
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		klog.Infof("Error getting link by name %v", err)
		return nil, err
	}
	linkType := link.Type()
	linkAttrs := link.Attrs()

	// identify the namespace holding the link as the other end of a veth pair
	alias := link.Attrs().Alias
	if strings.Contains(alias, "link-pod") {
		return nil, fmt.Errorf("interface belongs to an existing Pod")
	}

	ipv4s := set.Set[string]{}
	ipv6s := set.Set[string]{}
	ips, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil && !errors.Is(err, unix.EINTR) {
		return nil, err
	}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			ipv4s.Insert(ip.IPNet.String())
		} else {
			ipv6s.Insert(ip.IPNet.String())
		}
	}

	device.Basic.Attributes["mode"] = resourceapi.DeviceAttribute{StringValue: ptr.To(string(mode))}
	if mode == TrunkMode {
		// TODO add more technologies as vlan or ipvlan
		device.Basic.Capacity["macvlan"] = resourceapi.DeviceCapacity{Value: *resource.NewQuantity(maxCapacity, resource.DecimalSI)}
	}

	if ipv4s.Len() > 0 {
		ips := strings.Join(ipv4s.SortedList(), ",")
		device.Basic.Attributes["ipv4"] = resourceapi.DeviceAttribute{StringValue: &ips}
	}
	if ipv6s.Len() > 0 {
		ips := strings.Join(ipv6s.SortedList(), ",")
		device.Basic.Attributes["ipv6"] = resourceapi.DeviceAttribute{StringValue: &ips}
	}

	mac := link.Attrs().HardwareAddr.String()
	if mac != "" {
		device.Basic.Attributes["mac"] = resourceapi.DeviceAttribute{StringValue: &mac}
	}
	mtu := int64(link.Attrs().MTU)
	if mtu != 0 {
		device.Basic.Attributes["mtu"] = resourceapi.DeviceAttribute{IntValue: &mtu}
	}

	device.Basic.Attributes["encapsulation"] = resourceapi.DeviceAttribute{StringValue: &linkAttrs.EncapType}
	operState := linkAttrs.OperState.String()
	device.Basic.Attributes["state"] = resourceapi.DeviceAttribute{StringValue: &operState}
	if linkAttrs.Alias != "" {
		device.Basic.Attributes["alias"] = resourceapi.DeviceAttribute{StringValue: &linkAttrs.Alias}
	}
	if linkType != "" {
		device.Basic.Attributes["type"] = resourceapi.DeviceAttribute{StringValue: &linkType}
	}

	return &device, nil
}

func nsAttachNetdev(hostIfName string, containerNsPAth string, ifName string) error {
	hostDev, err := netlink.LinkByName(hostIfName)
	if err != nil {
		return err
	}

	// Devices can be renamed only when down
	if err = netlink.LinkSetDown(hostDev); err != nil {
		return fmt.Errorf("failed to set %q down: %v", hostDev.Attrs().Name, err)
	}

	// get the existing IP addresses
	addresses, err := netlink.AddrList(hostDev, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("fail to get ip addresses: %w", err)
	}

	containerNs, err := netns.GetFromPath(containerNsPAth)
	if err != nil {
		return err
	}

	attrs := hostDev.Attrs()
	// Store the original name
	attrs.Alias = hostIfName

	// copy from netlink.LinkModify(dev) using only the parts needed
	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, flags)
	// Get a netlink socket in current namespace
	s, err := nl.GetNetlinkSocketAt(netns.None(), netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("could not get network namespace handle: %w", err)
	}
	req.Sockets = map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: s},
	}

	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(attrs.Index)
	req.AddData(msg)

	nameData := nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(attrs.Name))
	req.AddData(nameData)

	alias := nl.NewRtAttr(unix.IFLA_IFALIAS, []byte(attrs.Alias))
	req.AddData(alias)

	mtu := nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(uint32(attrs.MTU)))
	req.AddData(mtu)

	val := nl.Uint32Attr(uint32(containerNs))
	attr := nl.NewRtAttr(unix.IFLA_NET_NS_FD, val)
	req.AddData(attr)

	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	// to avoid golang problem with goroutines we create the socket in the
	// namespace and use it directly
	nhNs, err := netlink.NewHandleAt(containerNs)
	if err != nil {
		return err
	}

	nsLink, err := nhNs.LinkByName(attrs.Name)
	if err != nil {
		return fmt.Errorf("link not found for interface %s on namespace %s: %w", attrs.Name, containerNsPAth, err)
	}

	for _, address := range addresses {
		// remove the interface attribute of the original address
		// to avoid issues when the interface is renamed.
		err = nhNs.AddrAdd(nsLink, &netlink.Addr{IPNet: address.IPNet})
		if err != nil {
			return fmt.Errorf("fail to set up address %s on namespace %s: %w", address.String(), containerNsPAth, err)
		}
	}

	err = nhNs.LinkSetUp(nsLink)
	if err != nil {
		return fmt.Errorf("failt to set up interface %s on namespace %s: %w", nsLink.Attrs().Name, containerNsPAth, err)
	}

	return nil
}

func nsDetachNetdev(containerNsPAth string, devName string) error {
	containerNs, err := netns.GetFromPath(containerNsPAth)
	if err != nil {
		return fmt.Errorf("could not get network namespace from path %s for network device %s : %w", containerNsPAth, devName, err)
	}
	// to avoid golang problem with goroutines we create the socket in the
	// namespace and use it directly
	nhNs, err := netlink.NewHandleAt(containerNs)
	if err != nil {
		return fmt.Errorf("could not get network namespace handle: %w", err)
	}

	nsLink, err := nhNs.LinkByName(devName)
	if err != nil {
		return fmt.Errorf("link not found for interface %s on namespace %s: %w", devName, containerNsPAth, err)
	}

	// set the device down to avoid network conflicts
	// when it is restored to the original namespace
	err = nhNs.LinkSetDown(nsLink)
	if err != nil {
		return err
	}

	attrs := nsLink.Attrs()
	// restore the original name if it was renamed
	if nsLink.Attrs().Alias != "" {
		attrs.Name = nsLink.Attrs().Alias
	}

	rootNs, err := netns.Get()
	if err != nil {
		return err
	}
	defer rootNs.Close()

	s, err := nl.GetNetlinkSocketAt(containerNs, rootNs, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("could not get network namespace handle: %w", err)
	}
	// copy from netlink.LinkModify(dev) using only the parts needed
	flags := unix.NLM_F_REQUEST | unix.NLM_F_ACK
	req := nl.NewNetlinkRequest(unix.RTM_NEWLINK, flags)
	req.Sockets = map[int]*nl.SocketHandle{
		unix.NETLINK_ROUTE: {Socket: s},
	}
	msg := nl.NewIfInfomsg(unix.AF_UNSPEC)
	msg.Index = int32(attrs.Index)
	req.AddData(msg)

	nameData := nl.NewRtAttr(unix.IFLA_IFNAME, nl.ZeroTerminated(attrs.Name))
	req.AddData(nameData)

	alias := nl.NewRtAttr(unix.IFLA_IFALIAS, []byte(attrs.Alias))
	req.AddData(alias)

	mtu := nl.NewRtAttr(unix.IFLA_MTU, nl.Uint32Attr(uint32(attrs.MTU)))
	req.AddData(mtu)

	val := nl.Uint32Attr(uint32(rootNs))
	attr := nl.NewRtAttr(unix.IFLA_NET_NS_FD, val)
	req.AddData(attr)

	_, err = req.Execute(unix.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	return nil
}

func getDefaultGwInterfaceName() string {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil && !errors.Is(err, unix.EINTR) {
		return ""
	}

	for _, r := range routes {
		if r.Dst.IP.Equal(net.IPv4zero) || r.Dst.IP.Equal(net.IPv6zero) {
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				continue
			}
			return intfLink.Attrs().Name
		}
	}
	return ""
}

func addMacVlan(containerNsPAth string, devName string) error {
	containerNs, err := netns.GetFromPath(containerNsPAth)
	if err != nil {
		return fmt.Errorf("could not get network namespace from path %s for network device %s : %w", containerNsPAth, devName, err)
	}
	parentLink, err := netlink.LinkByName(devName)
	if err != nil {
		return fmt.Errorf("could not find parent interface %s : %w", devName, err)
	}
	macvlan := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        "knet-" + devName,
			ParentIndex: parentLink.Attrs().Index,
			NetNsID:     int(containerNs),
		},
		Mode: netlink.MACVLAN_MODE_BRIDGE,
	}
	if err := netlink.LinkAdd(macvlan); err != nil {
		// If a user creates a macvlan and ipvlan on same parent, only one slave iface can be active at a time.
		return fmt.Errorf("failed to create the %s macvlan interface: %v", macvlan.Name, err)
	}

	return nil
}
