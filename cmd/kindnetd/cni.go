// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/aojea/kindnet/pkg/apis"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

type Allocator struct {
	mu       sync.Mutex
	cidr     netip.Prefix
	store    sets.Set[netip.Addr]
	ipFirst  netip.Addr
	ipLast   netip.Addr
	size     uint64
	reserved int // reserve first number of address
}

func NewAllocator(cidr netip.Prefix, reserved int) (*Allocator, error) {
	var size uint64
	hostsBits := cidr.Addr().BitLen() - cidr.Bits()
	if hostsBits > 64 {
		size = math.MaxUint64
	} else {
		size = uint64(1) << uint(hostsBits)
	}
	if size < uint64(reserved) {
		return nil, fmt.Errorf("range too short")
	}
	// Caching the first, offset and last addresses allows to optimize
	// the search loops by using the netip.Addr iterator instead
	// of having to do conversions with IP addresses.
	// Don't allocate the network's ".0" address.
	ipFirst := cidr.Masked().Addr().Next()
	// Don't allocate in the reserved zone
	ipFirst, err := addOffsetAddress(ipFirst, uint64(reserved))
	if err != nil {
		return nil, err
	}
	// Use the broadcast address as last address for IPv6
	ipLast, err := broadcastAddress(cidr)
	if err != nil {
		return nil, err
	}

	return &Allocator{
		cidr:     cidr,
		size:     size,
		reserved: reserved,
		store:    sets.Set[netip.Addr]{},
		ipFirst:  ipFirst,
		ipLast:   ipLast,
	}, nil
}

// IP iterator allows to iterate over all the IP addresses
// in a range defined by the start and last address.
// It starts iterating at the address position defined by the offset.
// It returns an invalid address to indicate it has finished.
func ipIterator(first netip.Addr, last netip.Addr, offset uint64) func() netip.Addr {
	// There are no modulo operations for IP addresses
	modulo := func(addr netip.Addr) netip.Addr {
		if addr.Compare(last) == 1 {
			return first
		}
		return addr
	}
	next := func(addr netip.Addr) netip.Addr {
		return modulo(addr.Next())
	}
	start, err := addOffsetAddress(first, offset)
	if err != nil {
		return func() netip.Addr { return netip.Addr{} }
	}
	start = modulo(start)
	ip := start
	seen := false
	return func() netip.Addr {
		value := ip
		// is the last or the first iteration
		if value == start {
			if seen {
				return netip.Addr{}
			}
			seen = true
		}
		ip = next(ip)
		return value
	}
}

func (a *Allocator) Allocate() (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	rangeSize := a.size - uint64(a.reserved)
	var offset uint64
	switch {
	case rangeSize >= math.MaxInt64:
		offset = rand.Uint64()
	case rangeSize == 0:
		return netip.Addr{}, fmt.Errorf("not available addresses")
	default:
		offset = uint64(rand.Int64N(int64(rangeSize)))
	}

	iterator := ipIterator(a.ipFirst, a.ipLast, offset)
	for {
		ip := iterator()
		if !ip.IsValid() {
			break
		}
		// IP already exist
		if a.store.Has(ip) {
			continue
		}
		a.store.Insert(ip)
		return ip, nil

	}
	return netip.Addr{}, fmt.Errorf("allocator full")
}

func (a *Allocator) AllocateAddress(ip netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.cidr.Contains(ip) {
		return fmt.Errorf("address %s out of range %s", ip.String(), a.cidr.String())
	}
	if a.store.Has(ip) {
		return fmt.Errorf("address %s allready allocated", ip.String())
	}
	if a.ipFirst.Compare(ip) == 1 {
		return fmt.Errorf("address %s on the reserved space, lower than %s", ip.String(), a.ipFirst.String())
	}
	a.store.Insert(ip)
	return nil
}

func (a *Allocator) Release(ip netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.store, ip)
}

/* cni config management */

type CNIServer struct {
	allocatorV4 []*Allocator
	allocatorV6 []*Allocator
	listener    net.Listener
	mtu         int

	nodeName    string
	nodeLister  corelisters.NodeLister
	nodesSynced cache.InformerSynced
}

func NewCNIServer(nodeName string, nodeInformer coreinformers.NodeInformer) (*CNIServer, error) {
	listener, err := net.Listen("unix", apis.SocketPath)
	if err != nil {
		return nil, err
	}

	mtu, err := GetMTU(netlink.FAMILY_V4)
	if err != nil {
		mtu, err = GetMTU(netlink.FAMILY_V6)
		if err != nil {
			return nil, err
		}
	}

	c := &CNIServer{
		nodeName:    nodeName,
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		listener:    listener,
		mtu:         mtu,
	}

	return c, nil
}

func (c *CNIServer) Run(ctx context.Context) error {

	if ok := cache.WaitForCacheSync(ctx.Done(), c.nodesSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	var ranges []string
	err := wait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (done bool, err error) {
		node, err := c.nodeLister.Get(c.nodeName)
		if err != nil || node == nil {
			return false, nil
		}
		if len(node.Spec.PodCIDRs) > 0 {
			ranges = node.Spec.PodCIDRs
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return err
	}

	for _, cidr := range ranges {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return err
		}
		allocator, err := NewAllocator(prefix, 8)
		if err != nil {
			return err
		}
		if prefix.Addr().Is4() {
			c.allocatorV4 = append(c.allocatorV4, allocator)
		} else {
			c.allocatorV6 = append(c.allocatorV6, allocator)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ipam", func(w http.ResponseWriter, r *http.Request) {
		result := apis.NetworkConfig{
			MTU: c.mtu,
		}
		for _, v4alloc := range c.allocatorV4 {
			addr, err := v4alloc.Allocate()
			if err != nil {
				continue
			}
			result.IPs = append(result.IPs, addr.String())
			break
		}
		for _, v6alloc := range c.allocatorV6 {
			addr, err := v6alloc.Allocate()
			if err != nil {
				continue
			}
			result.IPs = append(result.IPs, addr.String())
			break
		}
		out, err := json.Marshal(result)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})

	err = WriteCNIConfig()
	if err != nil {
		klog.Fatalf("unable to write CNI config file: %v", err)
	}

	return http.Serve(c.listener, mux)
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

// broadcastAddress returns the broadcast address of the subnet
// The broadcast address is obtained by setting all the host bits
// in a subnet to 1.
// network 192.168.0.0/24 : subnet bits 24 host bits 32 - 24 = 8
// broadcast address 192.168.0.255
func broadcastAddress(subnet netip.Prefix) (netip.Addr, error) {
	base := subnet.Masked().Addr()
	bytes := base.AsSlice()
	// get all the host bits from the subnet
	n := 8*len(bytes) - subnet.Bits()
	// set all the host bits to 1
	for i := len(bytes) - 1; i >= 0 && n > 0; i-- {
		if n >= 8 {
			bytes[i] = 0xff
			n -= 8
		} else {
			mask := ^uint8(0) >> (8 - n)
			bytes[i] |= mask
			break
		}
	}

	addr, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid address %v", bytes)
	}
	return addr, nil
}

// addOffsetAddress returns the address at the provided offset within the subnet
// TODO: move it to k8s.io/utils/net, this is the same as current AddIPOffset()
// but using netip.Addr instead of net.IP
func addOffsetAddress(address netip.Addr, offset uint64) (netip.Addr, error) {
	addressBytes := address.AsSlice()
	addressBig := big.NewInt(0).SetBytes(addressBytes)
	r := big.NewInt(0).Add(addressBig, big.NewInt(int64(offset))).Bytes()
	// r must be 4 or 16 bytes depending of the ip family
	// bigInt conversion to bytes will not take this into consideration
	// and drop the leading zeros, so we have to take this into account.
	lenDiff := len(addressBytes) - len(r)
	if lenDiff > 0 {
		r = append(make([]byte, lenDiff), r...)
	} else if lenDiff < 0 {
		return netip.Addr{}, fmt.Errorf("invalid address %v", r)
	}
	addr, ok := netip.AddrFromSlice(r)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid address %v", r)
	}
	return addr, nil
}
