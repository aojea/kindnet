/*
Copyright 2024 The Kubernetes Authors.

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
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

const (
	prefixNAT64           = "64:ff9b::/96"
	tproxyNAT64BypassMark = 14
	tproxyNAT64Mark       = 13
	tproxyNAT64Table      = 101
)

func NewNAT64Agent() (*NAT64Agent, error) {
	klog.V(2).Info("Initializing nftables")
	nft, err := knftables.New(knftables.IPv6Family, "kindnet-nat64")
	if err != nil {
		return nil, err
	}

	d := &NAT64Agent{
		nft:      nft,
		interval: 5 * time.Minute,
	}

	return d, nil
}

// NAT64Agent caches all DNS traffic from Pods with network based on the PodCIDR of the node they are running.
// Cache logic is very specific to Kubernetes,
type NAT64Agent struct {
	nft      knftables.Interface
	interval time.Duration

	udpProxyAddr string
	tcpProxyAddr string
	flushed      bool
}

// Run syncs dns cache intercept rules
func (n *NAT64Agent) Run(ctx context.Context) error {

	// start listeners
	udpLc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
				klog.Fatalf("error setting IPV6_TRANSPARENT: %v", err)
			}
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1); err != nil {
				klog.Fatalf("error setting IPV6_RECVORIGDSTADDR: %v", err)

			}

		})
	},
	}

	// UDP NAT64 proxy
	// use mtu as max size of the UDP packet
	mtu, err := GetMTU(unix.AF_INET6)
	if err != nil {
		klog.Infof("Failed to get MTU size from interface eth0, using kernel default MTU size error:%v", err)
		mtu = 1500
	}

	conn, err := udpLc.ListenPacket(context.Background(), "udp6", "[::1]:0")
	if err != nil {
		return err
	}
	defer conn.Close()
	n.udpProxyAddr = conn.LocalAddr().String()
	klog.V(2).Infof("listening on UDP %s", n.udpProxyAddr)

	go func() {
		for {
			buf := make([]byte, mtu)
			udpConn, ok := conn.(*net.UDPConn)
			if !ok {
				klog.Infof("invalid connection type, not UDP")
				continue
			}
			n, origAddr, dstAddr, err := ReadFromUDP(udpConn, buf)
			if err != nil {
				klog.Infof("error on UDP connection: %v", err)
				continue
			}
			klog.V(7).Infof("UDP connection from %s to %s", origAddr.String(), dstAddr.String())
			go handleUDPConn(origAddr, dstAddr, buf[:n])
		}
	}()

	// TCP NAT64 proxy
	tcpLc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
				klog.Fatalf("error setting IP_TRANSPARENT: %v", err)
			}
		})
	},
	}

	tcpListener, err := tcpLc.Listen(context.Background(), "tcp6", "[::1]:0")
	if err != nil {
		return err
	}
	defer tcpListener.Close()
	n.tcpProxyAddr = tcpListener.Addr().String()
	klog.V(2).Infof("listening on TCP %s", n.tcpProxyAddr)

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				klog.Fatalf("Unrecoverable error while accepting connection: %s", err)
				return
			}
			klog.V(7).Infof("TCP connection from %s", conn.RemoteAddr().String())
			go handleTCPConn(conn)
		}
	}()

	klog.Info("Syncing local route rules")
	err = n.syncLocalRoute()
	if err != nil {
		klog.Infof("error syncing local route: %v", err)
	}

	klog.Info("Syncing nftables rules")
	errs := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := n.SyncRules(ctx); err != nil {
			errs++
			if errs > 3 {
				return fmt.Errorf("can't synchronize rules after 3 attempts: %v", err)
			}
		} else {
			errs = 0
		}
		time.Sleep(n.interval)
	}
}

func (n *NAT64Agent) syncLocalRoute() error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find 'lo' link: %v", err)
	}

	r := netlink.NewRule()
	r.Family = unix.AF_INET6
	r.Table = tproxyNAT64Table
	r.Mark = tproxyNAT64Mark
	if err := netlink.RuleAdd(r); err != nil {
		return fmt.Errorf("failed to configure netlink rule: %v", err)
	}

	_, dst, err := net.ParseCIDR(prefixNAT64)
	if err != nil {
		return fmt.Errorf("parse CIDR: %v", err)
	}

	err = netlink.RouteAdd(&netlink.Route{
		Dst:       dst,
		Scope:     netlink.SCOPE_HOST,
		Type:      unix.RTN_LOCAL,
		Table:     tproxyNAT64Table,
		LinkIndex: link.Attrs().Index,
	})
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
			return fmt.Errorf("failed to add route: %v", err)
		}

	}
	return nil
}

// SyncRules syncs ip masquerade rules
func (n *NAT64Agent) SyncRules(ctx context.Context) error {
	table := &knftables.Table{
		Comment: knftables.PtrTo("rules for kindnet dnscache"),
	}
	tx := n.nft.NewTransaction()
	// do it once to delete the existing table
	if !n.flushed {
		tx.Add(table)
		tx.Delete(table)
		n.flushed = true
	}
	tx.Add(table)

	hook := knftables.PreroutingHook
	chainName := string(hook)
	tx.Add(&knftables.Chain{
		Name: chainName,
		Type: knftables.PtrTo(knftables.FilterType),
		Hook: knftables.PtrTo(hook),
		// before conntrack to avoid tproxied traffic to be natted
		// https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation
		// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
		Priority: knftables.PtrTo(knftables.RawPriority + "-10"),
	})
	tx.Flush(&knftables.Chain{
		Name: chainName,
	})
	// bypass mark
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"meta", "mark", tproxyNAT64BypassMark, "return",
		),
	})

	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"ip6 daddr", prefixNAT64,
			"meta l4proto udp",
			"tproxy ip6 to", n.udpProxyAddr,
			"meta mark set", tproxyNAT64Mark,
			"notrack",
			"accept",
		), // set a mark to check if there is abug in the kernel when creating the entire expression
		Comment: ptr.To("UDP NAT64 traffic"),
	})

	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"ip6 daddr", prefixNAT64,
			"meta l4proto tcp",
			"tproxy ip6 to", n.tcpProxyAddr,
			"meta mark set", tproxyNAT64Mark,
			"notrack",
			"accept",
		), // set a mark to check if there is abug in the kernel when creating the entire expression
		Comment: ptr.To("TCP NAT64 traffic"),
	})

	// stop processing tproxied traffic
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"meta", "mark", tproxyNAT64Mark, "drop",
		),
	})

	if err := n.nft.Run(ctx, tx); err != nil {
		klog.Infof("error syncing nftables rules %v", err)
		return err
	}
	return nil
}

func (n *NAT64Agent) CleanRules() {
	tx := n.nft.NewTransaction()
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	tx.Add(&knftables.Table{})
	tx.Delete(&knftables.Table{})

	if err := n.nft.Run(context.TODO(), tx); err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}

func handleTCPConn(conn net.Conn) {
	defer conn.Close()

	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		klog.V(2).Infof("Failed to get remote address [%s]: %v", conn.LocalAddr().String(), err)
		return
	}
	ip4in6 := net.ParseIP(host)
	if ip4in6 == nil || ip4in6.To16() == nil {
		klog.V(2).Infof("Failed to get remote address from IP [%s]: %v", host, err)
		return
	}

	// assume 64:ff9b::/96 and last 4 digits
	// https://www.rfc-editor.org/rfc/rfc6052.html
	ip4 := ip4in6[12:16]
	klog.V(4).Infof("Connecting to [%s]", net.JoinHostPort(ip4.String(), port))
	remoteConn, err := net.Dial("tcp4", net.JoinHostPort(ip4.String(), port))
	if err != nil {
		klog.V(2).Infof("Failed to connect to original destination [%s]: %s", conn.LocalAddr().String(), err)
		return
	}
	defer remoteConn.Close()

	var streamWait sync.WaitGroup
	streamWait.Add(2)

	streamConn := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src) // golint: errcheck
		streamWait.Done()
	}

	go streamConn(remoteConn, conn)
	go streamConn(conn, remoteConn)

	streamWait.Wait()
}

func handleUDPConn(origAddr *net.UDPAddr, dstAddr *net.UDPAddr, data []byte) {
	ip4in6 := dstAddr.IP
	if ip4in6 == nil || ip4in6.To16() == nil {
		klog.V(2).Infof("Failed to get remote address from IP %s", dstAddr.IP.String())
		return
	}

	// assume 64:ff9b::/96 and last 4 digits
	// https://www.rfc-editor.org/rfc/rfc6052.html
	ip4 := ip4in6[12:16]
	dstV4Addr := fmt.Sprintf("%s:%d", ip4.String(), dstAddr.Port)
	klog.V(4).Infof("Connecting to %s", dstV4Addr)
	remoteConn, err := net.Dial("udp", dstV4Addr)
	if err != nil {
		klog.V(2).Infof("Failed to connect to original destination %s: %v", dstV4Addr, err)
		return
	}
	defer remoteConn.Close()

	n, err := remoteConn.Write(data)
	if err != nil {
		klog.V(2).Infof("Fail to write to remote %s: %s", remoteConn.RemoteAddr(), err)
		return
	} else if n < len(data) {
		klog.V(2).Infof("Buffer underflow %d < %d to remote %s", n, len(data), remoteConn.RemoteAddr())
		return
	}

	data = make([]byte, 1500)
	err = remoteConn.SetReadDeadline(time.Now().Add(3 * time.Second)) // Add deadline to ensure it doesn't block forever
	if err != nil {
		klog.Infof("error setting readdeadline: %v", err)
		return
	}
	_, err = remoteConn.Read(data)
	if err != nil {
		klog.V(2).Infof("Fail to read from remote %s: %s", remoteConn.RemoteAddr(), err)
		return
	}

	// it must answer with the origin the DNS server used to cache
	// and destination the same original address
	klog.V(4).Infof("dialing from %s to %s", dstAddr.String(), origAddr.String())
	bypassFreebindDialer := &net.Dialer{
		LocalAddr: dstAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Mark connections so thet are not processed by the netfilter TPROXY rules
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, tproxyNAT64BypassMark); err != nil {
					klog.Infof("setting SO_MARK bypass: %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
					klog.Infof("setting IP_TRANSPARENT: %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					klog.Infof("setting SO_REUSEPORT: %v", err)
				}
			})
		},
	}
	conn, err := bypassFreebindDialer.Dial("udp", origAddr.String())
	if err != nil {
		klog.Infof("can not dial to %s : %v", origAddr.String(), err)
		return
	}
	_, err = conn.Write(data)
	if err != nil {
		klog.Infof("error writing UDP NAT64 answer: %v", err)
	}
}

// https://github.com/KatelynHaworth/go-tproxy/blob/ef7efd7f24ed7e9bf8f479c890c81ce7db27000e/tproxy_udp.go#L40C1-L97C1
// ReadFromUDP reads a UDP packet from c, copying the payload into b.
// It returns the number of bytes copied into b and the return address
// that was on the packet.
//
// Out-of-band data is also read in so that the original destination
// address can be identified and parsed.
func ReadFromUDP(conn *net.UDPConn, b []byte) (int, *net.UDPAddr, *net.UDPAddr, error) {
	oob := make([]byte, 1024)
	n, oobn, _, addr, err := conn.ReadMsgUDP(b, oob)
	if err != nil {
		return 0, nil, nil, err
	}

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parsing socket control message: %s", err)
	}

	var dstAddr *net.UDPAddr
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR {
			pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&m.Data[0]))
			p := (*[2]byte)(unsafe.Pointer(&pp.Port))
			dstAddr = &net.UDPAddr{
				IP:   net.IP(pp.Addr[:]),
				Port: int(p[0])<<8 + int(p[1]),
				Zone: strconv.Itoa(int(pp.Scope_id)),
			}
			break
		}
	}

	if dstAddr == nil {
		return 0, nil, nil, fmt.Errorf("unable to obtain original destination oob: %+v", oob)
	}

	return n, addr, dstAddr, nil
}
