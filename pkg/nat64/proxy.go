
package nat64

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/aojea/kindnet/pkg/network"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

const (
	tableName             = "kindnet-nat64"
	prefixNAT64           = "64:ff9b::/96"
	tproxyNAT64BypassMark = 14
	tproxyNAT64Mark       = 13
	tproxyNAT64Table      = 101
)

var (
	prefixNAT64bytes = []byte{0x0, 0x64, 0xff, 0x9b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
)

func NewNAT64Agent() (*NAT64Agent, error) {
	klog.V(2).Info("Initializing nftables")

	d := &NAT64Agent{
		interval: 5 * time.Minute,
	}

	return d, nil
}

// NAT64Agent caches all DNS traffic from Pods with network based on the PodCIDR of the node they are running.
// Cache logic is very specific to Kubernetes,
type NAT64Agent struct {
	interval time.Duration

	udpProxyPort int
	tcpProxyPort int
}

// Run syncs dns cache intercept rules
func (n *NAT64Agent) Run(ctx context.Context) error {
	registerMetrics()

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
	conn, err := udpLc.ListenPacket(context.Background(), "udp6", "[::1]:0")
	if err != nil {
		return err
	}
	defer conn.Close()

	klog.V(2).Infof("listening on UDP %s", conn.LocalAddr().String())
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	n.udpProxyPort = p

	go func() {
		for {
			buf := make([]byte, 9100)
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
			connectionsTotal.WithLabelValues("udp").Inc()
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

	klog.V(2).Infof("listening on TCP %s", tcpListener.Addr().String())
	_, port, err = net.SplitHostPort(tcpListener.Addr().String())
	if err != nil {
		return err
	}
	p, err = strconv.Atoi(port)
	if err != nil {
		return err
	}
	n.tcpProxyPort = p

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				klog.Fatalf("Unrecoverable error while accepting connection: %s", err)
				return
			}
			klog.V(7).Infof("TCP connection from %s", conn.RemoteAddr().String())
			connectionsTotal.WithLabelValues("tcp").Inc()
			go handleTCPConn(conn)
		}
	}()

	klog.Info("Syncing local route rules")
	err = n.syncLocalRoute()
	if err != nil {
		klog.Infof("error syncing local route: %v", err)
	}

	ticker := time.NewTicker(n.interval)
	defer ticker.Stop()
	errs := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := n.SyncRules(ctx); err != nil {
			errs++
			if errs > 3 {
				klog.Infof("can't synchronize rules after 3 attempts: %v", err)
				errs = 0
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}

func (n *NAT64Agent) syncLocalRoute() error {
	link, err := netlink.LinkByName("lo")
	if err != nil && !errors.Is(err, unix.EINTR) {
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
	klog.V(2).Info("Syncing kindnet-nat64 nftables rules")
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("portmap failure, can not start nftables:%v", err)
	}

	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   tableName,
	})
	nft.FlushTable(table)

	chain := nft.AddChain(&nftables.Chain{
		Name:    "prerouting",
		Table:   table,
		Type:    nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting,
		// before conntrack to avoid tproxied traffic to be natted
		// https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation
		// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityRaw - 10),
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: network.EncodeWithAlignment(byte(tproxyNAT64BypassMark))},
			&expr.Verdict{Kind: expr.VerdictReturn},
		},
	})

	// ip6 daddr 64:ff9b::/96 meta l4proto udp tproxy to [::1]:60693 meta mark set 0x0000000d notrack accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 12},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: prefixNAT64bytes},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Immediate{Register: 0x1, Data: net.IPv6loopback.To16()},
			&expr.Immediate{Register: 0x2, Data: binaryutil.BigEndian.PutUint16(uint16(n.udpProxyPort))},
			&expr.TProxy{Family: byte(nftables.TableFamilyIPv6), TableFamily: byte(nftables.TableFamilyIPv6), RegAddr: 1, RegPort: 2},
			&expr.Immediate{Register: 0x1, Data: network.EncodeWithAlignment(byte(tproxyNAT64Mark))},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
			&expr.Notrack{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// ip6 daddr 64:ff9b::/96 meta l4proto tcp tproxy to [::1]:45217 meta mark set 0x0000000d notrack accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: prefixNAT64bytes},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []uint8{unix.IPPROTO_TCP}},
			&expr.Immediate{Register: 0x1, Data: net.IPv6loopback.To16()},
			&expr.Immediate{Register: 0x2, Data: binaryutil.BigEndian.PutUint16(uint16(n.tcpProxyPort))},
			&expr.TProxy{Family: byte(nftables.TableFamilyIPv6), TableFamily: byte(nftables.TableFamilyIPv6), RegAddr: 1, RegPort: 2},
			&expr.Immediate{Register: 0x1, Data: network.EncodeWithAlignment(byte(tproxyNAT64Mark))},
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: true, Register: 0x1},
			&expr.Notrack{},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: 0x0, Register: 0x1, Data: network.EncodeWithAlignment(byte(tproxyNAT64Mark))},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})

	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create kindnet-fastpath table: %v", err)
	}
	return nil
}

func CleanRules() {
	nft, err := nftables.New()
	if err != nil {
		klog.Infof("nat64 cleanup failure, can not start nftables:%v", err)
		return
	}
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv6,
		Name:   tableName,
	})
	nft.DelTable(table)

	err = nft.Flush()
	if err != nil {
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
	err = remoteConn.SetReadDeadline(time.Now().Add(5 * time.Second)) // Add deadline to ensure it doesn't block forever
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
