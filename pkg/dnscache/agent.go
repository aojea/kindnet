
package dnscache

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/aojea/kindnet/pkg/network"
	"github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// reference https://coredns.io/plugins/cache/
const (
	tableName = "kindnet-dnscache"
	queueID   = 103
	// same as LocalNodeDNS
	// https://github.com/kubernetes/dns/blob/c0fa2d1128d42c9b13e08a6a7e3ee8c635b9acd5/cmd/node-cache/Corefile#L3
	expireTimeout = 30 * time.Second
	// It was 512 byRFC1035 for UDP until EDNS, but large packets can be fragmented ...
	// it seems bind uses 1232 as maximum size
	// https://kb.isc.org/docs/behavior-dig-versions-edns-bufsize
	maxDNSSize  = 1232
	KubeletPort = 10250
	noTrackMark = uint32(110)
)

// NewDNSCacheAgent caches all DNS traffic from Pods with network based on the PodCIDR of the node they are running.
// Cache logic is very specific to Kubernetes,
func NewDNSCacheAgent(nodeName string, nodeInformer coreinformers.NodeInformer) (*DNSCacheAgent, error) {
	d := &DNSCacheAgent{
		nodeName:    nodeName,
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		interval:    5 * time.Minute,
		cache:       newIPCache(),
		tcpPool:     NewPools(),
	}

	return d, nil
}

// DNSCacheAgent caches all DNS traffic from Pods with network based on the PodCIDR of the node they are running.
// Cache logic is very specific to Kubernetes,
type DNSCacheAgent struct {
	nodeName    string
	nodeLister  corelisters.NodeLister
	nodesSynced cache.InformerSynced
	interval    time.Duration

	podCIDRv4     string
	podCIDRv6     string
	nameServers   []string
	searches      []string
	clusterDomain string

	nfq *nfqueue.Nfqueue

	cache   *ipCache
	tcpPool *Pools
}

// Run syncs dns cache intercept rules
func (d *DNSCacheAgent) Run(ctx context.Context) error {
	if !cache.WaitForNamedCacheSync("kindnet-dnscache", ctx.Done(), d.nodesSynced) {
		return fmt.Errorf("error syncing cache")
	}
	logger := klog.FromContext(ctx)
	registerMetrics()

	klog.Info("Waiting for node parameters")
	err := wait.PollUntilContextCancel(ctx, 1*time.Second, true, func(context.Context) (bool, error) {
		node, err := d.nodeLister.Get(d.nodeName)
		if err != nil {
			return false, nil
		}
		podCIDRsv4, podCIDRsv6 := network.SplitCIDRslice(node.Spec.PodCIDRs)
		klog.V(7).Infof("Got %v and %v from node %s", podCIDRsv4, podCIDRsv6, node.Name)
		if len(podCIDRsv4) > 0 {
			d.podCIDRv4 = podCIDRsv4[0]
		}
		if len(podCIDRsv6) > 0 {
			d.podCIDRv6 = podCIDRsv6[0]
		}
		return true, nil
	})
	if err != nil {
		return fmt.Errorf("failed to get Node PodCIDRs: %w", err)
	}

	// kubelet config clusterDNS
	// clusterDNS is a list of IP addresses for the cluster DNS server.
	// If set, kubelet will configure all containers to use this for DNS resolution instead of the host's DNS servers.

	klog.Info("Configuring upstream DNS resolver")
	kubeletConfig, err := getKubeletConfigz(ctx, d.nodeName)
	if err != nil {
		klog.ErrorS(err, "Could not obtain local Kubelet config")
		return err
	}
	klog.InfoS("Obtained DNS config from kubelet", "nameservers", kubeletConfig.ClusterDNS, "search", kubeletConfig.ClusterDomain, "resolver", kubeletConfig.ResolverConfig)

	if len(kubeletConfig.ClusterDNS) > 0 {
		d.nameServers = kubeletConfig.ClusterDNS
	}

	d.clusterDomain = kubeletConfig.ClusterDomain
	resolvPath := "/etc/resolv.conf"
	if kubeletConfig.ResolverConfig != nil {
		resolvPath = *kubeletConfig.ResolverConfig
	}

	hostDNS, hostSearch, hostOptions, err := parseResolvConf(resolvPath)
	if err != nil {
		klog.ErrorS(err, "Could not parse resolv conf file", "path", resolvPath)
	} else {
		d.searches = hostSearch
		klog.Infof("Resolv.conf from %s: nameservers: %v search: %v options: %v", resolvPath, hostDNS, hostSearch, hostOptions)
	}

	// https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html
	// the kernel will not normalize offload packets,
	// i.e. your application will need to be able to handle packets larger than the mtu.
	// Normalization is expensive, so this flag should always be set.
	// This also solves a bug with SCTP
	// https://github.com/aojea/kube-netpol/issues/8
	// https://bugzilla.netfilter.org/show_bug.cgi?id=1742
	flags := uint32(nfqueue.NfQaCfgFlagGSO + nfqueue.NfQaCfgFlagFailOpen)

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(queueID),
		Flags:        flags,
		MaxPacketLen: maxDNSSize,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket, // headers
		WriteTimeout: 100 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		logger.Info("could not open nfqueue socket", "error", err)
		return err
	}
	defer nf.Close()

	d.nfq = nf

	// Parse the DNS request
	fn := func(a nfqueue.Attribute) int {
		// by default accept packets to no interrupt traffic
		verdict := nfqueue.NfAccept
		startTime := time.Now()
		logger.V(4).Info("Processing sync for packet", "id", *a.PacketID)

		packet, err := network.ParsePacket(*a.Payload)
		if err != nil {
			logger.Error(err, "Can not process packet, applying default policy", "id", *a.PacketID)
			err := d.nfq.SetVerdict(*a.PacketID, verdict)
			if err != nil {
				logger.Error(err, "Can not set verdict for packet", "id", *a.PacketID)
			}
			return 0
		}
		packet.ID = *a.PacketID
		logger.V(4).Info("Processing packet", "packet", packet)

		defer func() {
			processingTime := float64(time.Since(startTime).Microseconds())
			packetProcessingHist.WithLabelValues(string(packet.Family)).Observe(processingTime)
			packetProcessingSum.Observe(processingTime)
			verdictStr := verdictString(verdict)
			packetCounterVec.WithLabelValues(string(packet.Family), verdictStr).Inc()
			logger.V(4).Info("Finished syncing packet", "id", *a.PacketID, "duration", time.Since(startTime), "verdict", verdictStr)
		}()

		if d.handleDNSPacket(ctx, packet) {
			verdict = nfqueue.NfAccept
		} else {
			verdict = nfqueue.NfDrop
		}
		err = d.nfq.SetVerdict(*a.PacketID, verdict)
		if err != nil {
			logger.Error(err, "Can not set verdict for packet", "id", *a.PacketID)
		}
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		logger.Info("Could not receive message", "error", err)
		printNfnetlinkQueueStats()
		return 0
	})
	if err != nil {
		logger.Info("could not open nfqueue socket", "error", err)
		return err
	}

	errs := 0
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := d.SyncRules(ctx); err != nil {
			errs++
			if errs > 3 {
				klog.Infof("can't synchronize rules after 3 attempts: %v", err)
				errs = 0
			}
		}
		// garbage collect ip cache entries
		d.cache.gc()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}

func printNfnetlinkQueueStats() {
	const maxBufferSize = 1024 * 1024

	f, err := os.Open("/proc/net/netfilter/nfnetlink_queue")
	if err != nil {
		klog.Infof("can not get nfqueue stats: %v", err)
		return
	}
	defer f.Close()

	reader := io.LimitReader(f, maxBufferSize)

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 9 {
			klog.Infof("unexpected output, expected 9 fields: %v", fields)
			return
		}
		klog.Infof("nfqueue stats: queue_number: %s port_id: %s queue_total: %s copy_mode: %s copy_range: %s kernel_dropped: %s user_dropped: %s last_packet_id: %s", fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7])
	}

}

// SyncRules syncs ip masquerade rules
func (d *DNSCacheAgent) SyncRules(ctx context.Context) error {
	klog.FromContext(ctx).Info("Syncing nftables rules")
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("can not start nftables:%v", err)
	}
	// add + delete + add for flushing all the table
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}

	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	chain := nft.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting, // packets not generated on the hosts
		Priority: nftables.ChainPriorityRaw,    // just before conntrack
	})

	//  ip saddr pod-range udp dport 53 queue flags bypass to 103
	if len(d.podCIDRv4) > 0 {
		v4Set := &nftables.Set{
			Table:   table,
			Name:    "set-v4-nameservers",
			KeyType: nftables.TypeIPAddr,
		}

		var elementsV4 []nftables.SetElement
		for _, ip := range d.nameServers {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if addr.Is6() {
				continue
			}
			elementsV4 = append(elementsV4, nftables.SetElement{
				Key: addr.AsSlice(),
			})
		}
		if err := nft.AddSet(v4Set, elementsV4); err != nil {
			return fmt.Errorf("failed to add Set %s : %v", v4Set.Name, err)
		}

		_, srccidrmatch, err := net.ParseCIDR(d.podCIDRv4)
		if err != nil {
			klog.Infof("SHOULD NOT HAPPEN bad cidr%s", d.podCIDRv4)
		} else {
			nft.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV4}},
					&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
					&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 4, Mask: srccidrmatch.Mask, Xor: binaryutil.NativeEndian.PutUint32(0)},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: srccidrmatch.IP.To4()},
					&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
					&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: v4Set.Name},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
					&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.BigEndian.PutUint16(53)},
					&expr.Queue{Num: queueID, Flag: expr.QueueFlagBypass},
				},
			})
		}
	}

	if len(d.podCIDRv6) > 0 {
		v6Set := &nftables.Set{
			Table:   table,
			Name:    "set-v6-nameservers",
			KeyType: nftables.TypeIP6Addr,
		}

		var elementsV6 []nftables.SetElement
		for _, ip := range d.nameServers {
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if addr.Is4() {
				continue
			}
			elementsV6 = append(elementsV6, nftables.SetElement{
				Key: addr.AsSlice(),
			})
		}
		if err := nft.AddSet(v6Set, elementsV6); err != nil {
			return fmt.Errorf("failed to add Set %s : %v", v6Set.Name, err)
		}

		if err := nft.AddSet(v6Set, elementsV6); err != nil {
			return fmt.Errorf("failed to add Set %s : %v", v6Set.Name, err)
		}

		_, srccidrmatch, err := net.ParseCIDR(d.podCIDRv6)
		if err != nil {
			klog.Infof("SHOULD NOT HAPPEN bad cidr%s", d.podCIDRv6)
		} else {
			//  ip6 saddr pod-range udp dport 53 queue flags bypass to 103
			nft.AddRule(&nftables.Rule{
				Table: table,
				Chain: chain,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
					&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
					&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 16, Mask: srccidrmatch.Mask, Xor: make([]byte, 16)},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: srccidrmatch.IP.To16()},
					&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
					&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: v6Set.Name},
					&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
					&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.BigEndian.PutUint16(53)},
					&expr.Queue{Num: queueID, Flag: expr.QueueFlagBypass},
				},
			})
		}
	}

	// replies from the agent should not be tracked
	chainOutput := nft.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,  // packets not generated on the hosts
		Priority: nftables.ChainPriorityRaw, // just before conntrack
	})

	//  meta mark 0x00000079 udp sport 53 notrack
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOutput,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.NativeEndian.PutUint32(noTrackMark)},
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.BigEndian.PutUint16(53)},
			&expr.Notrack{},
		},
	})

	if err := nft.Flush(); err != nil {
		klog.Infof("error syncing nftables rules %v", err)
		return err
	}
	return nil
}

func CleanRules() {
	nft, err := nftables.New()
	if err != nil {
		klog.Errorf("can not start nftables:%v", err)
		return
	} // Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}

	nft.AddTable(table)
	nft.DelTable(table)

	if err := nft.Flush(); err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}

// 1. Check DNS cache
// 2. If not in cache, forward via TCP
// 3. Return true to keep processing in dataplane, false to drop it in the dataplane
// because it was already processed here.
func (d *DNSCacheAgent) handleDNSPacket(ctx context.Context, packet network.Packet) bool {
	// sanity check, the nftables rules should only queue UDP packets destined to port 53
	if packet.Proto != v1.ProtocolUDP || packet.DstPort != 53 {
		klog.Infof("SHOULD NOT HAPPEN expected udp dst port 53, got protocol %s dst port %d", packet.Proto, packet.DstPort)
		return true
	}

	if len(packet.Payload) > maxDNSSize {
		klog.InfoS("dns request size unsupported", "packet", packet, "maxSize", maxDNSSize)
		return true
	}

	klog.V(7).Info("starting parsing packet")
	var p dnsmessage.Parser
	hdr, err := p.Start(packet.Payload)
	if err != nil {
		klog.ErrorS(err, "can not parse DNS message", "packet", packet)
		return true
	}
	questions, err := p.AllQuestions()
	if err != nil {
		klog.ErrorS(err, "can not get DNS message questions", "packet", packet)
		return true
	}
	if len(questions) == 0 {
		klog.ErrorS(err, "DNS message does not have any question", "packet", packet, "header", hdr)
		return true
	}
	// it is supported but not wildly implemented, at least not in golang stdlib
	if len(questions) > 1 {
		klog.ErrorS(err, "DNS messages unsupported number of questions, only one supported", "packet", packet, "header", hdr)
		return true
	}
	q := questions[0]
	// data to build the response
	host := q.Name.String()
	var network string // ip4 or ip6
	var gotIPs []net.IP
	var udpResp []byte

	dnsRecordsTotal.WithLabelValues(q.Type.String()).Inc()

	// TODO process more records types
	switch q.Type {
	case dnsmessage.TypeA:
		network = "ip4"
	case dnsmessage.TypeAAAA:
		network = "ip6"
	case dnsmessage.TypePTR:
		return true
	case dnsmessage.TypeSRV:
		return true
	case dnsmessage.TypeNS:
		return true
	case dnsmessage.TypeCNAME:
		return true
	case dnsmessage.TypeSOA:
		return true
	case dnsmessage.TypeMX:
		return true
	case dnsmessage.TypeTXT:
		return true
	default:
		return true
	}

	ips, ok := d.cache.get(network, host)
	if ok {
		b, err := dnsBuildResponse(hdr.ID, q, ips)
		if err != nil {
			klog.ErrorS(err, "fail to build dns response", "header", hdr, "IPs", ips)
			return true
		}
		udpResp = b
		gotIPs = ips
	} else {
		// no cache entry found so we forward the request via tcp
		start := time.Now()
		pool := d.tcpPool.Get(net.JoinHostPort(packet.DstIP.String(), "53"))
		conn, err := pool.Get()
		if err != nil {
			klog.Error(err, "fail to get TCP connection from pool")
			return true
		}
		dnsRecordsForwardedTotal.WithLabelValues(q.Type.String()).Inc()
		ips, b, err := forwardDNSOverTCP(conn, hdr.ID, q)
		pool.Put(conn)
		if err != nil {
			klog.ErrorS(err, "fail to get dns response over TCP", "header", hdr)
			return true
		}
		dnsRecordsForwardeHist.WithLabelValues(q.Type.String()).Observe(float64(time.Since(start).Milliseconds()))
		udpResp = b
		gotIPs = ips
		d.cache.add(network, host, ips)
	}

	klog.V(4).Infof("host %s for network %s has IPs %v", host, network, gotIPs)
	err = dnsResponseRoundtrip(packet, udpResp)
	if err != nil {
		klog.ErrorS(err, "can not dial back the response")
		return true
	}
	return false
}

// verdictString converts nfqueue int verdicts to strings for metrics/logging
// it does not cover all of them because we only use a subset.
func verdictString(verdict int) string {
	switch verdict {
	case nfqueue.NfDrop:
		return "cached"
	case nfqueue.NfAccept:
		return "forwarded"
	default:
		return "unknown"
	}
}
