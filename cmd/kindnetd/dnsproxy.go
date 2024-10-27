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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

// reference https://coredns.io/plugins/cache/
const (
	// same as LocalNodeDNS
	// https://github.com/kubernetes/dns/blob/c0fa2d1128d42c9b13e08a6a7e3ee8c635b9acd5/cmd/node-cache/Corefile#L3
	expireTimeout = 30 * time.Second
	// It was 512 byRFC1035 for UDP until EDNS, but large packets can be fragmented ...
	// it seems bind uses 1232 as maximum size
	// https://kb.isc.org/docs/behavior-dig-versions-edns-bufsize
	maxDNSSize = 1232
)

type ipEntry struct {
	ts  time.Time
	ips []net.IP
}

type ipCache struct {
	mu             sync.RWMutex
	clock          clock.Clock
	cacheV4Address map[string]ipEntry
	cacheV6Address map[string]ipEntry
}

func (i *ipCache) add(network string, host string, ips []net.IP) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock.Now()
	entry := ipEntry{
		ts:  now,
		ips: ips,
	}
	if network == "ip6" {
		i.cacheV6Address[host] = entry
		dnsCacheSize.WithLabelValues("ip6").Set(float64(len(i.cacheV6Address)))
	}
	if network == "ip4" {
		i.cacheV4Address[host] = entry
		dnsCacheSize.WithLabelValues("ip4").Set(float64(len(i.cacheV4Address)))
	}
}

func (i *ipCache) get(network string, host string) ([]net.IP, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	var entry ipEntry
	var ok bool

	if network == "ip6" {
		entry, ok = i.cacheV6Address[host]
	}
	if network == "ip4" {
		entry, ok = i.cacheV4Address[host]
	}
	if !ok {
		return nil, false
	}
	// check if the entry is still valid
	if entry.ts.Add(expireTimeout).Before(i.clock.Now()) {
		i.delete(network, host)
		return nil, false
	}
	return entry.ips, true
}

func (i *ipCache) delete(network string, host string) {
	if network == "ip6" {
		delete(i.cacheV6Address, host)
		dnsCacheSize.WithLabelValues("ip6").Set(float64(len(i.cacheV6Address)))
	}
	if network == "ip4" {
		delete(i.cacheV4Address, host)
		dnsCacheSize.WithLabelValues("ip4").Set(float64(len(i.cacheV4Address)))
	}
}

func (i *ipCache) gc() {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock.Now()
	for host, entry := range i.cacheV4Address {
		// check if the entry is still valid
		if entry.ts.Add(expireTimeout).Before(now) {
			i.delete("ip4", host)
		}
	}
	for host, entry := range i.cacheV6Address {
		// check if the entry is still valid
		if entry.ts.Add(expireTimeout).Before(now) {
			i.delete("ip6", host)
		}
	}
	dnsCacheSize.WithLabelValues("ip4").Set(float64(len(i.cacheV4Address)))
	dnsCacheSize.WithLabelValues("ip6").Set(float64(len(i.cacheV6Address)))
}

func newIPCache() *ipCache {
	return &ipCache{
		cacheV4Address: map[string]ipEntry{},
		cacheV6Address: map[string]ipEntry{},
		clock:          clock.RealClock{},
	}
}

type DNSProxy struct {
	nameServer string
	resolver   *net.Resolver
	connCh     chan net.Conn // share the connections to the upstream nameserver
	closeCh    chan struct{}
	localAddr  string
	cache      *ipCache
}

func NewDNSProxy(nameServer string) *DNSProxy {
	return &DNSProxy{
		nameServer: nameServer,
		closeCh:    make(chan struct{}),
		connCh:     make(chan net.Conn),
		cache:      newIPCache(),
	}
}

func (d *DNSProxy) GetLocalAddr() string {
	return d.localAddr
}

func (d *DNSProxy) ReadyChannel() chan struct{} {
	return d.closeCh
}

func (d *DNSProxy) Start() error {
	dialer := net.Dialer{
		KeepAlive: 30 * time.Second,
		Timeout:   5 * time.Second,
	}

	// create a connection with the upstream DNS server
	dnsTCPConn, err := dialer.Dial("tcp", net.JoinHostPort(d.nameServer, "53"))
	if err != nil {
		return err
	}
	defer dnsTCPConn.Close()
	go func() {
		klog.V(2).Infof("connected to %s", net.JoinHostPort(d.nameServer, "53"))
		// return the connection to the channel
		d.connCh <- dnsTCPConn
	}()

	d.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case conn, ok := <-d.connCh:
				if ok {
					return conn, nil
				}
				return nil, fmt.Errorf("connection channel closed")
			case <-ctx.Done():
				d.Stop()
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				d.Stop()
				return nil, fmt.Errorf("error waiting for available connection")
			}
		},
	}

	// start listener
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
				klog.Fatalf("error setting IP_TRANSPARENT bypass: %v", err)
			}
		})
	},
	}

	conn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:9785")
	if err != nil {
		return err
	}
	defer conn.Close()

	d.localAddr = conn.LocalAddr().String()
	klog.V(2).Infof("listening on %s", d.localAddr)

	// proxy the DNS requests
	go func() {
		for {
			// It was 512 until EDNS but large packets can be fragmented ...
			// https://kb.isc.org/docs/behavior-dig-versions-edns-bufsize
			buf := make([]byte, maxDNSSize)
			n, addr, err := conn.ReadFrom(buf)
			if errors.Is(err, net.ErrClosed) {
				klog.Infof("exiting, UDP connection closed: %v", err)
				d.Stop()
				return
			}
			if err != nil {
				klog.Infof("error on UDP connection: %v", err)
				continue
			}
			klog.V(7).Infof("UDP connection from %s", addr.String())
			go d.serveDNS(addr, buf[:n])
		}
	}()

	// purge the cache periodically
	go func() {
		ticker := time.NewTicker(expireTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.cache.gc()
			case <-d.closeCh:
				return
			}
		}
	}()

	<-d.closeCh
	return nil
}

func (d *DNSProxy) Stop() {
	select {
	case <-d.closeCh:
	default:
		close(d.closeCh)
	}
}

// serveDNS(addr net.Addr, data []byte) {
func (d *DNSProxy) serveDNS(addr net.Addr, data []byte) {
	// it must answer with the origin the DNS server used to cache
	// and destination the same original address
	klog.V(4).Infof("dialing from %s:%d to %s", d.nameServer, 53, addr.String())
	bypassFreebindDialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{IP: net.ParseIP(d.nameServer), Port: 53},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Mark connections so thet are not processed by the netfilter TPROXY rules
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tproxyBypassMark); err != nil {
					klog.Infof("setting SO_MARK bypass: %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
					klog.Infof("setting IP_TRANSPARENT: %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					klog.Infof("setting SO_REUSEPORT: %v", err)
				}
			})
		},
	}
	conn, err := bypassFreebindDialer.Dial("udp", addr.String())
	if err != nil {
		klog.Infof("can not dial to %s : %v", addr.String(), err)
		return
	}
	_, err = conn.Write(d.dnsPacketRoundTrip(data))
	if err != nil {
		klog.Infof("error writing DNS answer: %v", err)
	}
}

func (d *DNSProxy) dnsPacketRoundTrip(b []byte) []byte {
	var p dnsmessage.Parser
	klog.V(7).Info("starting parsing packet")
	hdr, err := p.Start(b)
	if err != nil {
		return dnsErrorMessage(hdr.ID, dnsmessage.RCodeFormatError, dnsmessage.Question{})
	}
	if len(b) > maxDNSSize {
		return dnsErrorMessage(hdr.ID, dnsmessage.RCodeFormatError, dnsmessage.Question{})
	}

	questions, err := p.AllQuestions()
	if err != nil {
		return dnsErrorMessage(hdr.ID, dnsmessage.RCodeFormatError, dnsmessage.Question{})
	}
	if len(questions) == 0 {
		return dnsErrorMessage(hdr.ID, dnsmessage.RCodeFormatError, dnsmessage.Question{})
	}
	// it is supported but not wildly implemented, at least not in golang stdlib
	if len(questions) > 1 {
		return dnsErrorMessage(hdr.ID, dnsmessage.RCodeNotImplemented, questions...)
	}
	question := questions[0]
	answer, delegate := d.processDNSRequest(hdr.ID, question)
	// pass it through
	if delegate {
		klog.V(7).Info("can not process request, delegating ...")
		answer, err = d.passThrough(b)
		if err != nil {
			return dnsErrorMessage(hdr.ID, dnsmessage.RCodeServerFailure, question)
		}
		// Return a truncated packet if the answer is too big
		if len(answer) > maxDNSSize {
			answer = dnsTruncatedMessage(hdr.ID, question)
		}
	}
	klog.V(7).Info("answer correct")
	return answer
}

func (d *DNSProxy) passThrough(b []byte) ([]byte, error) {
	var err error
	buf := make([]byte, maxDNSSize)
	// get connection from the pool
	conn, ok := <-d.connCh
	if !ok {
		return buf, fmt.Errorf("connection channel closed")
	}
	// return the connection to the channel or stop the proxy
	defer func() {
		if err != nil {
			d.Stop()
		} else {
			d.connCh <- conn
		}
	}()

	// As per RFC 1035, TCP DNS messages are preceded by a 16 bit size, skip first 2 bytes.
	hdrLen := make([]byte, 2)
	binary.BigEndian.PutUint16(hdrLen, uint16(len(b)))
	_, err = conn.Write(append(hdrLen, b...))
	if err != nil {
		return buf, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second)) // golint: errcheck
	var n int
	n, err = conn.Read(buf)
	if err != nil {
		klog.Infof("error on upstream connection: %v", err)
		return buf, err
	}
	// skip first two bytes with the TCP DNS size
	return buf[2:n], nil
}

// dnsErrorMessage return an encoded dns error message
func dnsErrorMessage(id uint16, rcode dnsmessage.RCode, q ...dnsmessage.Question) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
			RCode:         rcode,
		},
		Questions: q,
	}
	buf, err := msg.Pack()
	if err != nil {
		klog.Errorf("SHOULD NOT HAPPEN: can not create dnsErrorMessage: %v", err)
	}
	return buf
}

func dnsTruncatedMessage(id uint16, q ...dnsmessage.Question) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
			Truncated:     true,
		},
		Questions: q,
	}
	buf, err := msg.Pack()
	if err != nil {
		klog.Errorf("SHOULD NOT HAPPEN: can not create dnsTruncatedMessage: %v", err)
	}
	return buf
}

// processDNSRequest implements dnsHandlerFunc so it can be used in a DNSCache
// transforming a DNS request to the corresponding Golang Lookup functions.
// If is not able to process the request it delegates to the caller the request.
func (d *DNSProxy) processDNSRequest(id uint16, q dnsmessage.Question) ([]byte, bool) {
	// DNS packet length is encoded in 2 bytes
	buf := []byte{}
	answer := dnsmessage.NewBuilder(buf,
		dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
		})
	answer.EnableCompression()
	err := answer.StartQuestions()
	if err != nil {
		return dnsErrorMessage(id, dnsmessage.RCodeServerFailure, q), false
	}
	answer.Question(q) // nolint: errcheck
	err = answer.StartAnswers()
	if err != nil {
		return dnsErrorMessage(id, dnsmessage.RCodeServerFailure, q), false
	}
	switch q.Type {
	case dnsmessage.TypeA:
		klog.V(7).Infof("DNS A request for %s", q.Name.String())
		addrs, err := d.lookupIP(context.Background(), "ip4", q.Name.String())
		if err != nil {
			klog.V(2).Infof("DNS A request lookupIP for %s error: %v", q.Name.String(), err)
			return nil, true
		}
		if len(addrs) == 0 {
			return dnsErrorMessage(id, dnsmessage.RCodeNameError, q), false
		}
		klog.V(7).Infof("DNS A request for %s ips: %v", q.Name.String(), addrs)
		for _, ip := range addrs {
			a := ip.To4()
			if a == nil {
				continue
			}
			err = answer.AResource(
				dnsmessage.ResourceHeader{
					Name:  q.Name,
					Class: q.Class,
					TTL:   uint32(expireTimeout.Seconds()),
				},
				dnsmessage.AResource{
					A: [4]byte{a[0], a[1], a[2], a[3]},
				},
			)
			if err != nil {
				klog.V(2).Infof("DNS A request for %s error: %v", q.Name.String(), err)
				return nil, true
			}
		}
	case dnsmessage.TypeAAAA:
		klog.V(7).Infof("DNS AAAA request for %s", q.Name.String())
		addrs, err := d.lookupIP(context.Background(), "ip6", q.Name.String())
		if err != nil {
			klog.V(2).Infof("DNS AAAA request lookupIP for %s error: %v", q.Name.String(), err)
			return nil, true
		}
		if len(addrs) == 0 {
			return dnsErrorMessage(id, dnsmessage.RCodeNameError, q), false
		}
		klog.V(7).Infof("DNS AAAA request for %s ips: %v", q.Name.String(), addrs)
		for _, ip := range addrs {
			if ip.To16() == nil || ip.To4() != nil {
				continue
			}
			var aaaa [16]byte
			copy(aaaa[:], ip.To16())
			err = answer.AAAAResource(
				dnsmessage.ResourceHeader{
					Name:  q.Name,
					Class: q.Class,
					TTL:   uint32(expireTimeout.Seconds()),
				},
				dnsmessage.AAAAResource{
					AAAA: aaaa,
				},
			)
			if err != nil {
				klog.V(2).Infof("DNS AAAA request for %s error: %v", q.Name.String(), err)
				return nil, true
			}
		}
	case dnsmessage.TypePTR:
		klog.V(7).Infof("DNS PTR request for %s", q.Name.String())
		return nil, true
	case dnsmessage.TypeSRV:
		return nil, true
	case dnsmessage.TypeNS:
		return nil, true
	case dnsmessage.TypeCNAME:
		return nil, true
	case dnsmessage.TypeSOA:
		return nil, true
	case dnsmessage.TypeMX:
		return nil, true
	case dnsmessage.TypeTXT:
		return nil, true
	default:
		return nil, true
	}
	buf, err = answer.Finish()
	if err != nil {
		return dnsErrorMessage(id, dnsmessage.RCodeServerFailure, q), false
	}
	return buf, false
}

func (d *DNSProxy) lookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ips, ok := d.cache.get(network, host)
	if ok {
		klog.V(4).Infof("Cached entries for %s %s : %v", network, host, ips)
		return ips, nil
	}
	ips, err := d.resolver.LookupIP(ctx, network, host)
	if err != nil {
		// cache empty answers
		if e, ok := err.(*net.DNSError); !ok || !e.IsNotFound {
			return nil, err
		}
	}
	d.cache.add(network, host, ips)
	klog.V(4).Infof("Caching new entries for %s %s : %v", network, host, ips)
	return ips, nil
}
