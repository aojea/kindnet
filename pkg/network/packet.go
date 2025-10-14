
package network

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"syscall"

	v1 "k8s.io/api/core/v1"
)

type Packet struct {
	ID      uint32
	Family  v1.IPFamily
	SrcIP   net.IP
	DstIP   net.IP
	Proto   v1.Protocol
	SrcPort int
	DstPort int
	Payload []byte
}

var ErrorTooShort = fmt.Errorf("packet too short")
var ErrorCorrupted = fmt.Errorf("packet corrupted")

func (p Packet) String() string {
	return fmt.Sprintf("[%d] %s:%d %s:%d %s\n%s", p.ID, p.SrcIP.String(), p.SrcPort, p.DstIP.String(), p.DstPort, p.Proto, hex.Dump(p.Payload))
}

// This function is used for JSON output (interface logr.Marshaler)
func (p Packet) MarshalLog() any {
	return &struct {
		ID      uint32
		Family  v1.IPFamily
		SrcIP   net.IP
		DstIP   net.IP
		Proto   v1.Protocol
		SrcPort int
		DstPort int
	}{
		p.ID,
		p.Family,
		p.SrcIP,
		p.DstIP,
		p.Proto,
		p.SrcPort,
		p.DstPort,
	}
}

// https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Packet_structure
// https://en.wikipedia.org/wiki/IPv6_packet
// https://github.com/golang/net/blob/master/ipv4/header.go
func ParsePacket(b []byte) (Packet, error) {
	t := Packet{}
	if len(b) < 20 {
		// 20 is the minimum length of an IPv4 header (IPv6 is 40)
		return t, ErrorTooShort
	}
	version := int(b[0] >> 4)
	// initialize variables
	var protocol, l4offset, nxtHeader int
	switch version {
	case 4:
		t.Family = v1.IPv4Protocol
		hdrlen := int(b[0]&0x0f) * 4 // (header length in 32-bit words)
		if hdrlen < 20 {
			return t, ErrorCorrupted
		}
		l4offset = hdrlen
		if l4offset >= len(b) {
			return t, ErrorTooShort
		}
		t.SrcIP = net.IPv4(b[12], b[13], b[14], b[15])
		t.DstIP = net.IPv4(b[16], b[17], b[18], b[19])
		protocol = int(b[9])
		// IPv4 fragments:
		// Since the conntracker is always used in K8s, IPv4 fragments
		// will never be passed via the nfqueue. Packets are
		// re-assembled by the kernel. Please see:
		// https://unix.stackexchange.com/questions/650790/unwanted-defragmentation-of-forwarded-ipv4-packets
	case 6:
		t.Family = v1.IPv6Protocol
		if len(b) < 48 {
			// 40 is the minimum length of an IPv6 header, and 8 is
			// the minimum lenght of an extension or L4 header
			return t, ErrorTooShort
		}
		t.SrcIP = make(net.IP, net.IPv6len)
		copy(t.SrcIP, b[8:24])
		t.DstIP = make(net.IP, net.IPv6len)
		copy(t.DstIP, b[24:40])
		// Handle extension headers.
		nxtHeader = int(b[6])
		l4offset = 40
		for nxtHeader == syscall.IPPROTO_DSTOPTS || nxtHeader == syscall.IPPROTO_HOPOPTS || nxtHeader == syscall.IPPROTO_ROUTING {
			// These headers have a lenght in 8-octet units, not
			// including the first 8 octets
			nxtHeader = int(b[l4offset])
			l4offset += (8 + int(b[l4offset+1])*8)
			// Now l4offset points to either another extension header,
			// or an L4 header. So we must have at least 8 byte data
			// after this (minimum extension header size)
			if (l4offset + 8) >= len(b) {
				return t, ErrorTooShort
			}
		}
		if nxtHeader == syscall.IPPROTO_FRAGMENT {
			// Only the first fragment has the L4 header
			fragOffset := int(binary.BigEndian.Uint16(b[l4offset+2 : l4offset+4]))
			if fragOffset&0xfff8 == 0 {
				nxtHeader = int(b[l4offset])
				l4offset += 8
				// Here it's assumed that the fragment is the last
				// extension header before the L4 header. But more
				// IPPROTO_DSTOPTS are allowed by the recommended order.
				// TODO: handle extra IPPROTO_DSTOPTS.
			} else {
				// If this is NOT the first fragment, we have no L4
				// header and the payload begins after this
				// header. Return a packet with t.proto unset
				return t, nil
			}
		}
		protocol = nxtHeader
	default:
		return t, fmt.Errorf("unknown version %d", version)
	}

	// The payload follows immediately after the L4 header, pointed
	// out by 'l4offset'. So payloadOffset will be (l4offset + the
	// L4header len) The L4header len is 8 byte for udp and sctp, but
	// may vary for tcp (the dataOffset)
	var payloadOffset int
	switch protocol {
	case syscall.IPPROTO_TCP:
		t.Proto = v1.ProtocolTCP
		dataOffset := int(b[l4offset+12]>>4) * 4
		if dataOffset < 20 {
			return t, ErrorCorrupted
		}
		payloadOffset = l4offset + dataOffset
	case syscall.IPPROTO_UDP:
		t.Proto = v1.ProtocolUDP
		payloadOffset = l4offset + 8
	case syscall.IPPROTO_SCTP:
		t.Proto = v1.ProtocolSCTP
		payloadOffset = l4offset + 8
	default:
		// Return a packet with t.proto unset, and ports 0
		return t, nil

	}
	if payloadOffset > len(b) {
		// If the payloadOffset is beyond the packet size, we have an
		// incomplete L4 header
		return t, ErrorTooShort
	}
	t.SrcPort = int(binary.BigEndian.Uint16(b[l4offset : l4offset+2]))
	t.DstPort = int(binary.BigEndian.Uint16(b[l4offset+2 : l4offset+4]))

	// TODO allow to filter by the payload
	t.Payload = b[payloadOffset:]
	return t, nil
}
