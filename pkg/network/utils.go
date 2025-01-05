package network

import (
	"bytes"
	"encoding/binary"
	"net"
)

// From https://github.com/google/nftables/blob/e99829fb4f26d75fdd0cfce8ba4632744e72c2bc/util.go#L49C1-L89C2
// NetFirstAndLastIP takes the beginning address of an entire network in CIDR
// notation (e.g. 192.168.1.0/24) and returns the first and last IP addresses
// within the network (e.g. first 192.168.1.0, last 192.168.1.255).
//
// Note that these are the first and last IP addresses, not the first and last
// *usable* IP addresses (which would be 192.168.1.1 and 192.168.1.254,
// respectively, for 192.168.1.0/24).
func NetFirstAndLastIP(networkCIDR string) (first, last net.IP, err error) {
	_, subnet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, nil, err
	}

	first = make(net.IP, len(subnet.IP))
	last = make(net.IP, len(subnet.IP))

	switch len(subnet.IP) {
	case net.IPv4len:
		mask := binary.BigEndian.Uint32(subnet.Mask)
		ip := binary.BigEndian.Uint32(subnet.IP)
		// To achieve the first IP address, we need to AND the IP with the mask.
		// The AND operation will set all bits in the host part to 0.
		binary.BigEndian.PutUint32(first, ip&mask)
		// To achieve the last IP address, we need to OR the IP network with the inverted mask.
		// The AND between the IP and the mask will set all bits in the host part to 0, keeping the network part.
		// The XOR between the mask and 0xffffffff will set all bits in the host part to 1, and the network part to 0.
		// The OR operation will keep the host part unchanged, and sets the host part to all 1.
		binary.BigEndian.PutUint32(last, (ip&mask)|(mask^0xffffffff))
	case net.IPv6len:
		mask1 := binary.BigEndian.Uint64(subnet.Mask[:8])
		mask2 := binary.BigEndian.Uint64(subnet.Mask[8:])
		ip1 := binary.BigEndian.Uint64(subnet.IP[:8])
		ip2 := binary.BigEndian.Uint64(subnet.IP[8:])
		binary.BigEndian.PutUint64(first[:8], ip1&mask1)
		binary.BigEndian.PutUint64(first[8:], ip2&mask2)
		binary.BigEndian.PutUint64(last[:8], (ip1&mask1)|(mask1^0xffffffffffffffff))
		binary.BigEndian.PutUint64(last[8:], (ip2&mask2)|(mask2^0xffffffffffffffff))
	}

	return first, last, nil
}

func EncodeWithAlignment(data any) []byte {
	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, data)
	if err != nil {
		panic(err)
	}

	// Calculate padding
	padding := (4 - buf.Len()%4) % 4
	for i := 0; i < padding; i++ {
		buf.WriteByte(0x00)
	}

	return buf.Bytes()
}
