// Copyright 2025 Antonio Ojea
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// FirstAndNextSubnetAddr takes the beginning address of an entire network in CIDR
// notation (e.g. 192.168.1.0/24) and returns the first addresses
// within the network and the first address of the next network (e.g. first 192.168.1.0, next 192.168.2.0).
//
// Note: nftables needs half-open intervals [firstIP, lastIP) for prefixes
// e.g. 10.0.0.0/24 becomes [10.0.0.0, 10.0.1.0), 10.1.1.1/32 becomes [10.1.1.1, 10.1.1.2) etc
func FirstAndNextSubnetAddr(subnet netip.Prefix) (first, next netip.Addr, err error) {
	first = subnet.Masked().Addr()

	broadcast, err := broadcastAddress(subnet)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}

	return first, broadcast.Next(), nil
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
