// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestAllocator(t *testing.T) {
	a, err := NewAllocator(netip.MustParsePrefix("192.168.1.0/25"), 10)
	if err != nil {
		t.Fatal(err)
	}
	// can not allocate on the reserved space
	err = a.AllocateAddress(netip.MustParseAddr("192.168.1.2"))
	if err == nil {
		t.Fatal("can not alllocate on the reserved space")
	}

	allocatable := a.size - 10 - 1
	var i uint64
	for i = 0; i < allocatable; i++ {
		_, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
	}
	// it should fail to allocate since it is full
	ip, err := a.Allocate()
	if err == nil {
		t.Fatalf("unexpected success %s", ip.String())
	}

	// release and allocate manually
	a.Release(netip.MustParseAddr("192.168.1.33"))
	err = a.AllocateAddress(netip.MustParseAddr("192.168.1.33"))
	if err != nil {
		t.Fatal(err)
	}

	// it should fail to allocate since it is full
	ip, err = a.Allocate()
	if err == nil {
		t.Fatalf("unexpected success %s", ip.String())
	}
}

func TestAllocatorV6(t *testing.T) {
	a, err := NewAllocator(netip.MustParsePrefix("2001:db8::/64"), 10)
	if err != nil {
		t.Fatal(err)
	}
	// can not allocate on the reserved space
	err = a.AllocateAddress(netip.MustParseAddr("2001:db8::2"))
	if err == nil {
		t.Fatal("can not alllocate on the reserved space")
	}

	// let's try some allocations
	var i uint64
	for i = 0; i < 100; i++ {
		_, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
	}
	// release and allocate manually
	a.Release(netip.MustParseAddr("2001:db8::aa"))
	err = a.AllocateAddress(netip.MustParseAddr("2001:db8::aa"))
	if err != nil {
		t.Fatal(err)
	}

	// it should fail to allocate since it is alreadya allocated
	err = a.AllocateAddress(netip.MustParseAddr("2001:db8::aa"))
	if err == nil {
		t.Fatalf("unexpected success for IP 2001:db8::aa")
	}

}

func Test_broadcastAddress(t *testing.T) {
	tests := []struct {
		name   string
		subnet netip.Prefix
		want   netip.Addr
	}{
		{
			name:   "ipv4",
			subnet: netip.MustParsePrefix("192.168.0.0/24"),
			want:   netip.MustParseAddr("192.168.0.255"),
		},
		{
			name:   "ipv4 no nibble boundary",
			subnet: netip.MustParsePrefix("10.0.0.0/12"),
			want:   netip.MustParseAddr("10.15.255.255"),
		},
		{
			name:   "ipv6",
			subnet: netip.MustParsePrefix("fd00:1:2:3::/64"),
			want:   netip.MustParseAddr("fd00:1:2:3:FFFF:FFFF:FFFF:FFFF"),
		},
		{
			name:   "ipv6 00fc::/112",
			subnet: netip.MustParsePrefix("00fc::/112"),
			want:   netip.MustParseAddr("fc::ffff"),
		},
		{
			name:   "ipv6 fc00::/112",
			subnet: netip.MustParsePrefix("fc00::/112"),
			want:   netip.MustParseAddr("fc00::ffff"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := broadcastAddress(tt.subnet); !reflect.DeepEqual(got, tt.want) || err != nil {
				t.Errorf("broadcastAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_addOffsetAddress(t *testing.T) {
	tests := []struct {
		name    string
		address netip.Addr
		offset  uint64
		want    netip.Addr
	}{
		{
			name:    "IPv4 offset 0",
			address: netip.MustParseAddr("192.168.0.0"),
			offset:  0,
			want:    netip.MustParseAddr("192.168.0.0"),
		},
		{
			name:    "IPv4 offset 0 not nibble boundary",
			address: netip.MustParseAddr("192.168.0.11"),
			offset:  0,
			want:    netip.MustParseAddr("192.168.0.11"),
		},
		{
			name:    "IPv4 offset 1",
			address: netip.MustParseAddr("192.168.0.0"),
			offset:  1,
			want:    netip.MustParseAddr("192.168.0.1"),
		},
		{
			name:    "IPv4 offset 1 not nibble boundary",
			address: netip.MustParseAddr("192.168.0.11"),
			offset:  1,
			want:    netip.MustParseAddr("192.168.0.12"),
		},
		{
			name:    "IPv6 offset 1",
			address: netip.MustParseAddr("fd00:1:2:3::"),
			offset:  1,
			want:    netip.MustParseAddr("fd00:1:2:3::1"),
		},
		{
			name:    "IPv6 offset 1 not nibble boundary",
			address: netip.MustParseAddr("fd00:1:2:3::a"),
			offset:  1,
			want:    netip.MustParseAddr("fd00:1:2:3::b"),
		},
		{
			name:    "IPv4 offset last",
			address: netip.MustParseAddr("192.168.0.0"),
			offset:  255,
			want:    netip.MustParseAddr("192.168.0.255"),
		},
		{
			name:    "IPv6 offset last",
			address: netip.MustParseAddr("fd00:1:2:3::"),
			offset:  0x7FFFFFFFFFFFFFFF,
			want:    netip.MustParseAddr("fd00:1:2:3:7FFF:FFFF:FFFF:FFFF"),
		},
		{
			name:    "IPv4 offset middle",
			address: netip.MustParseAddr("192.168.0.0"),
			offset:  128,
			want:    netip.MustParseAddr("192.168.0.128"),
		},
		{
			name:    "IPv4 with leading zeros",
			address: netip.MustParseAddr("0.0.1.8"),
			offset:  138,
			want:    netip.MustParseAddr("0.0.1.146"),
		},
		{
			name:    "IPv6 with leading zeros",
			address: netip.MustParseAddr("00fc::1"),
			offset:  255,
			want:    netip.MustParseAddr("fc::100"),
		},
		{
			name:    "IPv6 offset 255",
			address: netip.MustParseAddr("2001:db8:1::101"),
			offset:  255,
			want:    netip.MustParseAddr("2001:db8:1::200"),
		},
		{
			name:    "IPv6 offset 1025",
			address: netip.MustParseAddr("fd00:1:2:3::"),
			offset:  1025,
			want:    netip.MustParseAddr("fd00:1:2:3::401"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := addOffsetAddress(tt.address, tt.offset)
			if !reflect.DeepEqual(got, tt.want) || err != nil {
				t.Errorf("offsetAddress() = %v, want %v", got, tt.want)
			}
			// double check to avoid mistakes on the hardcoded values
			// avoid large numbers or it will timeout the test
			if tt.offset < 2048 {
				want := tt.address
				var i uint64
				for i = 0; i < tt.offset; i++ {
					want = want.Next()
				}
				if !reflect.DeepEqual(got, tt.want) || err != nil {
					t.Errorf("offsetAddress() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
