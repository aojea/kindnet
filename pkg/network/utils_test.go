// Copyright 2025 Antonio Ojea

package network

import (
	"net/netip"
	"testing"
)

func TestFirstAndNextSubnetAddr(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		name        string
		networkCIDR string
		wantFirst   string
		wantNext    string
	}{
		{
			name:        "ipv4",
			networkCIDR: "10.0.0.0/24",
			wantFirst:   "10.0.0.0",
			wantNext:    "10.0.1.0",
		},
		{
			name:        "ipv4 large",
			networkCIDR: "10.0.0.0/8",
			wantFirst:   "10.0.0.0",
			wantNext:    "11.0.0.0",
		},
		{
			name:        "ipv6",
			networkCIDR: "fd00:1:2:3::/64",
			wantFirst:   "fd00:1:2:3::",
			wantNext:    "fd00:1:2:4::",
		},
		{
			name:        "ipv4",
			networkCIDR: "10.0.0.0/13",
			wantFirst:   "10.0.0.0",
			wantNext:    "10.8.0.0",
		},
		{
			name:        "ipv6",
			networkCIDR: "2001:db8:85a3::8a2e:370:7334/74",
			wantFirst:   "2001:db8:85a3::",
			wantNext:    "2001:db8:85a3:0:40::",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFirst, gotNext, err := FirstAndNextSubnetAddr(netip.MustParsePrefix(tt.networkCIDR))
			if err != nil {
				t.Errorf("FirstAndNextSubnetAddr() error = %v", err)
				return
			}
			if gotFirst.String() != tt.wantFirst {
				t.Errorf("FirstAndNextSubnetAddr() gotFirst = %v, want %v", gotFirst, tt.wantFirst)
			}
			if gotNext.String() != tt.wantNext {
				t.Errorf("FirstAndNextSubnetAddr() gotNext = %v, want %v", gotNext, tt.wantNext)
			}
		})
	}
}
