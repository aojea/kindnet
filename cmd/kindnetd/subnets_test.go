// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"
)

func Test_splitCIDRs(t *testing.T) {
	tests := []struct {
		name   string
		cidrs  string
		wantV4 []string
		wantV6 []string
	}{
		{
			name: "empty",
		},
		{
			name:   "ipv4",
			cidrs:  "192.168.0.0/24",
			wantV4: []string{"192.168.0.0/24"},
		},
		{
			name:   "ipv4s",
			cidrs:  "192.168.0.0/24,10.0.0.0/24",
			wantV4: []string{"192.168.0.0/24", "10.0.0.0/24"},
		},
		{
			name:   "ipv6",
			cidrs:  "2001:db8::/64",
			wantV6: []string{"2001:db8::/64"},
		},
		{
			name:   "ip4-ipv6",
			cidrs:  "192.168.0.0/24,2001:db8::/64",
			wantV4: []string{"192.168.0.0/24"},
			wantV6: []string{"2001:db8::/64"},
		},
		{
			name:   "ip6-ipv4",
			cidrs:  "2001:db8::/64,192.168.0.0/24",
			wantV4: []string{"192.168.0.0/24"},
			wantV6: []string{"2001:db8::/64"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v4CIDRs := sets.New[string]()
			v6CIDRs := sets.New[string]()

			got, got1 := splitCIDRs(tt.cidrs)
			v4CIDRs.Insert(got...)
			v6CIDRs.Insert(got1...)

			t.Logf("len got %d len got1 %d", v4CIDRs.Len(), v6CIDRs.Len())
			if !reflect.DeepEqual(got, tt.wantV4) {
				t.Errorf("splitCIDRs() got = %v, want %v", got, tt.wantV4)
			}
			if !reflect.DeepEqual(got1, tt.wantV6) {
				t.Errorf("splitCIDRs() got1 = %v, want %v", got1, tt.wantV6)
			}
		})
	}
}
