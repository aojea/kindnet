
package network

import (
	"net/netip"
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

			got, got1 := SplitCIDRs(tt.cidrs)
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

func Test_isNotContained(t *testing.T) {
	tests := []struct {
		name     string
		prefix   netip.Prefix
		prefixes []netip.Prefix
		want     bool
	}{
		{
			name:     "ipv4 not contained nor overlapping",
			prefix:   netip.MustParsePrefix("192.168.0.0/24"),
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.0/27")},
			want:     true,
		},
		{
			name:     "ipv4 not contained but contains",
			prefix:   netip.MustParsePrefix("10.0.0.0/8"),
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.0/27")},
			want:     true,
		},
		{
			name:     "ipv4 not contained but matches existing one",
			prefix:   netip.MustParsePrefix("10.0.0.0/24"),
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.0/27")},
			want:     true,
		},
		{
			name:     "ipv4 contained but matches existing one",
			prefix:   netip.MustParsePrefix("10.0.0.0/27"),
			prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.0/27")},
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNotContained(tt.prefix, tt.prefixes); got != tt.want {
				t.Errorf("isNotContained() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTopLevelPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []netip.Prefix
		want     []netip.Prefix
		want1    []netip.Prefix
	}{
		{
			name: "ipv4",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("10.0.1.0/23"),
			},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			want1: []netip.Prefix{},
		},
		{
			name: "ipv6",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/8"),
				netip.MustParsePrefix("2001:db8::/23"),
			},
			want:  []netip.Prefix{},
			want1: []netip.Prefix{netip.MustParsePrefix("2001:db8::/8")},
		},
		{
			name: "ipv4 ipv6",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("10.0.1.0/23"),
				netip.MustParsePrefix("2001:db8::/8"),
				netip.MustParsePrefix("2001:db8::/23"),
			},
			want:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			want1: []netip.Prefix{netip.MustParsePrefix("2001:db8::/8")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := TopLevelPrefixes(tt.prefixes)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TopLevelPrefixes() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("TopLevelPrefixes() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
