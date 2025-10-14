
package dnscache

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netns"
)

func TestNFLogAgent_syncRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	tests := []struct {
		name             string
		podCIDRv4        string
		podCIDRv6        string
		expectedNftables string
		nameservers      []string
	}{
		{
			name: "empty",
			expectedNftables: `
table inet kindnet-dnscache {
        chain prerouting {
                type filter hook prerouting priority raw; policy accept;
        }
        chain output {
                type filter hook output priority raw; policy accept;
                meta mark 0x0000006e udp sport 53 notrack
        }
}
`,
		},
		{
			name:        "dual",
			podCIDRv4:   "10.0.0.0/24",
			podCIDRv6:   "2001:db8::/112",
			nameservers: []string{"1.1.1.1", "fd00::1"},
			expectedNftables: `
table inet kindnet-dnscache {
        set set-v4-nameservers {
                type ipv4_addr
                elements = { 1.1.1.1 }
        }

        set set-v6-nameservers {
                type ipv6_addr
                elements = { fd00::1 }
        }
        chain prerouting {
                type filter hook prerouting priority raw; policy accept;
                ip saddr 10.0.0.0/24 ip daddr @set-v4-nameservers udp dport 53 queue flags bypass to 103
                ip6 saddr 2001:db8::/112 ip6 daddr @set-v6-nameservers udp dport 53 queue flags bypass to 103
        }
        chain output {
                type filter hook output priority raw; policy accept;
                meta mark 0x0000006e udp sport 53 notrack
        }
}
`,
		},
		{
			name:        "dual odd mask",
			podCIDRv4:   "10.0.0.0/17",
			podCIDRv6:   "2001:db8::/77",
			nameservers: []string{"1.1.1.1", "fd00::1"},
			expectedNftables: `
table inet kindnet-dnscache {
        set set-v4-nameservers {
                type ipv4_addr
                elements = { 1.1.1.1 }
        }

        set set-v6-nameservers {
                type ipv6_addr
                elements = { fd00::1 }
        }
        chain prerouting {
                type filter hook prerouting priority raw; policy accept;
                ip saddr 10.0.0.0/17 ip daddr @set-v4-nameservers udp dport 53 queue flags bypass to 103
                ip6 saddr 2001:db8::/77 ip6 daddr @set-v6-nameservers udp dport 53 queue flags bypass to 103
        }
        chain output {
                type filter hook output priority raw; policy accept;
                meta mark 0x0000006e udp sport 53 notrack
        }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &DNSCacheAgent{
				podCIDRv4:   tt.podCIDRv4,
				podCIDRv6:   tt.podCIDRv6,
				nameServers: tt.nameservers,
			}
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// Save the current network namespace
			origns, err := netns.Get()
			if err != nil {
				t.Fatal(err)
			}
			defer origns.Close()

			// Create a new network namespace
			newns, err := netns.New()
			if err != nil {
				t.Fatal(err)
			}
			defer newns.Close()

			if err := n.SyncRules(context.Background()); err != nil {
				t.Fatalf("DNSCacheAgent.SyncRules() error = %v", err)
			}

			cmd := exec.Command("nft", "list", "table", "inet", tableName)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("nft list table error = %v", err)
			}
			got := string(out)
			if !compareMultilineStringsIgnoreIndentation(got, tt.expectedNftables) {
				t.Errorf("Got:\n%s\nExpected:\n%s\nDiff:\n%s", got, tt.expectedNftables, cmp.Diff(got, tt.expectedNftables))
			}
			CleanRules()
			cmd = exec.Command("nft", "list", "table", "inet", tableName)
			out, err = cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("nft list ruleset unexpected success")
			}
			if !strings.Contains(string(out), "No such file or directory") {
				t.Errorf("unexpected error %v %s", err, string(out))
			}
			// Switch back to the original namespace
			netns.Set(origns)
		})
	}
}

func compareMultilineStringsIgnoreIndentation(str1, str2 string) bool {
	// Remove all indentation from both strings
	re := regexp.MustCompile(`(?m)^\s+`)
	str1 = re.ReplaceAllString(str1, "")
	str2 = re.ReplaceAllString(str2, "")

	return str1 == str2
}
