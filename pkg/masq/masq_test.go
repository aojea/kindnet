
package masq

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/vishvananda/netns"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
)

func TestIPMasqAgent_SyncRules(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	tests := []struct {
		name             string
		nodes            []*v1.Node
		noMasqV4         []string
		noMasqV6         []string
		expectedNftables string
	}{
		{
			name: "no masq empty",
			expectedNftables: `
table inet kindnet-ipmasq {
      set noMasqV4 {
              type ipv4_addr
              flags interval
              auto-merge
      }

      set noMasqV6 {
              type ipv6_addr
              flags interval
              auto-merge
      }

      chain postrouting {
              type nat hook postrouting priority srcnat - 10; policy accept;
              ct state established,related accept
              fib daddr type local accept
              ip daddr @noMasqV4 accept
              ip6 daddr @noMasqV6 accept
              masquerade counter packets 0 bytes 0
      }
}
`,
		},
		{
			name: "ipv4 node",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "node1"},
					Spec:       v1.NodeSpec{PodCIDRs: []string{"10.1.1.0/24"}},
				},
			},
			expectedNftables: `
table inet kindnet-ipmasq {
      set noMasqV4 {
              type ipv4_addr
              flags interval
              auto-merge
              elements = { 10.1.1.0/24 }
      }

      set noMasqV6 {
              type ipv6_addr
              flags interval
              auto-merge
      }

      chain postrouting {
              type nat hook postrouting priority srcnat - 10; policy accept;
              ct state established,related accept
              fib daddr type local accept
              ip daddr @noMasqV4 accept
              ip6 daddr @noMasqV6 accept
              masquerade counter packets 0 bytes 0
      }
}
`,
		},
		{
			name: "ipv4 node overlapping",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "node1"},
					Spec:       v1.NodeSpec{PodCIDRs: []string{"10.1.1.0/24"}},
				},
			},
			noMasqV4: []string{"10.0.0.0/8", "10.0.1.0/23"},
			expectedNftables: `
table inet kindnet-ipmasq {
      set noMasqV4 {
              type ipv4_addr
              flags interval
              auto-merge
              elements = { 10.0.0.0/8 }
      }

      set noMasqV6 {
              type ipv6_addr
              flags interval
              auto-merge
      }

      chain postrouting {
              type nat hook postrouting priority srcnat - 10; policy accept;
              ct state established,related accept
              fib daddr type local accept
              ip daddr @noMasqV4 accept
              ip6 daddr @noMasqV6 accept
              masquerade counter packets 0 bytes 0
      }
}
`,
		},
		{
			name: "ipv4 - ipv6 node",
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "node1"},
					Spec:       v1.NodeSpec{PodCIDRs: []string{"10.1.1.0/24", "2001:db8::/64"}},
				},
			},
			expectedNftables: `
table inet kindnet-ipmasq {
      set noMasqV4 {
              type ipv4_addr
              flags interval
              auto-merge
              elements = { 10.1.1.0/24 }
      }

      set noMasqV6 {
              type ipv6_addr
              flags interval
              auto-merge
              elements = { 2001:db8::/64 }
      }

      chain postrouting {
              type nat hook postrouting priority srcnat - 10; policy accept;
              ct state established,related accept
              fib daddr type local accept
              ip daddr @noMasqV4 accept
              ip6 daddr @noMasqV6 accept
              masquerade counter packets 0 bytes 0
      }
}
`,
		},
		{
			name:     "ipv4 - ipv6 node and no cidr masqs",
			noMasqV4: []string{"192.168.0.0/24"},
			noMasqV6: []string{"fd00:1:2:3::/112"},
			nodes: []*v1.Node{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "node1"},
					Spec:       v1.NodeSpec{PodCIDRs: []string{"10.1.1.0/24", "2001:db8::/64"}},
				},
			},
			expectedNftables: `
table inet kindnet-ipmasq {
      set noMasqV4 {
              type ipv4_addr
              flags interval
              auto-merge
              elements = { 10.1.1.0/24, 192.168.0.0/24 }
      }

      set noMasqV6 {
              type ipv6_addr
              flags interval
              auto-merge
              elements = { 2001:db8::/64,
                           fd00:1:2:3::/112 }

      }

      chain postrouting {
              type nat hook postrouting priority srcnat - 10; policy accept;
              ct state established,related accept
              fib daddr type local accept
              ip daddr @noMasqV4 accept
              ip6 daddr @noMasqV6 accept
              masquerade counter packets 0 bytes 0
      }
}
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			informerFactory := informers.NewSharedInformerFactory(client, 0)
			nodeInformer := informerFactory.Core().V1().Nodes()
			indexer := nodeInformer.Informer().GetIndexer()
			for _, node := range tt.nodes {
				if err := indexer.Add(node); err != nil {
					t.Fatal(err)
				}
			}
			v4s := []netip.Prefix{}
			for _, cidr := range tt.noMasqV4 {
				v4s = append(v4s, netip.MustParsePrefix(cidr))
			}
			v6s := []netip.Prefix{}
			for _, cidr := range tt.noMasqV6 {
				v6s = append(v4s, netip.MustParsePrefix(cidr))
			}
			ma := &IPMasqAgent{
				nodeLister: nodeInformer.Lister(),
				noMasqV4:   v4s,
				noMasqV6:   v6s,
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

			if err := ma.SyncRules(context.Background()); err != nil {
				t.Fatalf("IPMasqAgent.SyncRules() error = %v", err)
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
