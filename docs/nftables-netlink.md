# NFtables netlink development

The kernels exposes a Netlink interface to program nftables

- https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals
- https://docs.kernel.org/next/networking/netlink_spec/nftables.html

To avoid dependencies on userspace, kindnet uses the library https://github.com/google/nftables to program the nftables rule directly.

Since is very complex to work directly with the bytecode, the workflow suggested is:

1. Define the rules with `nft` and use the [debug option](https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/VM_code_analysis) to dump the bytecode

```sh
nft --debug=netlink -f -
table ip6 kindnet-nat64 {
                chain prerouting {
                        type filter hook prerouting priority raw - 10; policy accept;
                        meta mark 0x0000000e return
                        ip6 daddr 64:ff9b::/96 meta l4proto udp tproxy to [::1]:60693 meta mark set 0x0000000d notrack accept
                        ip6 daddr 64:ff9b::/96 meta l4proto tcp tproxy to [::1]:45217 meta mark set 0x0000000d notrack accept
                        meta mark 0x0000000d drop
                }
        }


ip6 (null) (null) use 0 type filter hook prerouting prio -310 packets 0 bytes 0
ip6 kindnet-nat64 prerouting
  [ meta load mark => reg 1 ]
  [ cmp eq reg 1 0x0000000e ]
  [ immediate reg 0 return ]

ip6 kindnet-nat64 prerouting
  [ payload load 12b @ network header + 24 => reg 1 ]
  [ cmp eq reg 1 0x9bff6400 0x00000000 0x00000000 ]
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000011 ]
  [ immediate reg 1 0x00000000 0x00000000 0x00000000 0x01000000 ]
  [ immediate reg 2 0x000015ed ]
  [ tproxy ip6 addr reg 1 port reg 2 ]
  [ immediate reg 1 0x0000000d ]
  [ meta set mark with reg 1 ]
  [ notrack ]
  [ immediate reg 0 accept ]

ip6 kindnet-nat64 prerouting
  [ payload load 12b @ network header + 24 => reg 1 ]
  [ cmp eq reg 1 0x9bff6400 0x00000000 0x00000000 ]
  [ meta load l4proto => reg 1 ]
  [ cmp eq reg 1 0x00000006 ]
  [ immediate reg 1 0x00000000 0x00000000 0x00000000 0x01000000 ]
  [ immediate reg 2 0x0000a1b0 ]
  [ tproxy ip6 addr reg 1 port reg 2 ]
  [ immediate reg 1 0x0000000d ]
  [ meta set mark with reg 1 ]
  [ notrack ]
  [ immediate reg 0 accept ]

ip6 kindnet-nat64 prerouting
  [ meta load mark => reg 1 ]
  [ cmp eq reg 1 0x0000000d ]
  [ immediate reg 0 drop ]
```

2. Some times there can be bugs or inconsistencies with the implementation, specialy about byte ordering or size of some fields.
On those cases it is needed to dump the netlink protocol with `nft --debug=all`  and compare against the one using the golang library with the feature in this PR https://github.com/mdlayher/netlink/pull/219.


For development, a good option is to checkout this PR https://github.com/google/nftables/pull/292/, that allow to write snippets of nftables script and build the tests with the netlink dump

```diff
diff --git a/go.mod b/go.mod
index 92dfd49..1c446ec 100644
--- a/go.mod
+++ b/go.mod
@@ -16,3 +16,5 @@ require (
        golang.org/x/net v0.23.0 // indirect
        golang.org/x/sync v0.6.0 // indirect
 )
+
+replace github.com/mdlayher/netlink => ../go-netlink
```

Then run them will dump the necessary information to compare
```sh
NLDEBUG=1,format=mnl ./tests.test -test.v -run_system_tests -test.run  TestNFTables/AddFlowtables
```

Another important tip is to use something like
```go
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/nftables"
)

func main() {
	args := os.Args[1:]
	if len(args) != 2 {
		log.Fatalf("need to specify the table and chain to list")
	}

	c, err := nftables.New()
	if err != nil {
		log.Fatalf("nftables.New() failed: %v", err)
	}

	table, err := c.ListTableOfFamily(args[0], nftables.TableFamilyIPv6)
	if err != nil {
		log.Fatalf("ListTableOfFamily failed: %v", err)
	}

	chain, err := c.ListChain(table, args[1])
	if err != nil {
		log.Fatalf("ListChain failed: %v", err)
	}

	rules, err := c.GetRules(table, chain)
	if err != nil {
		log.Fatalf("GetRules failed: %v", err)
	}
	for _, rule := range rules {
		log.Printf("rule position %d", rule.Position)
		for _, exp := range rule.Exprs {
			fmt.Printf("%#v,\n", exp)
		}
	}
}
```

to dump the expression directly:

```sh
/internal kindnet-nat64 prerouting                                       
2025/01/09 19:34:28 rule position 0
&expr.Meta{Key:0x3, SourceRegister:false, Register:0x1}
&expr.Cmp{Op:0x0, Register:0x1, Data:[]uint8{0xe, 0x0, 0x0, 0x0}}
&expr.Verdict{Kind:-5, Chain:""}
2025/01/09 19:34:28 rule position 18
&expr.Payload{OperationType:0x0, DestRegister:0x1, SourceRegister:0x0, Base:0x1, Offset:0x18, Len:0xc, CsumType:0x0, CsumOffset:0x0, CsumFlags:0x0}
&expr.Cmp{Op:0x0, Register:0x1, Data:[]uint8{0x0, 0x64, 0xff, 0x9b, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}
&expr.Meta{Key:0x10, SourceRegister:false, Register:0x1}
&expr.Cmp{Op:0x0, Register:0x1, Data:[]uint8{0x11}}
&expr.Immediate{Register:0x1, Data:[]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}}
```

But usually there are bugs on the unmarshalling of the golang library and some expressions are missing.