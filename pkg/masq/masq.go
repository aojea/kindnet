// SPDX-License-Identifier: APACHE-2.0

package masq

import (
	"context"
	"fmt"
	"time"

	"github.com/aojea/kindnet/pkg/network"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

const tableName = "kindnet-ipmasq"

// NewIPMasqAgent returns a new IPMasqAgent that avoids masquerading the intra-cluster traffic
// but allows to masquerade the cluster to external traffic.
func NewIPMasqAgent(nodeInformer coreinformers.NodeInformer, noMasqueradeCIDRs string) (*IPMasqAgent, error) {
	v4, v6 := network.SplitCIDRs(noMasqueradeCIDRs)
	return &IPMasqAgent{
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		noMasqV4:    v4,
		noMasqV6:    v6,
	}, nil
}

// IPMasqAgent is based on https://github.com/kubernetes-incubator/ip-masq-agent
// but collapsed into kindnetd and made ipv6 aware in an opinionated and simplified
// fashion using "github.com/coreos/go-iptables"
type IPMasqAgent struct {
	nodeLister  v1.NodeLister
	nodesSynced cache.InformerSynced
	noMasqV4    []string
	noMasqV6    []string
}

// SyncRulesForever syncs ip masquerade rules forever
// these rules only needs to be installed once, but we run it periodically to check that are
// not deleted by an external program.
func (ma *IPMasqAgent) SyncRulesForever(ctx context.Context, interval time.Duration) error {
	if !cache.WaitForNamedCacheSync("kindnet-ipmasq", ctx.Done(), ma.nodesSynced) {
		return fmt.Errorf("error syncing cache")
	}
	errs := 0
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := ma.SyncRules(ctx); err != nil {
			errs++
			if errs > 3 {
				klog.Infof("can't synchronize rules after 3 attempts, retrying: %v", err)
				errs = 0
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}

// SyncRules syncs ip masquerade rules
func (ma *IPMasqAgent) SyncRules(ctx context.Context) error {
	klog.V(2).Info("Syncing kindnet-ipmasq nftables rules")
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("kindnet ipamsq failure, can not start nftables: %v", err)
	}

	// add + delete + add for flushing all the table
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	v4CIDRs := sets.New[string]()
	v6CIDRs := sets.New[string]()
	if len(ma.noMasqV4) > 0 {
		klog.V(7).Infof("Adding no masquerade IPv4 cidrs from user %v", ma.noMasqV4)
		v4CIDRs = v4CIDRs.Insert(ma.noMasqV4...)
	}
	if len(ma.noMasqV6) > 0 {
		klog.V(7).Infof("Adding no masquerade IPv6 cidrs from user %v", ma.noMasqV4)
		v6CIDRs = v6CIDRs.Insert(ma.noMasqV6...)
	}

	nodes, err := ma.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	// don't masquerade the traffic directed to the Pods
	for _, node := range nodes {
		podCIDRsv4, podCIDRsv6 := network.SplitCIDRslice(node.Spec.PodCIDRs)
		klog.V(7).Infof("Got %v and %v from node %s", podCIDRsv4, podCIDRsv6, node.Name)
		if len(podCIDRsv4) > 0 {
			v4CIDRs.Insert(podCIDRsv4...)
		}
		if len(podCIDRsv6) > 0 {
			v6CIDRs.Insert(podCIDRsv6...)
		}
	}

	var elementsV4, elementsV6 []nftables.SetElement
	for _, cidr := range v4CIDRs.UnsortedList() {
		klog.V(7).Infof("Adding %s to set noMasqV4", cidr)
		first, last, err := network.FirstAndNextSubnetAddr(cidr)
		if err != nil {
			klog.Infof("not able to parse %s : %v", cidr, err)
			continue
		}
		elementsV4 = append(elementsV4,
			nftables.SetElement{Key: first.AsSlice(), IntervalEnd: false},
			nftables.SetElement{Key: last.AsSlice(), IntervalEnd: true},
		)
	}

	for _, cidr := range v6CIDRs.UnsortedList() {
		klog.V(7).Infof("Adding %s to set noMasqV6", cidr)
		first, last, err := network.FirstAndNextSubnetAddr(cidr)
		if err != nil {
			klog.Infof("not able to parse %s : %v", cidr, err)
			continue
		}

		elementsV6 = append(elementsV6,
			nftables.SetElement{Key: first.AsSlice(), IntervalEnd: false},
			nftables.SetElement{Key: last.AsSlice(), IntervalEnd: true},
		)
	}

	setV4 := &nftables.Set{
		Table:     table,
		Name:      "noMasqV4",
		KeyType:   nftables.TypeIPAddr,
		Interval:  true,
		AutoMerge: true,
	}

	setV6 := &nftables.Set{
		Table:     table,
		Name:      "noMasqV6",
		KeyType:   nftables.TypeIP6Addr,
		Interval:  true,
		AutoMerge: true,
	}

	if err := nft.AddSet(setV4, elementsV4); err != nil {
		return fmt.Errorf("failed to add Set %s : %v", setV4.Name, err)
	}

	if err := nft.AddSet(setV6, elementsV6); err != nil {
		return fmt.Errorf("failed to add Set %s : %v", setV6.Name, err)
	}

	chain := nft.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 10),
	})

	//  ct state established,related accept
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Register: 0x1, SourceRegister: false, Key: expr.CtKeySTATE, Direction: 0x0},
			&expr.Bitwise{SourceRegister: 0x1, DestRegister: 0x1, Len: 0x4, Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED), Xor: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 0x1, Data: []byte{0x0, 0x0, 0x0, 0x0}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// fib daddr type local accept comment "skip local traffic"
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Fib{Register: 0x1, FlagSADDR: true, ResultADDRTYPE: true},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: network.EncodeWithAlignment(byte(unix.RTN_LOCAL))},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	// ip daddr @noMasqV4 accept comment "no masquerade IPv4 traffic"
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV4}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 0x4},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "noMasqV4", Invert: false},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	// ip6 daddr @noMasqV6 accept comment "no masquerade IPv6 traffic"
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: []byte{unix.NFPROTO_IPV6}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
			&expr.Lookup{SourceRegister: 0x1, DestRegister: 0x0, SetName: "noMasqV6", Invert: false},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// masquerade comment "masquerade traffic"
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Masq{Random: false, FullyRandom: false, Persistent: false, ToPorts: false, RegProtoMin: 0x0, RegProtoMax: 0x0},
			&expr.Counter{},
		},
	})

	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create kindnet-ipmasq table: %v", err)
	}
	return nil
}

func (ma *IPMasqAgent) CleanRules() {
	nft, err := nftables.New()
	if err != nil {
		klog.Infof("ipmasq cleanup failure, can not start nftables:%v", err)
		return
	}
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.DelTable(table)

	err = nft.Flush()
	if err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}
