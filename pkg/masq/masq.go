/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package masq

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/aojea/kindnet/pkg/network"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	nodelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

// TODO: move this logic to a controller to process the nodes in a queue
// and to implement proper deduplication to avoid overlapping ranges.
const tableName = "kindnet-ipmasq"

// NewIPMasqAgent returns a new IPMasqAgent that avoids masquerading the intra-cluster traffic
// but allows to masquerade the cluster to external traffic.
func NewIPMasqAgent(nodeInformer coreinformers.NodeInformer, noMasqueradeCIDRs string) (*IPMasqAgent, error) {
	v4, v6 := network.TopLevelPrefixes(network.CIDRsToPrefix(noMasqueradeCIDRs))

	c := &IPMasqAgent{
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		workqueue:   workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		noMasqV4:    v4,
		noMasqV6:    v6,
	}

	_, err := nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueNode,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueNode(new)
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*v1.Node)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				node, ok = tombstone.Obj.(*v1.Node)
				if !ok {
					return
				}
			}
			if len(node.Spec.PodCIDRs) == 0 {
				klog.Infof("Node %s has no CIDR, ignoring\n", node.Name)
				return
			}
			// we do a full resync so no need to differentiate between nodes
			c.workqueue.AddAfter("sync-token", 5*time.Second)
		},
	})

	if err != nil {
		klog.Infof("unexpected error adding event handler to informer: %v", err)
		return nil, err
	}
	return c, nil
}

func (ma *IPMasqAgent) enqueueNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}

	if len(node.Spec.PodCIDRs) == 0 {
		klog.Infof("Node %s has no CIDR, ignoring\n", node.Name)
		return
	}

	// we do a full resync so no need to differentiate between nodes
	ma.workqueue.AddAfter("sync-token", 5*time.Second)
}

// IPMasqAgent is based on https://github.com/kubernetes-incubator/ip-masq-agent
// but collapsed into kindnetd and made ipv6 aware in an opinionated and simplified
// fashion using "github.com/coreos/go-iptables"
type IPMasqAgent struct {
	nodeLister  nodelisters.NodeLister
	nodesSynced cache.InformerSynced
	workqueue   workqueue.TypedRateLimitingInterface[string]

	noMasqV4 []netip.Prefix
	noMasqV6 []netip.Prefix
}

func (ma *IPMasqAgent) Run(ctx context.Context) error {
	defer utilruntime.HandleCrash()
	defer ma.workqueue.ShutDown()
	logger := klog.FromContext(ctx)

	logger.Info("Starting masquerade controller")
	logger.Info("Waiting for informer caches to sync")
	if !cache.WaitForNamedCacheSync("kindnet-ipmasq", ctx.Done(), ma.nodesSynced) {
		return fmt.Errorf("error syncing cache")
	}

	logger.Info("Starting worker")
	go wait.UntilWithContext(ctx, ma.runWorker, time.Second)

	logger.Info("Started worker")
	<-ctx.Done()
	logger.Info("Shutting down worker")
	return nil
}

func (ma *IPMasqAgent) runWorker(ctx context.Context) {
	for ma.processNextWorkItem(ctx) {
	}
}

func (ma *IPMasqAgent) processNextWorkItem(ctx context.Context) bool {
	key, shutdown := ma.workqueue.Get()
	if shutdown {
		return false
	}
	defer ma.workqueue.Done(key)

	err := ma.SyncRules(ctx)
	ma.handleErr(err, key)
	return true
}

func (ma *IPMasqAgent) handleErr(err error, key string) {
	if err == nil {
		ma.workqueue.Forget(key)
		return
	}

	if ma.workqueue.NumRequeues(key) < 15 {
		klog.Infof("Error syncing node %s, retrying: %v", key, err)
		ma.workqueue.AddRateLimited(key)
		return
	}

	ma.workqueue.Forget(key)
	utilruntime.HandleError(err)
	klog.Infof("Dropping node %q out of the queue: %v", key, err)
}

// SyncRules syncs ip masquerade rules
func (ma *IPMasqAgent) SyncRules(ctx context.Context) error {
	klog.Info("Syncing kindnet-ipmasq nftables rules")
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

	prefixes := sets.New[netip.Prefix]()
	prefixes.Insert(ma.noMasqV4...)
	prefixes.Insert(ma.noMasqV6...)

	nodes, err := ma.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	// don't masquerade the traffic directed to the Pods
	for _, node := range nodes {
		podCIDRsv4, podCIDRsv6 := network.SplitCIDRslice(node.Spec.PodCIDRs)
		klog.V(4).Infof("Got %v and %v from node %s", podCIDRsv4, podCIDRsv6, node.Name)
		if len(podCIDRsv4) > 0 {
			prefix, err := netip.ParsePrefix(podCIDRsv4[0])
			if err == nil {
				prefixes.Insert(prefix)
			}
		}
		if len(podCIDRsv6) > 0 {
			prefix, err := netip.ParsePrefix(podCIDRsv6[0])
			if err == nil {
				prefixes.Insert(prefix)
			}
		}
	}
	v4CIDRs, v6CIDRs := network.TopLevelPrefixes(prefixes.UnsortedList())
	var elementsV4, elementsV6 []nftables.SetElement
	for _, cidr := range v4CIDRs {
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

	for _, cidr := range v6CIDRs {
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
			&expr.Fib{Register: 0x1, FlagDADDR: true, ResultADDRTYPE: true},
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

func CleanRules() {
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
