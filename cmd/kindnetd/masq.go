// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/aojea/kindnet/pkg/network"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	coreinformers "k8s.io/client-go/informers/core/v1"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

// NewIPMasqAgent returns a new IPMasqAgent that avoids masquerading the intra-cluster traffic
// but allows to masquerade the cluster to external traffic.
func NewIPMasqAgent(nodeInformer coreinformers.NodeInformer, noMasqueradeCIDRs string) (*IPMasqAgent, error) {
	klog.V(2).Info("Initializing nftables")
	nft, err := knftables.New(knftables.InetFamily, "kindnet-ipmasq")
	if err != nil {
		return nil, err
	}
	v4, v6 := network.SplitCIDRs(noMasqueradeCIDRs)
	return &IPMasqAgent{
		nft:         nft,
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
	nft         knftables.Interface
	nodeLister  v1.NodeLister
	nodesSynced cache.InformerSynced
	noMasqV4    []string
	noMasqV6    []string
	flushed     bool
}

// SyncRulesForever syncs ip masquerade rules forever
// these rules only needs to be installed once, but we run it periodically to check that are
// not deleted by an external program. It fails if can't sync the rules during 3 iterations
// TODO: aggregate errors
func (ma *IPMasqAgent) SyncRulesForever(ctx context.Context, interval time.Duration) error {
	if !cache.WaitForNamedCacheSync("kindnet-ipmasq", ctx.Done(), ma.nodesSynced) {
		return fmt.Errorf("error syncing cache")
	}
	klog.Info("Syncing nftables rules")
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
				return fmt.Errorf("can't synchronize rules after 3 attempts: %v", err)
			}
		} else {
			errs = 0
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
	table := &knftables.Table{
		Comment: knftables.PtrTo("rules for kindnet masquerading"),
	}
	tx := ma.nft.NewTransaction()
	// do it once to delete the existing table
	if !ma.flushed {
		tx.Add(table)
		tx.Delete(table)
		ma.flushed = true
	}
	tx.Add(table)

	// add set with the CIDRs that should not be masqueraded
	tx.Add(&knftables.Set{
		Name:      "noMasqV4",
		Type:      "ipv4_addr",
		Flags:     []knftables.SetFlag{knftables.IntervalFlag},
		AutoMerge: ptr.To(true),
		Comment:   ptr.To("IPv4 CIDRs that should not be masqueraded"),
	})
	tx.Flush(&knftables.Set{
		Name: "noMasqV4",
	})
	tx.Add(&knftables.Set{
		Name:      "noMasqV6",
		Type:      "ipv6_addr",
		Flags:     []knftables.SetFlag{knftables.IntervalFlag},
		AutoMerge: ptr.To(true),
		Comment:   ptr.To("IPv6 CIDRs that should not be masqueraded"),
	})
	tx.Flush(&knftables.Set{
		Name: "noMasqV6",
	})

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

	for _, cidr := range v4CIDRs.UnsortedList() {
		klog.V(7).Infof("Adding %s to set noMasqV4", cidr)
		tx.Add(&knftables.Element{
			Set: "noMasqV4",
			Key: []string{cidr},
		})
	}
	for _, cidr := range v6CIDRs.UnsortedList() {
		klog.V(7).Infof("Adding %s to set noMasqV6", cidr)
		tx.Add(&knftables.Element{
			Set: "noMasqV6",
			Key: []string{cidr},
		})
	}
	hook := knftables.PostroutingHook
	chainName := string(hook)
	tx.Add(&knftables.Chain{
		Name:     chainName,
		Type:     knftables.PtrTo(knftables.NATType),
		Hook:     knftables.PtrTo(hook),
		Priority: knftables.PtrTo(knftables.SNATPriority + "-5"),
	})
	tx.Flush(&knftables.Chain{
		Name: chainName,
	})

	tx.Add(&knftables.Rule{
		Chain:   chainName,
		Rule:    "ct state established,related accept",
		Comment: ptr.To("skip stablished"),
	})

	// skip local traffic
	tx.Add(&knftables.Rule{
		Chain:   chainName,
		Rule:    "fib daddr type local accept",
		Comment: ptr.To("skip local traffic"),
	})

	// ignore other Pods and defined cidrs
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"ip", "daddr", "@", "noMasqV4", "accept",
		),
		Comment: ptr.To("no masquerade IPv4 traffic"),
	})

	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"ip6", "daddr", "@", "noMasqV6", "accept",
		),
		Comment: ptr.To("no masquerade IPv6 traffic"),
	})

	// masquerade the rest of the traffic
	tx.Add(&knftables.Rule{
		Chain:   chainName,
		Rule:    "masquerade",
		Comment: ptr.To("masquerade traffic"),
	})

	if err := ma.nft.Run(ctx, tx); err != nil {
		klog.Infof("error syncing nftables rules %v", err)
		return err
	}
	return nil
}

func (ma *IPMasqAgent) CleanRules() {
	tx := ma.nft.NewTransaction()
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	tx.Add(&knftables.Table{})
	tx.Delete(&knftables.Table{})

	if err := ma.nft.Run(context.TODO(), tx); err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}
