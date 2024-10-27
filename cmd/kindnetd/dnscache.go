/*
Copyright 2024 The Kubernetes Authors.

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

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	utilio "k8s.io/utils/io"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

const (
	maxResolvConfLength = 10 * 1 << 20 // 10MB
	tproxyBypassMark    = 12
	tproxyMark          = 11
	tproxyTable         = 100
)

// NewDNSCacheAgent caches all DNS traffic from Pods with network based on the PodCIDR of the node they are running.
// Cache logic is very specific to Kubernetes,
func NewDNSCacheAgent(nodeName string, nodeInformer coreinformers.NodeInformer) (*DNSCacheAgent, error) {
	klog.V(2).Info("Initializing nftables")
	nft, err := knftables.New(knftables.InetFamily, "kindnet-dnscache")
	if err != nil {
		return nil, err
	}
	// kindnet is using hostNetwork and dnsPolicy: ClusterFirstWithHostNet
	// so its resolv.conf will have the configuration from the network Pods
	klog.Info("Configuring upstream DNS resolver")
	hostDNS, hostSearch, hostOptions, err := parseResolvConf()
	if err != nil {
		err := fmt.Errorf("encountered error while parsing resolv conf file. Error: %w", err)
		klog.ErrorS(err, "Could not parse resolv conf file.")
		return nil, err
	}

	klog.V(2).Infof("Parsed resolv.conf: nameservers: %v search: %v options: %v", hostDNS, hostSearch, hostOptions)

	d := &DNSCacheAgent{
		nft:         nft,
		nodeName:    nodeName,
		nameServer:  hostDNS[0],
		searches:    hostSearch,
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		interval:    1 * time.Minute,
		proxy:       NewDNSProxy(hostDNS[0]),
	}

	return d, nil
}

// DNSCacheAgent caches all DNS traffic from Pods with network based on the PodCIDR of the node they are running.
// Cache logic is very specific to Kubernetes,
type DNSCacheAgent struct {
	nft         knftables.Interface
	nodeName    string
	nodeLister  v1.NodeLister
	nodesSynced cache.InformerSynced
	interval    time.Duration

	podCIDRv4  string
	podCIDRv6  string
	nameServer string
	searches   []string
	flushed    bool

	proxy *DNSProxy
}

// Run syncs dns cache intercept rules
func (d *DNSCacheAgent) Run(ctx context.Context) error {
	if !cache.WaitForNamedCacheSync("kindnet-dnscache", ctx.Done(), d.nodesSynced) {
		return fmt.Errorf("error syncing cache")
	}

	klog.Info("Waiting for node parameters")
	err := wait.PollUntilContextCancel(ctx, 1*time.Second, true, func(context.Context) (bool, error) {
		node, err := d.nodeLister.Get(d.nodeName)
		if err != nil {
			return false, nil
		}
		podCIDRsv4, podCIDRsv6 := splitCIDRslice(node.Spec.PodCIDRs)
		klog.V(7).Infof("Got %v and %v from node %s", podCIDRsv4, podCIDRsv6, node.Name)
		if len(podCIDRsv4) > 0 {
			d.podCIDRv4 = podCIDRsv4[0]
		}
		if len(podCIDRsv6) > 0 {
			d.podCIDRv6 = podCIDRsv6[0]
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	go func() {
		for {
			klog.Info("Starting dns proxy")
			err = d.proxy.Start()
			if err != nil {
				klog.Errorf("dns proxy stopped with error: %v , restarting in 5 seconds ...", err)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	for d.proxy.GetLocalAddr() == "" {
		klog.Info("Waiting for dns proxy to start")
		time.Sleep(1 * time.Second)
	}

	klog.Info("Syncing local route rules")
	err = d.syncLocalRoute()
	if err != nil {
		klog.Infof("error syncing local route: %v", err)
	}

	klog.Info("Syncing nftables rules")
	errs := 0
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := d.SyncRules(ctx); err != nil {
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
		case <-d.proxy.ReadyChannel():
			continue
		case <-ticker.C:
			continue
		}
	}
}

func (d *DNSCacheAgent) syncLocalRoute() error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find 'lo' link: %v", err)
	}

	ip, err := netip.ParseAddr(d.nameServer)
	if err != nil {
		return err
	}
	r := netlink.NewRule()
	r.Family = unix.AF_INET
	if ip.Is6() {
		r.Family = unix.AF_INET6
	}
	r.Table = tproxyTable
	r.Mark = tproxyMark
	if err := netlink.RuleAdd(r); err != nil {
		return fmt.Errorf("failed to configure netlink rule: %v", err)
	}

	mask := "32"
	if ip.Is6() {
		mask = "128"
	}
	_, dst, err := net.ParseCIDR(d.nameServer + "/" + mask)
	if err != nil {
		return fmt.Errorf("parse CIDR: %v", err)
	}

	err = netlink.RouteAdd(&netlink.Route{
		Dst:       dst,
		Scope:     netlink.SCOPE_HOST,
		Type:      unix.RTN_LOCAL,
		Table:     tproxyTable,
		LinkIndex: link.Attrs().Index,
	})
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
			return fmt.Errorf("failed to add route: %v", err)
		}

	}
	return nil
}

// SyncRules syncs ip masquerade rules
func (d *DNSCacheAgent) SyncRules(ctx context.Context) error {
	table := &knftables.Table{
		Comment: knftables.PtrTo("rules for kindnet dnscache"),
	}
	tx := d.nft.NewTransaction()
	// do it once to delete the existing table
	if !d.flushed {
		tx.Add(table)
		tx.Delete(table)
		d.flushed = true
	}
	tx.Add(table)

	hook := knftables.PreroutingHook
	chainName := string(hook)
	tx.Add(&knftables.Chain{
		Name: chainName,
		Type: knftables.PtrTo(knftables.FilterType),
		Hook: knftables.PtrTo(hook),
		// before conntrack to avoid tproxied traffic to be natted
		// https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation
		// https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
		Priority: knftables.PtrTo(knftables.RawPriority + "-10"),
	})
	tx.Flush(&knftables.Chain{
		Name: chainName,
	})
	// bypass mark
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"meta", "mark", tproxyBypassMark, "return",
		),
	})

	// process coming from Pods destined to the DNS server
	// https://www.netfilter.org/projects/nftables/manpage.html
	// TODO: obtain the DNS server for the Pods from the kubelet config
	// Port 10250/configz ??
	if d.podCIDRv4 != "" {
		// only packets destined to the cluster DNS server from the Pods
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip saddr", d.podCIDRv4,
				"ip daddr", d.nameServer,
				"meta l4proto udp th dport 53",
				//"socket transparent 1",
				"tproxy ip to", d.proxy.GetLocalAddr(),
				"meta mark set", tproxyMark,
				"notrack",
				"counter",
				"accept",
			), // set a mark to check if there is abug in the kernel when creating the entire expression
			Comment: ptr.To("DNS IPv4 pod originated traffic"),
		})
	}

	if d.podCIDRv6 != "" {
		// only packets destined to the cluster DNS server
		tx.Add(&knftables.Rule{
			Chain: chainName,
			Rule: knftables.Concat(
				"ip6 saddr", d.podCIDRv6,
				"ip6 daddr", d.nameServer,
				"meta l4proto udp th dport 53",
				// "socket transparent 1",
				"tproxy ip6 to", d.proxy.GetLocalAddr(),
				"meta mark set", tproxyMark,
				"counter",
				"notrack",
				"accept",
			),
			Comment: ptr.To("DNS IPv6 pod originated traffic"),
		})
	}

	// stop processing tproxied traffic
	tx.Add(&knftables.Rule{
		Chain: chainName,
		Rule: knftables.Concat(
			"meta", "mark", tproxyMark, "drop",
		),
	})

	if err := d.nft.Run(ctx, tx); err != nil {
		klog.Infof("error syncing nftables rules %v", err)
		return err
	}
	return nil
}

func (d *DNSCacheAgent) CleanRules() {
	tx := d.nft.NewTransaction()
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	tx.Add(&knftables.Table{})
	tx.Delete(&knftables.Table{})

	if err := d.nft.Run(context.TODO(), tx); err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}

// https://github.com/kubernetes/kubernetes/blob/2108e54f5249c6b3b0c9f824314cb5f33c01e3f4/pkg/kubelet/network/dns/dns.go#L176
// parseResolvConf reads a resolv.conf file from the given reader, and parses
// it into nameservers, searches and options, possibly returning an error.
func parseResolvConf() (nameservers []string, searches []string, options []string, err error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		klog.ErrorS(err, "Could not open resolv conf file.")
		return nil, nil, nil, err
	}
	defer f.Close()

	file, err := utilio.ReadAtMost(f, maxResolvConfLength)
	if err != nil {
		return nil, nil, nil, err
	}

	// Lines of the form "nameserver 1.2.3.4" accumulate.
	nameservers = []string{}

	// Lines of the form "search example.com" overrule - last one wins.
	searches = []string{}

	// Lines of the form "option ndots:5 attempts:2" overrule - last one wins.
	// Each option is recorded as an element in the array.
	options = []string{}

	var allErrors []error
	lines := strings.Split(string(file), "\n")
	for l := range lines {
		trimmed := strings.TrimSpace(lines[l])
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "nameserver" {
			if len(fields) >= 2 {
				nameservers = append(nameservers, fields[1])
			} else {
				allErrors = append(allErrors, fmt.Errorf("nameserver list is empty "))
			}
		}
		if fields[0] == "search" {
			// Normalise search fields so the same domain with and without trailing dot will only count once, to avoid hitting search validation limits.
			searches = []string{}
			for _, s := range fields[1:] {
				if s != "." {
					searches = append(searches, strings.TrimSuffix(s, "."))
				}
			}
		}
		if fields[0] == "options" {
			options = appendOptions(options, fields[1:]...)
		}
	}

	return nameservers, searches, options, utilerrors.NewAggregate(allErrors)
}

// appendOptions appends options to the given list, but does not add duplicates.
// append option will overwrite the previous one either in new line or in the same line.
func appendOptions(options []string, newOption ...string) []string {
	var optionMap = make(map[string]string)
	for _, option := range options {
		optName := strings.Split(option, ":")[0]
		optionMap[optName] = option
	}
	for _, option := range newOption {
		optName := strings.Split(option, ":")[0]
		optionMap[optName] = option
	}

	options = []string{}
	for _, v := range optionMap {
		options = append(options, v)
	}
	return options
}
