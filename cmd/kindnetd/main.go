/*
Copyright 2019 The Kubernetes Authors.

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
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// kindnetd is a simple networking daemon to complete kind's CNI implementation
// kindnetd will ensure routes to the other node's PodCIDR via their InternalIP
// kindnetd will ensure pod to pod communication will not be masquerade
// kindnetd will also write a templated cni config supplied with PodCIDR
//
// input envs:
// - HOST_IP: should be populated by downward API
// - POD_IP: should be populated by downward API
// - CNI_CONFIG_TEMPLATE: the cni .conflist template, run with {{ .PodCIDR }}

// TODO: improve logging & error handling

// IPFamily defines kindnet networking operating model
type IPFamily string

const (
	// IPv4Family sets IPFamily to ipv4
	IPv4Family IPFamily = "ipv4"
	// IPv6Family sets IPFamily to ipv6
	IPv6Family IPFamily = "ipv6"
	// DualStackFamily sets ClusterIPFamily to DualStack
	DualStackFamily IPFamily = "dualstack"
)

var (
	useBridge         bool
	networkpolicies   bool
	dnsCaching        bool
	nat64             bool
	hostnameOverride  string
	masquerading      bool
	noMasqueradeCIDRs string
)

func init() {
	flag.BoolVar(&useBridge, "cni-bridge", false, "If set, enable the CNI bridge plugin (default is the ptp plugin)")
	flag.BoolVar(&networkpolicies, "network-policy", true, "If set, enable Network Policies (default true)")
	flag.BoolVar(&dnsCaching, "dns-caching", false, "If set, enable Kubernetes DNS caching (default false)")
	flag.BoolVar(&nat64, "nat64", true, "If set, enable NAT64 using the reserved prefix 64:ff9b::/96 on IPv6 only clusters (default true)")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "If non-empty, will be used as the name of the Node that kube-network-policies is running on. If unset, the node name is assumed to be the same as the node's hostname.")
	flag.BoolVar(&masquerading, "masquerading", true, "masquerade with the Node IP the cluster to external traffic (default true)")
	flag.StringVar(&noMasqueradeCIDRs, "no-masquerade-cidr", "", "Comma seperated list of CIDRs that will not be masqueraded.")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: kindnet [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// enable logging
	klog.InitFlags(nil)
	_ = flag.Set("logtostderr", "true")
	flag.Parse()
	flag.VisitAll(func(flag *flag.Flag) {
		klog.Infof("FLAG: --%s=%q", flag.Name, flag.Value)
	})

	var err error
	nodeName := hostnameOverride
	if nodeName == "" {
		nodeName, err = os.Hostname()
		if err != nil {
			klog.Fatalf("couldn't determine hostname: %v", err)
		}
	}

	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	config.UserAgent = "kindnet"
	// use protobuf for better performance at scale
	// https://kubernetes.io/docs/reference/using-api/api-concepts/#alternate-representations-of-resources
	config.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	config.ContentType = "application/vnd.kubernetes.protobuf"

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)

	go func() {
		select {
		case <-signalCh:
			klog.Infof("Exiting: received signal")
			cancel()
		case <-ctx.Done():
		}
	}()

	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informersFactory.Core().V1().Nodes()
	nodeLister := nodeInformer.Lister()

	// obtain the host and pod ip addresses
	hostIP, podIP := os.Getenv("HOST_IP"), os.Getenv("POD_IP")
	klog.Infof("hostIP = %s\npodIP = %s\n", hostIP, podIP)
	if hostIP != podIP {
		panic(fmt.Sprintf(
			"hostIP(= %q) != podIP(= %q) but must be running with host network: ",
			hostIP, podIP,
		))
	}

	mtu, err := GetMTU(unix.AF_UNSPEC)
	klog.Infof("setting mtu %d for CNI \n", mtu)
	if err != nil {
		klog.Infof("Failed to get MTU size from interface eth0, using kernel default MTU size error:%v", err)
	}

	// CNI_BRIDGE env variable uses the CNI bridge plugin, defaults to ptp
	useBridge = useBridge || len(os.Getenv("CNI_BRIDGE")) > 0
	// disable offloading in the bridge if exists
	disableOffload := false
	if useBridge {
		disableOffload = len(os.Getenv("DISABLE_CNI_BRIDGE_OFFLOAD")) > 0
	}
	// used to track if the cni config inputs changed and write the config
	cniConfigWriter := &CNIConfigWriter{
		path:   cniConfigPath,
		bridge: useBridge,
		mtu:    mtu,
	}
	klog.Infof("Configuring CNI path: %s bridge: %v disableOffload: %v mtu: %d",
		cniConfigPath, useBridge, disableOffload, mtu)

	// create an ipMasqAgent
	if masquerading {
		klog.Infof("masquerading cluster traffic")
		masqAgent, err := NewIPMasqAgent(nodeInformer, noMasqueradeCIDRs)
		if err != nil {
			klog.Fatalf("error creating masquerading agent: %v", err)
		}

		go func() {
			defer masqAgent.CleanRules()
			if err := masqAgent.SyncRulesForever(ctx, time.Second*60); err != nil {
				klog.Infof("error running masquerading agent: %v", err)
			}
		}()
	} else {
		klog.Info("Skipping ipMasqAgent")
	}

	// create an nat64 agent if nat64 is enabled and is an IPv6 only cluster
	ip, err := netip.ParseAddr(podIP)
	if err != nil {
		klog.Fatalf("can not parse ip %s : %v", podIP, err)
	}
	if nat64 && ip.Is6() {
		klog.Infof("nat64 traffic")
		nat64Agent, err := NewNAT64Agent()
		if err != nil {
			klog.Fatalf("error creating nat64 agent: %v", err)
		}

		go func() {
			defer nat64Agent.CleanRules()
			if err := nat64Agent.Run(ctx); err != nil {
				klog.Infof("error running nat64 agent: %v", err)
			}
		}()
	} else {
		klog.Info("Skipping nat64 agent")
	}

	// create a dnsCacheAgent
	if dnsCaching {
		klog.Infof("caching DNS cluster traffic")
		dnsCacheAgent, err := NewDNSCacheAgent(nodeName, nodeInformer)
		if err != nil {
			klog.Fatalf("error creating dnsCacheAgent agent: %v", err)
		}

		go func() {
			defer dnsCacheAgent.CleanRules()
			if err := dnsCacheAgent.Run(ctx); err != nil {
				klog.Infof("error running dnsCacheAgent agent: %v", err)
			}
		}()
	} else {
		klog.Info("Skipping dnsCacheAgent")
	}

	// setup nodes reconcile function, closes over arguments
	reconcileNodes := makeNodesReconciler(cniConfigWriter, hostIP)

	// network policies
	if networkpolicies {
		cfg := networkpolicy.Config{
			FailOpen:            true,
			QueueID:             102,
			NodeName:            nodeName,
			NFTableName:         "kindnet-network-policies",
			NetfilterBug1766Fix: true,
		}

		networkPolicyController, err := networkpolicy.NewController(
			clientset,
			informersFactory.Networking().V1().NetworkPolicies(),
			informersFactory.Core().V1().Namespaces(),
			informersFactory.Core().V1().Pods(),
			nodeInformer,
			nil,
			nil,
			nil,
			cfg)
		if err != nil {
			klog.Infof("Error creating network policy controller: %v, skipping network policies", err)
		} else {
			go func() {
				_ = networkPolicyController.Run(ctx)
			}()
		}
	}
	// main control loop
	informersFactory.Start(ctx.Done())

	for {
		// Gets the Nodes information from the API
		// TODO: use a proper controller instead
		var nodes []*corev1.Node
		var err error
		for i := 0; i < 5; i++ {
			nodes, err = nodeLister.List(labels.Everything())
			if err == nil {
				break
			}
			klog.Infof("Failed to get nodes, retrying after error: %v", err)
			time.Sleep(time.Second * time.Duration(i))
		}
		if err != nil {
			panic("Reached maximum retries obtaining node list: " + err.Error())
		}

		// reconcile the nodes with retries
		for i := 0; i < 5; i++ {
			err = reconcileNodes(nodes)
			if err == nil {
				break
			}
			klog.Infof("Failed to reconcile routes, retrying after error: %v", err)
			time.Sleep(time.Second * time.Duration(i))
		}
		if err != nil {
			panic("Maximum retries reconciling node routes: " + err.Error())
		}

		// disable offload if required
		if disableOffload {
			err = SetChecksumOffloading("kind-br", false, false)
			if err != nil {
				klog.Infof("Failed to disable offloading on interface kind-br: %v", err)
			} else {
				disableOffload = false
			}
		}

		// rate limit
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(10 * time.Second)
		}
	}
}

// nodeNodesReconciler returns a reconciliation func for nodes
func makeNodesReconciler(cniConfig *CNIConfigWriter, hostIP string) func([]*corev1.Node) error {
	// reconciles a node
	reconcileNode := func(node *corev1.Node) error {
		// first get this node's IPs
		// we don't support more than one IP address per IP family for simplification
		nodeIPs := internalIPs(node)
		klog.Infof("Handling node with IPs: %v\n", nodeIPs)
		// This is our node. We don't need to add routes, but we might need to
		// update the cni config and "annotate" our external IPs
		if nodeIPs.Has(hostIP) {
			klog.Info("handling current node\n")
			// compute the current cni config inputs
			if err := cniConfig.Write(
				ComputeCNIConfigInputs(node),
			); err != nil {
				return err
			}
			// we're done handling this node
			return nil
		}

		podCIDRs := node.Spec.PodCIDRs
		if len(podCIDRs) == 0 {
			fmt.Printf("Node %v has no CIDR, ignoring\n", node.Name)
			return nil
		}
		klog.Infof("Node %v has CIDR %s \n", node.Name, podCIDRs)
		podCIDRsv4, podCIDRsv6 := splitCIDRslice(podCIDRs)

		// obtain the PodCIDR gateway
		var nodeIPv4, nodeIPv6 string
		for _, ip := range nodeIPs.UnsortedList() {
			if isIPv6String(ip) {
				nodeIPv6 = ip
			} else {
				nodeIPv4 = ip
			}
		}

		if nodeIPv4 != "" && len(podCIDRsv4) > 0 {
			if err := syncRoute(nodeIPv4, podCIDRsv4); err != nil {
				return err
			}
		}
		if nodeIPv6 != "" && len(podCIDRsv6) > 0 {
			if err := syncRoute(nodeIPv6, podCIDRsv6); err != nil {
				return err
			}
		}
		return nil
	}

	// return a reconciler for all the nodes
	return func(nodes []*corev1.Node) error {
		for _, node := range nodes {
			if err := reconcileNode(node); err != nil {
				return err
			}
		}
		return nil
	}
}

// internalIPs returns the internal IP address for node
func internalIPs(node *corev1.Node) sets.Set[string] {
	ips := sets.New[string]()
	// check the node.Status.Addresses
	for _, address := range node.Status.Addresses {
		if address.Type == "InternalIP" {
			ips.Insert(address.Address)
		}
	}
	return ips
}

// isIPv6String returns if ip is IPv6.
func isIPv6String(ip string) bool {
	netIP := net.ParseIP(ip)
	return netIP != nil && netIP.To4() == nil
}
