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
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	nodeutil "k8s.io/component-helpers/node/util"
	"sigs.k8s.io/kube-network-policies/pkg/networkpolicy"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	_ "k8s.io/component-base/metrics/prometheus/clientgo" // load all the prometheus client-go plugin
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
	useBridge            bool
	networkpolicies      bool
	dnsCaching           bool
	nat64                bool
	hostnameOverride     string
	masquerading         bool
	noMasqueradeCIDRs    string
	controlPlaneEndpoint string
	metricsBindAddress   string
)

func init() {
	flag.BoolVar(&useBridge, "cni-bridge", false, "If set, enable the CNI bridge plugin (default is the ptp plugin)")
	flag.BoolVar(&networkpolicies, "network-policy", true, "If set, enable Network Policies (default true)")
	flag.BoolVar(&dnsCaching, "dns-caching", false, "If set, enable Kubernetes DNS caching (default false)")
	flag.BoolVar(&nat64, "nat64", true, "If set, enable NAT64 using the reserved prefix 64:ff9b::/96 on IPv6 only clusters (default true)")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "If non-empty, will be used as the name of the Node that kube-network-policies is running on. If unset, the node name is assumed to be the same as the node's hostname.")
	flag.BoolVar(&masquerading, "masquerading", true, "masquerade with the Node IP the cluster to external traffic (default true)")
	flag.StringVar(&noMasqueradeCIDRs, "no-masquerade-cidr", "", "Comma seperated list of CIDRs that will not be masqueraded.")
	flag.StringVar(&controlPlaneEndpoint, "control-plane-endpoint", "", "The URL of the control plane")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":19080", "The IP address and port for the metrics server to serve on")

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

	nodeName, err := nodeutil.GetHostname(hostnameOverride)
	if err != nil {
		panic(err.Error())
	}

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		err := http.ListenAndServe(metricsBindAddress, nil)
		utilruntime.HandleError(err)
	}()

	// add metrics
	registerMetrics()

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

	// override the internal apiserver endpoint to avoid
	// waiting for kube-proxy to install the services rules.
	// If the endpoint is not reachable, fallback the internal endpoint
	if controlPlaneEndpoint != "" {
		// check that the apiserver is reachable before continue
		// to fail fast and avoid waiting until the client operations timeout
		var ok bool
		for i := 0; i < 5; i++ {
			ok = checkHTTP(controlPlaneEndpoint)
			if ok {
				config.Host = controlPlaneEndpoint
				break
			}
			klog.Infof("apiserver not reachable, attempt %d ... retrying", i)
			time.Sleep(time.Second * time.Duration(i))
		}
	}

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

	// obtain the host and pod ip addresses
	hostIP, podIP := os.Getenv("HOST_IP"), os.Getenv("POD_IP")
	klog.Infof("hostIP = %s\npodIP = %s\n", hostIP, podIP)
	if hostIP != podIP {
		panic(fmt.Sprintf(
			"hostIP(= %q) != podIP(= %q) but must be running with host network: ",
			hostIP, podIP,
		))
	}

	ip, err := netip.ParseAddr(podIP)
	if err != nil {
		klog.Fatalf("can not parse ip %s : %v", podIP, err)
	}

	ipFamily := IPv4Family
	if ip.Is6() {
		ipFamily = IPv6Family
	}

	mtu, err := GetMTU(unix.AF_UNSPEC)
	klog.Infof("setting mtu %d for CNI \n", mtu)
	if err != nil {
		klog.Infof("Failed to get MTU size from interface eth0, using kernel default MTU size error:%v", err)
	}

	// CNI_BRIDGE env variable uses the CNI bridge plugin, defaults to ptp
	useBridge = useBridge || len(os.Getenv("CNI_BRIDGE")) > 0
	if useBridge {
		// disable offload if required
		if len(os.Getenv("DISABLE_CNI_BRIDGE_OFFLOAD")) > 0 {
			err = SetChecksumOffloading("kind-br", false, false)
			if err != nil {
				klog.Infof("Failed to disable offloading on interface kind-br: %v", err)
			}
		}
	}

	// used to track if the cni config inputs changed and write the config
	cniConfigWriter := &CNIConfigWriter{
		path:   cniConfigPath,
		bridge: useBridge,
		mtu:    mtu,
	}
	klog.Infof("Configuring CNI path: %s bridge: %v mtu: %d",
		cniConfigPath, useBridge, mtu)

	// node controller handles CNI config for our own node and routes to the others
	nodeController := NewNodeController(nodeName, clientset, nodeInformer, cniConfigWriter)
	go func() {
		err := nodeController.Run(ctx, 5)
		if err != nil {
			klog.Fatalf("error running routes controller: %v", err)
		}
	}()

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
	if nat64 && ipFamily == IPv6Family {
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
	if dnsCaching && ipFamily == IPv4Family {
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
	klog.Infof("Kindnetd started successfully")

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}
	// Time for gracefully shutdown
	time.Sleep(1 * time.Second)
}

func checkHTTP(address string) bool {
	klog.Infof("probe URL %s", address)
	tr := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second,
	}

	resp, err := client.Get(address + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		klog.Infof("error draining the body response: %v", err)
		return false
	}
	return true
}
