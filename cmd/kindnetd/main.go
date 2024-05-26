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
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"

	"github.com/aojea/kindnet/pkg/cni"
	"github.com/aojea/kindnet/pkg/router"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	nodeutil "k8s.io/component-helpers/node/util"
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
type IPFamily int

const (
	// Family type definitions
	AllFamily       IPFamily = unix.AF_UNSPEC
	IPv4Family      IPFamily = unix.AF_INET
	IPv6Family      IPFamily = unix.AF_INET6
	DualStackFamily IPFamily = unix.AF_UNSPEC
)

var (
	failOpen                   bool
	adminNetworkPolicy         bool // 	AdminNetworkPolicy is alpha so keep it feature gated behind a flag
	baselineAdminNetworkPolicy bool // 	BaselineAdminNetworkPolicy is alpha so keep it feature gated behind a flag
	queueID                    int
	metricsBindAddress         string
	hostnameOverride           string
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running")
	flag.BoolVar(&adminNetworkPolicy, "admin-network-policy", false, "If set, enable Admin Network Policy API")
	flag.BoolVar(&baselineAdminNetworkPolicy, "baseline-admin-network-policy", false, "If set, enable Baseline Admin Network Policy API")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "The hostname of the node")

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

	hostname, err := nodeutil.GetHostname(hostnameOverride)
	if err != nil {
		panic(err.Error())
	}

	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
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

	// enforce ip masquerade rules
	noMaskIPv4Subnets, noMaskIPv6Subnets := getNoMasqueradeSubnets(clientset)
	// detect the cluster IP family based on the Cluster CIDR akka PodSubnet
	var ipFamily IPFamily
	switch {
	case len(noMaskIPv4Subnets) > 0 && len(noMaskIPv6Subnets) > 0:
		ipFamily = DualStackFamily
	case len(noMaskIPv6Subnets) > 0:
		ipFamily = IPv6Family
	case len(noMaskIPv4Subnets) > 0:
		ipFamily = IPv4Family
	default:
		panic("Cluster CIDR is not defined")
	}
	klog.Infof("kindnetd IP family: %q", ipFamily)

	// create an ipMasqAgent for IPv4
	if len(noMaskIPv4Subnets) > 0 {
		klog.Infof("noMask IPv4 subnets: %v", noMaskIPv4Subnets)
		masqAgentIPv4, err := NewIPMasqAgent(false, noMaskIPv4Subnets)
		if err != nil {
			panic(err.Error())
		}
		go func() {
			if err := masqAgentIPv4.SyncRulesForever(time.Second * 60); err != nil {
				panic(err)
			}
		}()
	}

	// create an ipMasqAgent for IPv6
	if len(noMaskIPv6Subnets) > 0 {
		klog.Infof("noMask IPv6 subnets: %v", noMaskIPv6Subnets)
		masqAgentIPv6, err := NewIPMasqAgent(true, noMaskIPv6Subnets)
		if err != nil {
			panic(err.Error())
		}

		go func() {
			if err := masqAgentIPv6.SyncRulesForever(time.Second * 60); err != nil {
				panic(err)
			}
		}()
	}

	// main control loop
	informersFactory.Start(ctx.Done())

	// CNI config controller
	go func() {
		err := cni.New(hostname, clientset, nodeInformer, int(ipFamily)).Run(ctx, 1)
		if err != nil {
			klog.Infof("error running router controller: %v", err)
		}
	}()

	// routes controller
	go func() {
		err := router.New(hostname, clientset, nodeInformer).Run(ctx, 5)
		if err != nil {
			klog.Infof("error running router controller: %v", err)
		}
	}()

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}
	// Time for gracefully shutdown
	time.Sleep(1 * time.Second)
}
