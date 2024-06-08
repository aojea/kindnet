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
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/nftables"

	"github.com/aojea/kindnet/pkg/apis"
	"github.com/aojea/kindnet/pkg/cni"
	"github.com/aojea/kindnet/pkg/dataplane"
	"github.com/aojea/kindnet/pkg/router"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	nodeutil "k8s.io/component-helpers/node/util"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
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

var (
	failOpen                   bool
	adminNetworkPolicy         bool // 	AdminNetworkPolicy is alpha so keep it feature gated behind a flag
	baselineAdminNetworkPolicy bool // 	BaselineAdminNetworkPolicy is alpha so keep it feature gated behind a flag
	queueID                    int
	metricsBindAddress         string
	hostnameOverride           string
	controlPlaneEndpoint       string
)

func init() {
	flag.BoolVar(&failOpen, "fail-open", false, "If set, don't drop packets if the controller is not running")
	flag.BoolVar(&adminNetworkPolicy, "admin-network-policy", false, "If set, enable Admin Network Policy API")
	flag.BoolVar(&baselineAdminNetworkPolicy, "baseline-admin-network-policy", false, "If set, enable Baseline Admin Network Policy API")
	flag.IntVar(&queueID, "nfqueue-id", 100, "Number of the nfqueue used")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9080", "The IP address and port for the metrics server to serve on")
	flag.StringVar(&hostnameOverride, "hostname-override", "", "The hostname of the node")
	flag.StringVar(&controlPlaneEndpoint, "control-plane-endpoint", "", "The URL of the control plane")

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
		log.Printf("FLAG: --%s=%q", flag.Name, flag.Value)
	})

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

	// obtain the host and pod ip addresses
	hostIP, podIP := os.Getenv("HOST_IP"), os.Getenv("POD_IP")
	klog.Infof("hostIP = %s\npodIP = %s\n", hostIP, podIP)
	if hostIP != podIP {
		panic(fmt.Sprintf(
			"hostIP(= %q) != podIP(= %q) but must be running with host network: ",
			hostIP, podIP,
		))
	}

	hostname, err := nodeutil.GetHostname(hostnameOverride)
	if err != nil {
		panic(err.Error())
	}

	// create a nftables connection
	nft, err := nftables.New(nftables.AsLasting())
	if err != nil {
		panic(err.Error())
	}
	defer nft.CloseLasting() // nolint: errcheck

	// Create kindnet table if does not exist
	klog.Infof("Creating nftables Table %v", apis.KindnetTable)
	_ = nft.AddTable(apis.KindnetTable)
	err = nft.Flush()
	if err != nil {
		panic(err.Error())
	}

	// create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	config.UserAgent = "kindnet"

	// use protobuf for better performance at scale
	// https://kubernetes.io/docs/reference/using-api/api-concepts/#alternate-representations-of-resources
	// npaConfig := config // shallow copy because  CRDs does not support proto
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
	// create the clientset to connect the apiserver
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	klog.Infof("client connecting to apiserver: %s", config.Host)
	informersFactory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := informersFactory.Core().V1().Nodes()
	serviceInformer := informersFactory.Core().V1().Services()

	// detect the cluster primary IP family
	ipFamily := apis.IPv6Family
	if netutils.IsIPv4String(hostIP) {
		ipFamily = apis.IPv4Family
	}
	klog.Infof("kindnetd Primary IP family: %q", ipFamily)

	// CNI config controller
	cniController := cni.New(hostname, clientset, nodeInformer, int(ipFamily))
	go func() {
		err := cniController.Run(ctx, 1)
		if err != nil {
			klog.Infof("error running router controller: %v", err)
		}
	}()

	// routes controller
	routerController := router.New(hostname, clientset, nodeInformer)
	go func() {
		err := routerController.Run(ctx, 5)
		if err != nil {
			klog.Infof("error running router controller: %v", err)
		}
	}()

	// dataplane controller
	nftController, err := dataplane.New(hostname, nft, clientset, nodeInformer, serviceInformer, ipFamily)
	if err != nil {
		panic(err.Error())
	}

	go func() {
		err := nftController.Run(ctx, 1)
		if err != nil {
			klog.Infof("error running router controller: %v", err)
		}
	}()

	// main control loop
	klog.Infof("Starting informers")
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
