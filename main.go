/*
Copyright 2016 The Kubernetes Authors.

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

// Note: the example only works with the code within the same release/branch.
package main

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	// initates the loop
	for {
		// Gets the Nodes information from the API
		nodes, err := clientset.CoreV1().Nodes().List(metav1.ListOptions{})
		if err != nil {
			panic(err.Error())
		}
		fmt.Printf("There are %d nodes in the cluster\n", len(nodes.Items))

		// Iterate over all the nodes information
		for _, node := range nodes.Items {
			var nodeIP string

			// Obtain node internal IP
			// TODO check if we need to add more sanity checks
			// current we asume the ip exists
			for _, address := range node.Status.Addresses {
				if address.Type == "InternalIP" {
					nodeIP = address.Address
				}
			}
			ip := net.ParseIP(nodeIP)

			// Obtain Pod Subnet
			if node.Spec.PodCIDR == "" {
				fmt.Printf("Node %v has no CIDR, ignoring", node.Name)
				continue
			}
			dst, err := netlink.ParseIPNet(node.Spec.PodCIDR)
			if err != nil {
				panic(err.Error())
			}
			fmt.Printf("Node %v has CIDR %s",
				node.Name, node.Spec.PodCIDR)

			// Add the route to the system
			routeToDst, err := netlink.RouteGet(dst.IP)
			if err != nil {
				panic(err.Error())
			}
			// Add route if not present
			if len(routeToDst) == 0 {
				route := netlink.Route{Dst: dst, Src: ip}
				if err := netlink.RouteAdd(&route); err != nil {
					panic(err.Error())
				}
			}

		}

		// Writes the routes to the Pod Subnets in other nodes

		// Sleep
		time.Sleep(10 * time.Second)
	}
}
