// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	internalapi "k8s.io/cri-api/pkg/apis"
	remote "k8s.io/cri-client/pkg"
	"k8s.io/klog/v2"
)

const (
	defaultCriConfigPath = "/etc/crictl.yaml"
)

var (
	defaultRuntimeEndpoints = []string{"unix:///run/containerd/containerd.sock", "unix:///run/crio/crio.sock", "unix:///var/run/cri-dockerd.sock"}

	RuntimeEndpoint string
)

func getRuntimeService(timeout time.Duration) (res internalapi.RuntimeService, err error) {
	logger := klog.Background()
	if RuntimeEndpoint == "" {
		for _, endPoint := range defaultRuntimeEndpoints {
			res, err = remote.NewRemoteRuntimeService(endPoint, timeout, nil, &logger)
			if err != nil {
				continue
			}
			RuntimeEndpoint = endPoint
			break
		}
		return res, err
	}
	return remote.NewRemoteRuntimeService(RuntimeEndpoint, timeout, nil, &logger)
}

func getPodsIPs() ([]string, error) {
	client, err := getRuntimeService(5 * time.Second)
	if err != nil {
		return nil, err
	}
	sandboxes, err := client.ListPodSandbox(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	ips := sets.Set[string]{}
	for _, sandbox := range sandboxes {
		status, err := client.PodSandboxStatus(context.Background(), sandbox.Id, false)
		if err != nil {
			return nil, err
		}
		ips.Insert(status.Status.Network.Ip)
		for _, podip := range status.Status.Network.AdditionalIps {
			ips.Insert(podip.String())
		}
	}
	return ips.UnsortedList(), nil
}
