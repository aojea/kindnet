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

package node

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

func getPodsIPs() (map[string][]string, error) {
	client, err := getRuntimeService(5 * time.Second)
	if err != nil {
		return nil, err
	}
	sandboxes, err := client.ListPodSandbox(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	result := map[string][]string{}
	for _, sandbox := range sandboxes {
		status, err := client.PodSandboxStatus(context.Background(), sandbox.Id, false)
		if err != nil {
			return nil, err
		}

		ips := sets.Set[string]{}
		if len(status.Status.Network.Ip) > 0 {
			ips.Insert(status.Status.Network.Ip)
		}
		for _, podip := range status.Status.Network.AdditionalIps {
			if len(podip.String()) > 0 {
				ips.Insert(podip.String())
			}
		}
		if ips.Len() > 0 {
			result[sandbox.Id] = ips.UnsortedList()
		}
	}
	return result, nil
}
