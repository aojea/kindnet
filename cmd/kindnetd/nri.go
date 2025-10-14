
package main

import (
	"context"
	"fmt"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"k8s.io/klog/v2"
)

const (
	pluginName = "kindnet"
	pluginIdx  = "10"
)

type nriPlugin struct {
	stub stub.Stub
}

func NewNriPlugin() (*nriPlugin, error) {
	p := &nriPlugin{}
	opts := []stub.Option{
		stub.WithOnClose(p.onClose),
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
	}
	stub, err := stub.New(p, opts...)
	if err != nil {
		return p, fmt.Errorf("failed to create plugin stub: %w", err)
	}
	p.stub = stub
	return p, nil
}

func (p *nriPlugin) Run(ctx context.Context) error {
	return p.stub.Run(ctx)
}

func (p *nriPlugin) Synchronize(_ context.Context, pods []*nriapi.PodSandbox, containers []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	klog.Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))

	for _, pod := range pods {
		klog.Infof("pod %s/%s: namespace=%s ips=%v", pod.GetNamespace(), pod.GetName(), getNetworkNamespace(pod), pod.GetIps())
	}

	return nil, nil
}

func (p *nriPlugin) Shutdown(_ context.Context) {
	klog.Info("Runtime shutting down...")
}

func (p *nriPlugin) RunPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	klog.Infof("Started pod %s/%s: namespace=%s ips=%v", pod.GetNamespace(), pod.GetName(), getNetworkNamespace(pod), pod.GetIps())
	return nil
}

func (p *nriPlugin) StopPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	klog.Infof("Stopped pod %s/%s: ips=%v", pod.GetNamespace(), pod.GetName(), pod.GetIps())
	return nil
}

func (p *nriPlugin) RemovePodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	klog.Infof("Removed pod %s/%s: ips=%v", pod.GetNamespace(), pod.GetName(), pod.GetIps())
	return nil
}

func (p *nriPlugin) onClose() {
	klog.Infof("Connection to the runtime lost, exiting...")
}

func getNetworkNamespace(pod *nriapi.PodSandbox) string {
	// get the pod network namespace
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}
	return "<host-network>"
}
