// SPDX-License-Identifier: APACHE-2.0

package multinetwork

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/vishvananda/netlink"
	"golang.org/x/time/rate"
	resourceapi "k8s.io/api/resource/v1beta1"
	resourcev1beta1 "k8s.io/api/resource/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
	drapb "k8s.io/kubelet/pkg/apis/dra/v1beta1"
)

const (
	driverName = "dra.kindnet.es"
	pluginIdx  = "10"
	// podUIDIndex is the lookup name for the most common index function, which is to index by the pod UID field.
	podUIDIndex               string = "podUID"
	kubeletPluginRegistryPath        = "/var/lib/kubelet/plugins_registry"
	kubeletPluginPath                = "/var/lib/kubelet/plugins"
	// interfaces poll period
	minInterval = 5 * time.Second
	maxInterval = 1 * time.Minute
)

// podUIDIndexFunc is a default index function that indexes based on an pod UID
func podUIDIndexFunc(obj interface{}) ([]string, error) {
	claim, ok := obj.(*resourcev1beta1.ResourceClaim)
	if !ok {
		return []string{}, nil
	}

	result := []string{}
	for _, reserved := range claim.Status.ReservedFor {
		if reserved.Resource != "pods" || reserved.APIGroup != "" {
			continue
		}
		result = append(result, string(reserved.UID))
	}
	return result, nil
}

var _ drapb.DRAPluginServer = &MultiNetworkAgent{}

func NewMultiNetworkAgent(client kubernetes.Interface, nodeName string) (*MultiNetworkAgent, error) {
	m := &MultiNetworkAgent{
		nodeName:    nodeName,
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Every(minInterval), 1),
		claimAllocations: cache.NewIndexer(cache.MetaNamespaceKeyFunc,
			cache.Indexers{
				cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
				podUIDIndex:          podUIDIndexFunc,
			}),
	}

	opts := []stub.Option{
		stub.WithPluginName(driverName),
		stub.WithPluginIdx(pluginIdx),
	}
	nriPlugin, err := stub.New(m, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create nri plugin nriPlugin: %w", err)
	}
	m.nriPlugin = nriPlugin
	return m, nil
}

type MultiNetworkAgent struct {
	nodeName         string
	client           kubernetes.Interface
	nriPlugin        stub.Stub
	draPlugin        kubeletplugin.DRAPlugin
	claimAllocations cache.Indexer // claims indexed by Claim UID to run on the Kubelet/DRA hooks
	rateLimiter      *rate.Limiter
}

func (m *MultiNetworkAgent) Run(ctx context.Context) error {
	// register the DRA driver
	pluginRegistrationPath := filepath.Join(kubeletPluginRegistryPath, driverName+".sock")
	driverPluginPath := filepath.Join(kubeletPluginPath, driverName)
	err := os.MkdirAll(driverPluginPath, 0750)
	if err != nil {
		return fmt.Errorf("failed to create plugin path %s: %v", driverPluginPath, err)
	}
	driverPluginSocketPath := filepath.Join(driverPluginPath, "/plugin.sock")

	kubeletOpts := []kubeletplugin.Option{
		kubeletplugin.DriverName(driverName),
		kubeletplugin.NodeName(m.nodeName),
		kubeletplugin.KubeClient(m.client),
		kubeletplugin.RegistrarSocketPath(pluginRegistrationPath),
		kubeletplugin.PluginSocketPath(driverPluginSocketPath),
		kubeletplugin.KubeletPluginSocketPath(driverPluginSocketPath),
	}
	d, err := kubeletplugin.Start(ctx, []any{m}, kubeletOpts...)
	if err != nil {
		return fmt.Errorf("fail to start kubelet plugin: %w", err)
	}
	m.draPlugin = d
	err = wait.PollUntilContextTimeout(ctx, 1*time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
		status := m.draPlugin.RegistrationStatus()
		if status == nil {
			return false, nil
		}
		return status.PluginRegistered, nil
	})
	if err != nil {
		return err
	}

	go func() {
		err = m.nriPlugin.Run(ctx)
		if err != nil {
			klog.Infof("NRI plugin failed with error %v", err)
		}
	}()

	m.PublishResources(ctx)
	return nil
}

func (m *MultiNetworkAgent) Synchronize(_ context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	klog.Infof("Synchronized state with the runtime (%d pods, %d containers)...",
		len(pods), len(containers))

	for _, pod := range pods {
		klog.V(2).Infof("pod %s/%s: namespace=%s ips=%v", pod.GetNamespace(), pod.GetName(), getNetworkNamespace(pod), pod.GetIps())
		// get the pod network namespace
		ns := getNetworkNamespace(pod)
		// host network pods are skipped
		if ns != "" {
			// store the Pod metadata in the db
		}
	}

	return nil, nil
}

func (m *MultiNetworkAgent) Shutdown(_ context.Context) {
	klog.Info("Runtime shutting down...")
}

func (m *MultiNetworkAgent) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	klog.V(2).Infof("RunPodSandbox Pod %s/%s UID %s", pod.Namespace, pod.Name, pod.Uid)
	objs, err := m.claimAllocations.ByIndex(podUIDIndex, pod.Uid)
	if err != nil || len(objs) == 0 {
		klog.V(4).Infof("RunPodSandbox Pod %s/%s does not have an associated ResourceClaim", pod.Namespace, pod.Name)
		return nil
	}

	// get the pod network namespace
	ns := getNetworkNamespace(pod)
	// host network pods are skipped
	if ns == "" {
		klog.V(2).Infof("RunPodSandbox pod %s/%s using host network, skipping", pod.Namespace, pod.Name)
		return nil
	}

	// Process the configurations of the ResourceClaim
	for _, obj := range objs {
		claim, ok := obj.(*resourcev1beta1.ResourceClaim)
		if !ok {
			continue
		}

		if claim.Status.Allocation == nil {
			continue
		}
		for _, result := range claim.Status.Allocation.Devices.Results {
			if result.Driver != driverName {
				continue
			}

			// Process the configurations of the ResourceClaim
			for _, config := range claim.Status.Allocation.Devices.Config {
				if config.Opaque == nil {
					continue
				}
				if len(config.Requests) > 0 && !slices.Contains(config.Requests, result.Request) {
					continue
				}
				netconf, err := ValidateConfig(&config.Opaque.Parameters)
				if err != nil {
					return err
				}
				klog.V(4).Infof("podStartHook Configuration %#v", netconf)
			}

			klog.V(2).Infof("RunPodSandbox allocation.Devices.Result: %#v", result)
			err := nsAttachNetdev(result.Device, ns, result.Device)
			if err != nil {
				klog.Infof("RunPodSandbox error moving device %s to namespace %s: %v", result.Device, ns, err)
				return err
			}
		}
	}
	return nil
}

func (m *MultiNetworkAgent) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	klog.V(2).Infof("StopPodSandbox pod %s/%s", pod.Namespace, pod.Name)
	objs, err := m.claimAllocations.ByIndex(podUIDIndex, pod.Uid)
	if err != nil || len(objs) == 0 {
		klog.V(2).Infof("StopPodSandbox pod %s/%s does not have allocations", pod.Namespace, pod.Name)
		return nil
	}

	// get the pod network namespace
	ns := getNetworkNamespace(pod)
	if ns == "" {
		klog.V(2).Infof("StopPodSandbox pod %s/%s using host network, skipping", pod.Namespace, pod.Name)
		return nil
	}
	// Process the configurations of the ResourceClaim
	for _, obj := range objs {
		claim, ok := obj.(*resourcev1beta1.ResourceClaim)
		if !ok {
			continue
		}

		if claim.Status.Allocation == nil {
			continue
		}

		for _, result := range claim.Status.Allocation.Devices.Results {
			if result.Driver != driverName {
				continue
			}

			for _, config := range claim.Status.Allocation.Devices.Config {
				if config.Opaque == nil {
					continue
				}
				klog.V(4).Infof("podStopHook Configuration %s", string(config.Opaque.Parameters.String()))
				// TODO get config options here, it can add ips or commands
				// to add routes, run dhcp, rename the interface ... whatever
			}

			klog.V(4).Infof("podStopHook Device %s", result.Device)
			// TODO config options to rename the device and pass parameters
			// use https://github.com/opencontainers/runtime-spec/pull/1271
			err := nsDetachNetdev(ns, result.Device)
			if err != nil {
				klog.Infof("RunPodSandbox error moving device %s to namespace %s: %v", result.Device, ns, err)
				continue
			}
		}
	}
	return nil
}

func (m *MultiNetworkAgent) RemovePodSandbox(_ context.Context, pod *api.PodSandbox) error {
	klog.V(2).Infof("RemovePodSandbox pod %s/%s: ips=%v", pod.GetNamespace(), pod.GetName(), pod.GetIps())
	// get the pod network namespace
	ns := getNetworkNamespace(pod)
	if ns == "" {
		klog.V(2).Infof("RemovePodSandbox pod %s/%s using host network, skipping", pod.Namespace, pod.Name)
		return nil
	}
	return nil
}

func (m *MultiNetworkAgent) PublishResources(ctx context.Context) {
	klog.V(2).Infof("Publishing resources")

	// the default gateway interface can only be used in trunk mode
	ifaceGateway := getDefaultGwInterfaceName()
	// Resources are published periodically or if there is a netlink notification
	// indicating a new interfaces was added or changed
	nlChannel := make(chan netlink.LinkUpdate)
	doneCh := make(chan struct{})
	defer close(doneCh)
	if err := netlink.LinkSubscribe(nlChannel, doneCh); err != nil {
		klog.Error(err, "error subscribing to netlink interfaces, only syncing periodically", "interval", maxInterval.String())
	}

	for {
		err := m.rateLimiter.Wait(ctx)
		if err != nil {
			klog.Error(err, "unexpected rate limited error trying to get system interfaces")
		}

		devices := []resourceapi.Device{}
		ifaces, err := net.Interfaces()
		if err != nil {
			klog.Error(err, "unexpected error trying to get system interfaces")
		}
		for _, iface := range ifaces {
			klog.V(7).InfoS("Checking network interface", "name", iface.Name)

			// skip loopback interfaces
			if iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			mode := HybridMode
			if iface.Name == ifaceGateway {
				mode = TrunkMode
			}

			// publish this network interface
			device, err := netdevToDRAdev(iface.Name, mode)
			if err != nil {
				klog.V(2).Infof("could not obtain attributes for iface %s : %v", iface.Name, err)
				continue
			}

			devices = append(devices, *device)
			klog.V(4).Infof("Found following network interface %s", iface.Name)
		}

		klog.V(4).Infof("Found %d devices", len(devices))
		if len(devices) > 0 {
			resources := kubeletplugin.Resources{
				Devices: devices,
			}
			err := m.draPlugin.PublishResources(ctx, resources)
			if err != nil {
				klog.Error(err, "unexpected error trying to publish resources")
			}
		}
		select {
		// trigger a reconcile
		case <-nlChannel:
			// drain the channel so we only sync once
			for len(nlChannel) > 0 {
				<-nlChannel
			}
		case <-time.After(maxInterval):
		case <-ctx.Done():
			return
		}
	}
}

// NodePrepareResources filter the Claim requested for this driver
func (m *MultiNetworkAgent) NodePrepareResources(ctx context.Context, request *drapb.NodePrepareResourcesRequest) (*drapb.NodePrepareResourcesResponse, error) {
	if request == nil {
		return nil, nil
	}
	resp := &drapb.NodePrepareResourcesResponse{
		Claims: make(map[string]*drapb.NodePrepareResourceResponse),
	}

	for _, claimReq := range request.GetClaims() {
		klog.V(2).Infof("NodePrepareResources: Claim Request %s/%s", claimReq.Namespace, claimReq.Name)
		devices, err := m.nodePrepareResource(ctx, claimReq)
		if err != nil {
			resp.Claims[claimReq.UID] = &drapb.NodePrepareResourceResponse{
				Error: err.Error(),
			}
		} else {
			r := &drapb.NodePrepareResourceResponse{}
			for _, device := range devices {
				pbDevice := &drapb.Device{
					PoolName:   device.PoolName,
					DeviceName: device.DeviceName,
				}
				r.Devices = append(r.Devices, pbDevice)
			}
			resp.Claims[claimReq.UID] = r
		}
	}
	return resp, nil
}

// TODO define better what is passed at the podStartHook
// Filter out the allocations not required for this Pod
func (m *MultiNetworkAgent) nodePrepareResource(ctx context.Context, claimReq *drapb.Claim) ([]drapb.Device, error) {
	// The plugin must retrieve the claim itself to get it in the version that it understands.
	claim, err := m.client.ResourceV1beta1().ResourceClaims(claimReq.Namespace).Get(ctx, claimReq.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("retrieve claim %s/%s: %w", claimReq.Namespace, claimReq.Name, err)
	}
	if claim.Status.Allocation == nil {
		return nil, fmt.Errorf("claim %s/%s not allocated", claimReq.Namespace, claimReq.Name)
	}
	if claim.UID != types.UID(claim.UID) {
		return nil, fmt.Errorf("claim %s/%s got replaced", claimReq.Namespace, claimReq.Name)
	}
	err = m.claimAllocations.Add(claim)
	if err != nil {
		return nil, fmt.Errorf("failed to add claim %s/%s to local cache: %w", claimReq.Namespace, claimReq.Name, err)
	}

	for _, reserved := range claim.Status.ReservedFor {
		if reserved.Resource != "pods" || reserved.APIGroup != "" {
			klog.Infof("Driver only supports Pods, unsupported reference %#v", reserved)
			continue
		}
	}

	var devices []drapb.Device
	for _, result := range claim.Status.Allocation.Devices.Results {
		requestName := result.Request
		for _, config := range claim.Status.Allocation.Devices.Config {
			if config.Opaque == nil ||
				config.Opaque.Driver != driverName ||
				len(config.Requests) > 0 && !slices.Contains(config.Requests, requestName) {
				continue
			}
			_, err := ValidateConfig(&config.Opaque.Parameters)
			if err != nil {
				return nil, err
			}

		}
		device := drapb.Device{
			PoolName:   result.Pool,
			DeviceName: result.Device,
		}
		devices = append(devices, device)
	}

	return devices, nil
}

func (m *MultiNetworkAgent) NodeUnprepareResources(ctx context.Context, request *drapb.NodeUnprepareResourcesRequest) (*drapb.NodeUnprepareResourcesResponse, error) {
	if request == nil {
		return nil, nil
	}
	resp := &drapb.NodeUnprepareResourcesResponse{
		Claims: make(map[string]*drapb.NodeUnprepareResourceResponse),
	}

	for _, claimReq := range request.Claims {
		err := m.nodeUnprepareResource(ctx, claimReq)
		if err != nil {
			klog.Infof("error unpreparing ressources for claim %s/%s : %v", claimReq.Namespace, claimReq.Name, err)
			resp.Claims[claimReq.UID] = &drapb.NodeUnprepareResourceResponse{
				Error: err.Error(),
			}
		} else {
			resp.Claims[claimReq.UID] = &drapb.NodeUnprepareResourceResponse{}
		}
	}
	return resp, nil
}

func (m *MultiNetworkAgent) nodeUnprepareResource(ctx context.Context, claimReq *drapb.Claim) error {
	objs, err := m.claimAllocations.ByIndex(cache.NamespaceIndex, fmt.Sprintf("%s/%s", claimReq.Namespace, claimReq.Name))
	if err != nil || len(objs) == 0 {
		klog.Infof("Claim %s/%s does not have an associated cached ResourceClaim: %v", claimReq.Namespace, claimReq.Name, err)
		return nil
	}

	for _, obj := range objs {
		claim, ok := obj.(*resourcev1beta1.ResourceClaim)
		if !ok {
			continue
		}
		defer func() {
			err := m.claimAllocations.Delete(obj)
			if err != nil {
				klog.Infof("Claim %s/%s can not be deleted from cache: %v", claimReq.Namespace, claimReq.Name, err)
			}
		}()

		if claim.Status.Allocation == nil {
			continue
		}

		for _, result := range claim.Status.Allocation.Devices.Results {
			if result.Driver != driverName {
				continue
			}

			for _, config := range claim.Status.Allocation.Devices.Config {
				if config.Opaque == nil {
					continue
				}
				klog.V(4).Infof("nodeUnprepareResource Configuration %s", string(config.Opaque.Parameters.String()))
				// TODO get config options here, it can add ips or commands
				// to add routes, run dhcp, rename the interface ... whatever
			}
			klog.Infof("nodeUnprepareResource claim %s/%s with allocation result %#v", claimReq.Namespace, claimReq.Name, result)

		}
	}
	return nil
}

func getNetworkNamespace(pod *api.PodSandbox) string {
	// get the pod network namespace
	for _, namespace := range pod.Linux.GetNamespaces() {
		if namespace.Type == "network" {
			return namespace.Path
		}
	}
	return ""
}

func podKey(pod *api.PodSandbox) string {
	return fmt.Sprintf("%s/%s", pod.GetNamespace(), pod.GetName())
}
