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

package cni

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"text/template"
	"time"

	utilnet "github.com/aojea/kindnet/pkg/net"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

// cniConfigPath is where kindnetd will write the computed CNI config
const CNIConfigPath = "/etc/cni/net.d/10-kindnet.conflist"

/* cni config management */

// CNIConfigInputs is supplied to the CNI config template
type CNIConfigInputs struct {
	PodCIDRs      []string
	DefaultRoutes []string
	Mtu           int
}

const controllerName = "router"

type Controller struct {
	nodeName string

	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	workqueue workqueue.RateLimitingInterface

	nodeLister  corelisters.NodeLister
	nodesSynced cache.InformerSynced

	configWriter *CNIConfigWriter
}

// TODO add fsnotify watcher to detect external changes on the CNI config file
func New(nodeName string, client clientset.Interface, nodeInformer coreinformers.NodeInformer, ipFamily int) *Controller {
	klog.V(2).Info("Creating CNI config controller")

	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	c := &Controller{
		nodeName:         nodeName,
		client:           client,
		nodeLister:       nodeInformer.Lister(),
		nodesSynced:      nodeInformer.Informer().HasSynced,
		workqueue:        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), controllerName),
		eventBroadcaster: broadcaster,
		eventRecorder:    recorder,
	}
	_, err := nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueNode,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueNode(new)
		},
		DeleteFunc: c.enqueueNode,
	})
	if err != nil {
		klog.Infof("unexpected error adding event handler to informer: %v", err)
	}

	mtu, err := utilnet.GetMTU(ipFamily)
	klog.Infof("setting mtu %d for CNI \n", mtu)
	if err != nil {
		klog.Infof("Failed to get MTU size from the default gateway interface, using kernel default MTU size , error: %v", err)
	}

	// used to track if the cni config inputs changed and write the config
	c.configWriter = &CNIConfigWriter{
		Path: CNIConfigPath,
		MTU:  mtu,
	}
	klog.Infof("Configuring CNI path: %s  mtu: %d", CNIConfigPath, mtu)

	return c
}

func (c *Controller) enqueueNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}
	// process our own node only
	if c.nodeName != node.Name {
		return
	}
	if len(node.Spec.PodCIDRs) == 0 {
		klog.Infof("Node %s has no CIDR, ignoring\n", node.Name)
		return
	}
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.Add(key)
}

func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()
	logger := klog.FromContext(ctx)

	// Start the informer factories to begin populating the informer caches
	logger.Info("Starting CNI controller")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	if ok := cache.WaitForCacheSync(ctx.Done(), c.nodesSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	logger.Info("Starting workers", "count", workers)
	// Launch two workers to process Foo resources
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	obj, shutdown := c.workqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(key string) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(key)
		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err := c.syncHandler(ctx, key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(key)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj.(string))

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

func (c *Controller) syncHandler(ctx context.Context, key string) error {
	node, err := c.nodeLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Node has been deleted, best effort to delete the CNI config fle
			err := os.Remove(CNIConfigPath)
			if err != nil {
				klog.Infof("node %s has been deleted, error deleting its CNI configuration: %v", node.Name, err)
			}
			return nil
		}
		return err
	}
	// compute the current cni config inputs
	err = c.configWriter.Write(
		ComputeCNIConfigInputs(node),
	)
	if err != nil {
		return err
	}
	return nil
}

// ComputeCNIConfigInputs computes the template inputs for CNIConfigWriter
func ComputeCNIConfigInputs(node *v1.Node) CNIConfigInputs {
	defaultRoutes := []string{"0.0.0.0/0", "::/0"}
	// check if is a dualstack cluster
	if len(node.Spec.PodCIDRs) > 1 {
		return CNIConfigInputs{
			PodCIDRs:      node.Spec.PodCIDRs,
			DefaultRoutes: defaultRoutes,
		}
	}
	// the cluster is single stack
	// we use the legacy node.Spec.PodCIDR for backwards compatibility
	podCIDRs := []string{node.Spec.PodCIDR}
	// This is a single stack cluster
	defaultRoute := defaultRoutes[:1]
	if netutils.IsIPv6CIDRString(podCIDRs[0]) {
		defaultRoute = defaultRoutes[1:]
	}
	return CNIConfigInputs{
		PodCIDRs:      podCIDRs,
		DefaultRoutes: defaultRoute,
	}
}

const cniConfigTemplate = `
{
	"cniVersion": "0.4.0",
	"name": "kindnet",
	"plugins": [
	{
		"type": "ptp",
		"ipMasq": false,
		"ipam": {
			"type": "host-local",
			"dataDir": "/run/cni-ipam-state",
			"routes": [
				{{$first := true}}
				{{- range $route := .DefaultRoutes}}
				{{if $first}}{{$first = false}}{{else}},{{end}}
				{ "dst": "{{ $route }}" }
				{{- end}}
			],
			"ranges": [
				{{$first := true}}
				{{- range $cidr := .PodCIDRs}}
				{{if $first}}{{$first = false}}{{else}},{{end}}
				[ { "subnet": "{{ $cidr }}" } ]
				{{- end}}
			]
		}
		{{if .Mtu}},
		"mtu": {{ .Mtu }}
		{{end}}
	},
	{
		"type": "portmap",
		"capabilities": {
			"portMappings": true
		}
	}
	]
}
`

// CNIConfigWriter no-ops re-writing config with the same inputs
// NOTE: should only be called from a single goroutine
type CNIConfigWriter struct {
	Path       string
	lastInputs CNIConfigInputs
	MTU        int
	Bridge     bool
}

// Write will write the config based on
func (c *CNIConfigWriter) Write(inputs CNIConfigInputs) error {
	if reflect.DeepEqual(inputs, c.lastInputs) {
		return nil
	}

	// use an extension not recognized by CNI to write the contents initially
	// https://github.com/containerd/go-cni/blob/891c2a41e18144b2d7921f971d6c9789a68046b2/opts.go#L170
	// then we can rename to atomically make the file appear
	f, err := os.Create(c.Path + ".temp")
	if err != nil {
		return err
	}

	// actually write the config
	if err := writeCNIConfig(f, cniConfigTemplate, inputs); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}
	_ = f.Sync()
	_ = f.Close()

	// then we can rename to the target config path
	if err := os.Rename(f.Name(), c.Path); err != nil {
		return err
	}

	// we're safely done now, record the inputs
	c.lastInputs = inputs
	return nil
}

func writeCNIConfig(w io.Writer, rawTemplate string, data CNIConfigInputs) error {
	t, err := template.New("cni-json").Parse(rawTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse cni template: %w", err)
	}
	return t.Execute(w, &data)
}
