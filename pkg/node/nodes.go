// SPDX-License-Identifier: APACHE-2.0

package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
)

type NodeController struct {
	nodeName string

	client    clientset.Interface
	workqueue workqueue.TypedRateLimitingInterface[string]

	nodeLister  corelisters.NodeLister
	nodesSynced cache.InformerSynced

	cniDone      bool
	providerDone bool
}

func NewNodeController(nodeName string, client clientset.Interface, nodeInformer coreinformers.NodeInformer) *NodeController {
	klog.V(2).Info("Creating routes controller")

	c := &NodeController{
		nodeName:    nodeName,
		client:      client,
		nodeLister:  nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,
		workqueue:   workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}
	_, err := nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueNode,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueNode(new)
		},
		// handle the delete logic here to have access to the object node.spec.PodCIDRs
		// so we don't have to cache those values.
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*v1.Node)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				node, ok = tombstone.Obj.(*v1.Node)
				if !ok {
					return
				}
			}
			// don't process our own node on deletion
			if c.nodeName == node.Name {
				return
			}
			err := deleteRoutes(node)
			if err != nil {
				klog.Infof("unexpected error deleting routes for node %s : %v", node.Name, err)
			}
		},
	})
	if err != nil {
		klog.Infof("unexpected error adding event handler to informer: %v", err)
	}
	return c
}

func (c *NodeController) enqueueNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
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

func (c *NodeController) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()
	logger := klog.FromContext(ctx)

	// Start the informer factories to begin populating the informer caches
	logger.Info("Starting router controller")

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

func (c *NodeController) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *NodeController) processNextWorkItem(ctx context.Context) bool {
	key, shutdown := c.workqueue.Get()
	if shutdown {
		return false
	}
	defer c.workqueue.Done(key)

	err := c.syncNode(ctx, key)
	c.handleErr(err, key)
	return true
}

func (c *NodeController) handleErr(err error, key string) {
	if err == nil {
		c.workqueue.Forget(key)
		return
	}

	if c.workqueue.NumRequeues(key) < 15 {
		klog.Infof("Error syncing node %s, retrying: %v", key, err)
		c.workqueue.AddRateLimited(key)
		return
	}

	c.workqueue.Forget(key)
	utilruntime.HandleError(err)
	klog.Infof("Dropping node %q out of the queue: %v", key, err)
}

func (c *NodeController) syncNode(ctx context.Context, key string) error {
	node, err := c.nodeLister.Get(key)
	if err != nil {
		if apierrors.IsNotFound(err) {
			// Node has been deleted it should be processed in the Delete hook
			return nil
		}
		return err
	}

	// if is a different node sync the routes
	if node.Name != c.nodeName {
		return syncRoute(node)
	}
	// compute the current cni config inputs for our own node
	if len(node.Spec.PodCIDRs) > 0 && !c.cniDone {
		err := WriteCNIConfig(node.Spec.PodCIDRs)
		if err != nil {
			return err
		}
		klog.Infof("CNI config file succesfully written")
		c.cniDone = true
	}
	// cloud provider specific changes required to the node

	// AWS requires to disable the source destination check
	// to allow traffic between Pods
	if strings.Contains(node.Spec.ProviderID, "aws") && !c.providerDone {
		klog.Infof("detected cloud provider: AWS")
		err := disableAWSSrcDstCheck()
		if err != nil {
			return err
		}
		klog.Infof("AWS SourceDestCheck disabled")
		c.providerDone = true
	}
	return nil
}

// GetNodeHostIPs returns the provided node's IP(s); either a single "primary IP" for the
// node in a single-stack cluster, or a dual-stack pair of IPs in a dual-stack cluster
// (for nodes that actually have dual-stack IPs). Among other things, the IPs returned
// from this function are used as the `.status.PodIPs` values for host-network pods on the
// node, and the first IP is used as the `.status.HostIP` for all pods on the node.
// https://github.com/kubernetes/kubernetes/blob/971477d9b5cc4bf5ae62abe3bbc46e534f481e1b/pkg/util/node/node.go
func GetNodeHostIPs(node *v1.Node) ([]net.IP, error) {
	// Re-sort the addresses with InternalIPs first and then ExternalIPs
	allIPs := make([]net.IP, 0, len(node.Status.Addresses))
	for _, addr := range node.Status.Addresses {
		if addr.Type == v1.NodeInternalIP {
			ip := net.ParseIP(addr.Address)
			if ip != nil {
				allIPs = append(allIPs, ip)
			}
		}
	}
	for _, addr := range node.Status.Addresses {
		if addr.Type == v1.NodeExternalIP {
			ip := net.ParseIP(addr.Address)
			if ip != nil {
				allIPs = append(allIPs, ip)
			}
		}
	}
	if len(allIPs) == 0 {
		return nil, fmt.Errorf("host IP unknown; known addresses: %v", node.Status.Addresses)
	}

	nodeIPs := []net.IP{allIPs[0]}
	for _, ip := range allIPs {
		if netutils.IsIPv6(ip) != netutils.IsIPv6(nodeIPs[0]) {
			nodeIPs = append(nodeIPs, ip)
			break
		}
	}

	return nodeIPs, nil
}
