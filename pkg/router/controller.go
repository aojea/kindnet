package router

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

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

const controllerName = "router"

type Controller struct {
	nodeName string

	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	workqueue workqueue.RateLimitingInterface

	nodeLister  corelisters.NodeLister
	nodesSynced cache.InformerSynced
}

func New(nodeName string, client clientset.Interface, nodeInformer coreinformers.NodeInformer) *Controller {
	klog.V(2).Info("Creating router controller")

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
			// don't process our own node
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

func (c *Controller) enqueueNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}
	// don't process our own node
	if c.nodeName == node.Name {
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
			// Node has been deleted
			return nil
		}
		return err
	}

	return syncRoutes(node)
}

func syncRoutes(node *v1.Node) error {
	nodeIPs, err := GetNodeHostIPs(node)
	if err != nil {
		return err
	}

	for _, nodeIP := range nodeIPs {
		for _, podCIDR := range node.Spec.PodCIDRs {
			// parse subnet
			dst, err := netlink.ParseIPNet(podCIDR)
			if err != nil {
				return err
			}

			if netutils.IsIPv6(nodeIP) != netutils.IsIPv6CIDR(dst) {
				// skip different IP families
				continue
			}

			// Check if the route exists to the other node's PodCIDR
			routeToDst := netlink.Route{Dst: dst, Gw: nodeIP}
			route, err := netlink.RouteListFiltered(nl.GetIPFamily(nodeIP), &routeToDst, netlink.RT_FILTER_DST)
			if err != nil {
				return err
			}

			// Add route if not present
			if len(route) == 0 {
				klog.Infof("Adding route %v \n", routeToDst)
				if err := netlink.RouteAdd(&routeToDst); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func deleteRoutes(node *v1.Node) error {
	nodeIPs, err := GetNodeHostIPs(node)
	if err != nil {
		return err
	}

	for _, nodeIP := range nodeIPs {
		for _, podCIDR := range node.Spec.PodCIDRs {
			// parse subnet
			dst, err := netlink.ParseIPNet(podCIDR)
			if err != nil {
				return err
			}
			if netutils.IsIPv6(nodeIP) != netutils.IsIPv6CIDR(dst) {
				// skip different IP families
				continue
			}

			// Check if the route exists to the other node's PodCIDR
			routeToDst := netlink.Route{Dst: dst, Gw: nodeIP}
			route, err := netlink.RouteListFiltered(nl.GetIPFamily(nodeIP), &routeToDst, netlink.RT_FILTER_DST)
			if err != nil {
				return err
			}

			// Remove route if exist
			if len(route) > 0 {
				klog.Infof("Removing route %v \n", routeToDst)
				if err := netlink.RouteDel(&routeToDst); err != nil {
					return err
				}
			}
		}
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
