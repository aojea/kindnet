package services

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	discoveryinformers "k8s.io/client-go/informers/discovery/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	discoverylisters "k8s.io/client-go/listers/discovery/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	// maxRetries is the number of times a object will be retried before it is dropped out of the queue.
	// With the current rate-limiter in use (5ms*2^(maxRetries-1)) the following numbers represent the
	// sequence of delays between successive queuings of an object.
	//
	// 5ms, 10ms, 20ms, 40ms, 80ms, 160ms, 320ms, 640ms, 1.3s, 2.6s, 5.1s, 10.2s, 20.4s, 41s, 82s
	maxRetries = 15

	controllerName = "kubernetes-services-controller"
)

// NewController returns a new *Controller.
func NewController(client clientset.Interface,
	serviceInformer coreinformers.ServiceInformer,
	endpointSliceInformer discoveryinformers.EndpointSliceInformer,
	loadBalancer LoadBalancer,
) *Controller {
	klog.V(4).Info("Creating event broadcaster")
	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	st := newServiceTracker()

	c := &Controller{
		client:           client,
		serviceTracker:   st,
		loadBalancer:     loadBalancer,
		queue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), controllerName),
		workerLoopPeriod: time.Second,
	}

	// services
	klog.Info("Setting up event handlers for services")
	serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onServiceAdd,
		UpdateFunc: c.onServiceUpdate,
		DeleteFunc: c.onServiceDelete,
	})
	c.serviceLister = serviceInformer.Lister()
	c.servicesSynced = serviceInformer.Informer().HasSynced

	// endpoints slices
	klog.Info("Setting up event handlers for endpoint slices")
	endpointSliceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onEndpointSliceAdd,
		UpdateFunc: c.onEndpointSliceUpdate,
		DeleteFunc: c.onEndpointSliceDelete,
	})

	c.endpointSliceLister = endpointSliceInformer.Lister()
	c.endpointSlicesSynced = endpointSliceInformer.Informer().HasSynced

	c.eventBroadcaster = broadcaster
	c.eventRecorder = recorder

	return c
}

// Controller manages selector-based service endpoints.
type Controller struct {
	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	// serviceTrack tracks services and map them to real LoadBalancers
	serviceTracker *serviceTracker

	// loadBalancer is the interface that implements the data-plane loadbalancer
	loadBalancer LoadBalancer

	// serviceLister is able to list/get services and is populated by the shared informer passed to
	serviceLister corelisters.ServiceLister
	// servicesSynced returns true if the service shared informer has been synced at least once.
	servicesSynced cache.InformerSynced

	// endpointSliceLister is able to list/get endpoint slices and is populated
	// by the shared informer passed to NewController
	endpointSliceLister discoverylisters.EndpointSliceLister
	// endpointSlicesSynced returns true if the endpoint slice shared informer
	// has been synced at least once. Added as a member to the struct to allow
	// injection for testing.
	endpointSlicesSynced cache.InformerSynced

	// Services that need to be updated. A channel is inappropriate here,
	// because it allows services with lots of pods to be serviced much
	// more often than services with few pods; it also would cause a
	// service that's inserted multiple times to be processed more than
	// necessary.
	queue workqueue.RateLimitingInterface

	// workerLoopPeriod is the time between worker runs. The workers process the queue of service and pod changes.
	workerLoopPeriod time.Duration
}

// Run will not return until stopCh is closed. workers determines how many
// endpoints will be handled in parallel.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.queue.ShutDown()

	klog.Infof("Starting controller %s", controllerName)
	defer klog.Infof("Shutting down controller %s", controllerName)

	// Wait for the caches to be synced
	klog.Info("Waiting for informer caches to sync")
	if !cache.WaitForNamedCacheSync(controllerName, ctx.Done(), c.servicesSynced, c.endpointSlicesSynced) {
		return fmt.Errorf("error syncing cache")
	}

	// Start the workers after the repair loop to avoid races
	klog.Info("Starting workers")
	for i := 0; i < workers; i++ {
		go wait.Until(c.worker, c.workerLoopPeriod, ctx.Done())
	}

	<-ctx.Done()
	return nil
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done. You may run as many of these in parallel as you wish; the
// workqueue guarantees that they will not end up processing the same service
// at the same time.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	eKey, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(eKey)

	err := c.syncServices(eKey.(string))
	c.handleErr(err, eKey)

	return true
}

func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	ns, name, keyErr := cache.SplitMetaNamespaceKey(key.(string))
	if keyErr != nil {
		klog.ErrorS(err, "Failed to split meta namespace cache key", "key", key)
	}
	metricRequeueServiceCount.WithLabelValues(key.(string)).Inc()

	if c.queue.NumRequeues(key) < maxRetries {
		klog.V(2).InfoS("Error syncing service, retrying", "service", klog.KRef(ns, name), "err", err)
		c.queue.AddRateLimited(key)
		return
	}

	klog.Warningf("Dropping service %q out of the queue: %v", key, err)
	c.queue.Forget(key)
	utilruntime.HandleError(err)
}

func (c *Controller) syncServices(key string) error {
	startTime := time.Now()
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	klog.Infof("Processing sync for service %s on namespace %s ", name, namespace)
	metricSyncServiceCount.WithLabelValues(key).Inc()

	defer func() {
		klog.V(4).Infof("Finished syncing service %s on namespace %s : %v", name, namespace, time.Since(startTime))
		metricSyncServiceLatency.WithLabelValues(key).Observe(time.Since(startTime).Seconds())
	}()

	// Get current Service from the cache
	service, err := c.serviceLister.Services(namespace).Get(name)
	// It´s unlikely that we have an error different that "Not Found Object"
	// because we are getting the object from the informer´s cache
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	// Get current state of the Service from the Service tracker
	// These are the VIPs (ClusterIP:Port) that we have seen so far
	// If the Service has updated the VIPs (has changed the Ports)
	// and some were removed we have to delete those
	// We need to create a map to not mutate the service tracker VIPs
	vipsTracked := sets.NewString().Union(c.serviceTracker.getService(name, namespace))
	// Delete the Service ClusterIPs from the dataplane
	// - the Service was deleted from the cache (doesn't exist in Kubernetes anymore)
	// - the Service mutated to a new service Type that we don't handle (ExternalName, Headless)
	if err != nil || !isIPService(service) {
		// delete all the VIPs from the dataplane
		for vipKey := range vipsTracked {
			vip, proto := splitVirtualIPKey(vipKey)
			err := c.loadBalancer.Remove(LB{
				Frontend: VirtualIP{
					vip:      vip,
					protocol: proto,
				},
			})
			if err != nil {
				return err
			}
			c.serviceTracker.deleteServiceVIP(name, namespace, vip, proto)
		}
		// Delete the Service form the Service Tracker
		c.serviceTracker.deleteService(name, namespace)
		return nil
	}
	klog.Infof("Creating service %s on namespace %s", name, namespace)
	// The Service exists in the cache: update it in OVN
	// Get the endpoint slices associated to the Service
	esLabelSelector := labels.Set(map[string]string{
		discovery.LabelServiceName: name,
	}).AsSelectorPreValidated()
	endpointSlices, err := c.endpointSliceLister.EndpointSlices(namespace).List(esLabelSelector)
	if err != nil {
		// Since we're getting stuff from a local cache, it is basically impossible to get this error.
		c.eventRecorder.Eventf(service, v1.EventTypeWarning, "FailedToListEndpointSlices",
			"Error listing Endpoint Slices for Service %s/%s: %v", namespace, name, err)
		return err
	}

	// Iterate over the ClusterIPs and Ports fields
	for _, ip := range getClusterIPs(service) {
		family := v1.IPv4Protocol
		if utilnet.IsIPv6String(ip) {
			family = v1.IPv6Protocol
		}
		for _, svcPort := range service.Spec.Ports {
			// ClusterIP
			// create the vip = ClusterIP:Port
			vip := net.JoinHostPort(ip, strconv.Itoa(int(svcPort.Port)))
			klog.V(4).Infof("Updating service %s/%s with VIP %s %s", name, namespace, vip, svcPort.Protocol)
			// get the endpoints associated to the vip
			eps := getLbEndpoints(endpointSlices, svcPort, family)
			klog.Infof("ClusterIP %s has endpoints: %v", ip, eps)
			err := c.loadBalancer.Apply(LB{
				Frontend: VirtualIP{
					vip:      vip,
					protocol: svcPort.Protocol,
				},
				Backend: eps,
			})
			if err != nil {
				return err
			}
			// update the tracker with the VIP
			c.serviceTracker.updateService(name, namespace, vip, svcPort.Protocol)
			// mark the vip as processed
			vipsTracked.Delete(virtualIPKey(vip, svcPort.Protocol))

			// Node Port
			if svcPort.NodePort != 0 {
				nodeIPs, err := getNodeIPs()
				if err != nil {
					return err
				}
				for _, nodeIP := range nodeIPs {
					vip := net.JoinHostPort(nodeIP, strconv.Itoa(int(svcPort.NodePort)))
					err := c.loadBalancer.Apply(LB{
						Frontend: VirtualIP{
							vip:      vip,
							protocol: svcPort.Protocol,
						},
						Backend: eps,
					})
					if err != nil {
						return err
					}
					// update the tracker with the VIP
					c.serviceTracker.updateService(name, namespace, vip, svcPort.Protocol)
					// mark the vip as processed
					vipsTracked.Delete(virtualIPKey(vip, svcPort.Protocol))
				}
			}

			// Services ExternalIPs and LoadBalancer.IngressIPs use to have the same behavior
			// so they are aggregated in a slice and processed together.
			var externalIPs []string
			// ExternalIP
			for _, extIP := range service.Spec.ExternalIPs {
				// only use the IPs of the same ClusterIP family
				if utilnet.IsIPv6String(extIP) == utilnet.IsIPv6String(ip) {
					externalIPs = append(externalIPs, extIP)
				}
			}
			// LoadBalancer
			for _, ingress := range service.Status.LoadBalancer.Ingress {
				// only use the IPs of the same ClusterIP family
				if ingress.IP != "" && utilnet.IsIPv6String(ingress.IP) == utilnet.IsIPv6String(ip) {
					externalIPs = append(externalIPs, ingress.IP)
				}
			}

			// reconcile external IPs
			if len(externalIPs) > 0 {
				for _, extIP := range externalIPs {
					vip := net.JoinHostPort(extIP, strconv.Itoa(int(svcPort.Port)))
					err := c.loadBalancer.Apply(LB{
						Frontend: VirtualIP{
							vip:      vip,
							protocol: svcPort.Protocol,
						},
						Backend: eps,
					})
					if err != nil {
						return err
					}
					c.serviceTracker.updateService(name, namespace, vip, svcPort.Protocol)
					// mark the vip as processed
					vipsTracked.Delete(virtualIPKey(vip, svcPort.Protocol))
				}
			}
		}
	}

	// at this point we have processed all vips we've found in the service
	// so the remaining ones that we had in the vipsTracked variable should be deleted
	for vipKey := range vipsTracked {
		vip, proto := splitVirtualIPKey(vipKey)
		err := c.loadBalancer.Remove(LB{
			Frontend: VirtualIP{
				vip:      vip,
				protocol: proto,
			},
		})
		if err != nil {
			return err
		}
		c.serviceTracker.deleteServiceVIP(name, namespace, vip, proto)
	}
	c.serviceTracker.deleteServiceVIPs(name, namespace, vipsTracked)
	return nil
}

// handlers

// onServiceUpdate queues the Service for processing.
func (c *Controller) onServiceAdd(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Couldn't get key for object %+v: %v", obj, err))
		return
	}
	klog.V(4).Infof("Adding service %s", key)
	c.queue.Add(key)
}

// onServiceUpdate updates the Service Selector in the cache and queues the Service for processing.
func (c *Controller) onServiceUpdate(oldObj, newObj interface{}) {
	oldService := oldObj.(*v1.Service)
	newService := newObj.(*v1.Service)

	// don't process resync or objects that are marked for deletion
	if oldService.ResourceVersion == newService.ResourceVersion ||
		!newService.GetDeletionTimestamp().IsZero() {
		return
	}

	key, err := cache.MetaNamespaceKeyFunc(newObj)
	if err == nil {
		c.queue.Add(key)
	}
}

// onServiceDelete queues the Service for processing.
func (c *Controller) onServiceDelete(obj interface{}) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for object %+v: %v", obj, err))
		return
	}
	klog.V(4).Infof("Deleting service %s", key)
	c.queue.Add(key)
}

// onEndpointSliceAdd queues a sync for the relevant Service for a sync
func (c *Controller) onEndpointSliceAdd(obj interface{}) {
	endpointSlice := obj.(*discovery.EndpointSlice)
	if endpointSlice == nil {
		utilruntime.HandleError(fmt.Errorf("invalid EndpointSlice provided to onEndpointSliceAdd()"))
		return
	}
	c.queueServiceForEndpointSlice(endpointSlice)
}

// onEndpointSliceUpdate queues a sync for the relevant Service for a sync
func (c *Controller) onEndpointSliceUpdate(prevObj, obj interface{}) {
	prevEndpointSlice := prevObj.(*discovery.EndpointSlice)
	endpointSlice := obj.(*discovery.EndpointSlice)

	// don't process resync or objects that are marked for deletion
	if prevEndpointSlice.ResourceVersion == endpointSlice.ResourceVersion ||
		!endpointSlice.GetDeletionTimestamp().IsZero() {
		return
	}
	c.queueServiceForEndpointSlice(endpointSlice)
}

// onEndpointSliceDelete queues a sync for the relevant Service for a sync if the
// EndpointSlice resource version does not match the expected version in the
// endpointSliceTracker.
func (c *Controller) onEndpointSliceDelete(obj interface{}) {
	endpointSlice, ok := obj.(*discovery.EndpointSlice)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		endpointSlice, ok = tombstone.Obj.(*discovery.EndpointSlice)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("tombstone contained object that is not a EndpointSlice: %#v", obj))
			return
		}
	}

	if endpointSlice != nil {
		c.queueServiceForEndpointSlice(endpointSlice)
	}
}

// queueServiceForEndpointSlice attempts to queue the corresponding Service for
// the provided EndpointSlice.
func (c *Controller) queueServiceForEndpointSlice(endpointSlice *discovery.EndpointSlice) {
	key, err := serviceControllerKey(endpointSlice)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("couldn't get key for EndpointSlice %+v: %v", endpointSlice, err))
		return
	}

	c.queue.Add(key)
}

// serviceControllerKey returns a controller key for a Service but derived from
// an EndpointSlice.
func serviceControllerKey(endpointSlice *discovery.EndpointSlice) (string, error) {
	if endpointSlice == nil {
		return "", fmt.Errorf("nil EndpointSlice passed to serviceControllerKey()")
	}
	serviceName, ok := endpointSlice.Labels[discovery.LabelServiceName]
	if !ok || serviceName == "" {
		return "", fmt.Errorf("endpointSlice missing %s label", discovery.LabelServiceName)
	}
	return fmt.Sprintf("%s/%s", endpointSlice.Namespace, serviceName), nil
}
