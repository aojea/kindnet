package dataplane

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/aojea/kindnet/pkg/apis"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
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
)

// controller that syncs the Kubernetes objects wtih the nftables ones
const controllerName = "dataplane"

type Controller struct {
	nodeName string

	nft              *nftables.Conn
	client           clientset.Interface
	eventBroadcaster record.EventBroadcaster
	eventRecorder    record.EventRecorder

	nodeLister    corelisters.NodeLister
	nodesSynced   cache.InformerSynced
	serviceLister corelisters.ServiceLister
	serviceSynced cache.InformerSynced

	nodeQueue    workqueue.RateLimitingInterface
	serviceQueue workqueue.RateLimitingInterface
}

func New(nodeName string,
	nft *nftables.Conn,
	client clientset.Interface,
	nodeInformer coreinformers.NodeInformer,
	serviceInformer coreinformers.ServiceInformer,
	ipFamily apis.IPFamily) (*Controller, error) {
	klog.V(2).Info("Creating dataplane API controller")

	broadcaster := record.NewBroadcaster()
	broadcaster.StartStructuredLogging(0)
	broadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: client.CoreV1().Events("")})
	recorder := broadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: controllerName})

	c := &Controller{
		nodeName:         nodeName,
		nft:              nft,
		client:           client,
		nodeLister:       nodeInformer.Lister(),
		nodesSynced:      nodeInformer.Informer().HasSynced,
		nodeQueue:        workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "nodes-"+controllerName),
		serviceLister:    serviceInformer.Lister(),
		serviceSynced:    serviceInformer.Informer().HasSynced,
		serviceQueue:     workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "services-"+controllerName),
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
		return nil, err
	}

	_, err = serviceInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueService,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueService(new)
		},
		DeleteFunc: c.enqueueService,
	})
	if err != nil {
		klog.Infof("unexpected error adding event handler to informer: %v", err)
		return nil, err
	}

	return c, nil
}

func (c *Controller) enqueueNode(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		return
	}
	if len(node.Spec.PodCIDRs) == 0 {
		klog.Infof("Node %s has no CIDR, ignoring\n", node.Name)
		return
	}

	// since we reconcile the whole state enqueue always the same key to collapse events
	c.nodeQueue.Add("dummy-key")
}

func (c *Controller) enqueueService(obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		return
	}
	if len(service.Spec.ClusterIP) == 0 ||
		service.Spec.ClusterIP == v1.ClusterIPNone {
		klog.V(2).Infof("Service %s has no Cluster IP, ignoring\n", service.Name)
		return
	}
	// since we reconcile the whole state enqueue always the same key to collapse events
	c.serviceQueue.Add("dummy-key")
}

func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.nodeQueue.ShutDown()
	logger := klog.FromContext(ctx)

	// Start the informer factories to begin populating the informer caches
	logger.Info("Starting egress controller")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	if ok := cache.WaitForCacheSync(ctx.Done(), c.nodesSynced, c.serviceSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	logger.Info("Starting workers", "count", workers)
	// Launch two workers to process Foo resources
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runNodeWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runServiceWorker, time.Second)
	}

	go wait.UntilWithContext(ctx, c.syncRules, 100*time.Second)

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}

func (c *Controller) syncRules(ctx context.Context) {
	masqueradeChain := c.nft.AddChain(&nftables.Chain{
		Name:     apis.NATPostroutingChain,
		Table:    apis.KindnetTable,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// masquerade all traffic that is not destined to a Pod range
	// TODO and are using the default gateway interface ???
	// https://github.com/capnspacehook/whalewall/blob/master/create.go
	c.nft.AddRule(&nftables.Rule{
		Table: apis.KindnetTable,
		Chain: masqueradeChain,
		Exprs: []expr.Any{
			// Store the conntrack state in register 1
			// [ ct load state => reg 1 ]
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			// Only New connections CtStateBitNEW
			// [ bitwise reg 1 = ( reg 1 & ... ) ^ 0x00000000 ]
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			// [ cmp neq reg 1 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(0),
			},
			// [ meta load nfproto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(unix.NFPROTO_IPV4)},
			},
			// [ payload load 4b @ network header + ... => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           4,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        apis.PodRangesV4Set,
			},
			// [ masq flags 0x10 ]
			&expr.Masq{
				FullyRandom: true,
			},
		},
	})

	// IPv6
	c.nft.AddRule(&nftables.Rule{
		Table: apis.KindnetTable,
		Chain: masqueradeChain,
		Exprs: []expr.Any{
			// Store the conntrack state in register 1
			// [ ct load state => reg 1 ]
			&expr.Ct{
				Register: 1,
				Key:      expr.CtKeySTATE,
			},
			// Only New connections CtStateBitNEW
			// [ bitwise reg 1 = ( reg 1 & ... ) ^ 0x00000000 ]
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitNEW),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			// [ cmp neq reg 1 0x00000000 ]
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binaryutil.NativeEndian.PutUint32(0),
			},
			// [ meta load nfproto => reg 1 ]
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 1,
			},
			// [ cmp eq reg 1 ... ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{byte(unix.NFPROTO_IPV6)},
			},
			// [ payload load 4b @ network header + ... => reg 1 ]
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Len:           16,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        24,
				DestRegister:  1,
			},
			// [ lookup reg 1 set ... 0x0 ]
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        apis.PodRangesV6Set,
			},
			// [ masq flags 0x10 ]
			&expr.Masq{
				FullyRandom: true,
			},
		},
	})
	err := c.nft.Flush()
	if err != nil {
		klog.Infof("error flushing masquerade tables: %v", err)
	}
}

func (c *Controller) runNodeWorker(ctx context.Context) {
	for c.processNextNodeWorkItem(ctx) {
	}
}

func (c *Controller) processNextNodeWorkItem(ctx context.Context) bool {
	obj, shutdown := c.nodeQueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.nodeQueue.Done.
	err := func(key string) error {
		// We call Done here so the nodeQueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the nodeQueue and attempted again after a back-off
		// period.
		defer c.nodeQueue.Done(key)
		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err := c.syncNodesHandler(ctx); err != nil {
			// Put the item back on the nodeQueue to handle any transient errors.
			c.nodeQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.nodeQueue.Forget(key)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj.(string))

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncNodesHandler update the Set for pod ranges with current state
func (c *Controller) syncNodesHandler(ctx context.Context) error {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	podSubnetsV4 := []nftables.SetElement{}
	podSubnetsV6 := []nftables.SetElement{}

	for _, node := range nodes {
		for _, podCIDR := range node.Spec.PodCIDRs {
			prefix, err := netip.ParsePrefix(podCIDR)
			if err != nil {
				return err
			}
			last, err := broadcastAddress(prefix)
			if err != nil {
				return err
			}

			elements := []nftables.SetElement{
				{
					Key:         prefix.Masked().Addr().AsSlice(),
					IntervalEnd: false,
				},
				{
					Key:         last.AsSlice(),
					IntervalEnd: true,
				},
			}
			if prefix.Addr().Is4() {
				podSubnetsV4 = append(podSubnetsV4, elements...)
			} else {
				podSubnetsV6 = append(podSubnetsV6, elements...)
			}
		}
	}

	if len(podSubnetsV4) > 0 {
		set := &nftables.Set{
			Table:   apis.KindnetTable,
			Name:    apis.PodRangesV4Set,
			KeyType: nftables.TypeIPAddr,
		}
		if err := c.nft.AddSet(set, podSubnetsV4); err != nil {
			return err
		}
	}

	if len(podSubnetsV6) > 0 {
		set := &nftables.Set{
			Table:   apis.KindnetTable,
			Name:    apis.PodRangesV6Set,
			KeyType: nftables.TypeIP6Addr,
		}
		if err := c.nft.AddSet(set, podSubnetsV6); err != nil {
			return err
		}
	}

	return c.nft.Flush()
}

func (c *Controller) runServiceWorker(ctx context.Context) {
	for c.processNextServiceWorkItem(ctx) {
	}
}

func (c *Controller) processNextServiceWorkItem(ctx context.Context) bool {
	obj, shutdown := c.serviceQueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.serviceQueue.Done.
	err := func(key string) error {
		// We call Done here so the serviceQueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the serviceQueue and attempted again after a back-off
		// period.
		defer c.serviceQueue.Done(key)
		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err := c.syncServicesHandler(ctx); err != nil {
			// Put the item back on the serviceQueue to handle any transient errors.
			c.serviceQueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.serviceQueue.Forget(key)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj.(string))

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncServicesHandler update the Set for Service IPs with current state
func (c *Controller) syncServicesHandler(ctx context.Context) error {
	services, err := c.serviceLister.List(labels.Everything())
	if err != nil {
		return err
	}

	clusterIPV4 := []nftables.SetElement{}
	clusterIPV6 := []nftables.SetElement{}

	for _, service := range services {
		for _, clusterIP := range service.Spec.ClusterIPs {
			if clusterIP == v1.ClusterIPNone {
				continue
			}

			ip, err := netip.ParseAddr(clusterIP)
			if err != nil {
				return err
			}
			element := nftables.SetElement{
				Key:         ip.AsSlice(),
				IntervalEnd: false,
			}

			if ip.Is4() {
				clusterIPV4 = append(clusterIPV4, element)

			} else {
				clusterIPV6 = append(clusterIPV6, element)
			}
		}
	}

	if len(clusterIPV4) > 0 {
		set := &nftables.Set{
			Table:   apis.KindnetTable,
			Name:    apis.ServiceIPsV4Set,
			KeyType: nftables.TypeIPAddr,
		}
		if err := c.nft.AddSet(set, clusterIPV4); err != nil {
			return err
		}
	}

	if len(clusterIPV6) > 0 {
		set := &nftables.Set{
			Table:   apis.KindnetTable,
			Name:    apis.ServiceIPsV6Set,
			KeyType: nftables.TypeIP6Addr,
		}
		if err := c.nft.AddSet(set, clusterIPV6); err != nil {
			return err
		}
	}

	return c.nft.Flush()
}

// broadcastAddress returns the broadcast address of the subnet
// The broadcast address is obtained by setting all the host bits
// in a subnet to 1.
// network 192.168.0.0/24 : subnet bits 24 host bits 32 - 24 = 8
// broadcast address 192.168.0.255
func broadcastAddress(subnet netip.Prefix) (netip.Addr, error) {
	base := subnet.Masked().Addr()
	bytes := base.AsSlice()
	// get all the host bits from the subnet
	n := 8*len(bytes) - subnet.Bits()
	// set all the host bits to 1
	for i := len(bytes) - 1; i >= 0 && n > 0; i-- {
		if n >= 8 {
			bytes[i] = 0xff
			n -= 8
		} else {
			mask := ^uint8(0) >> (8 - n)
			bytes[i] |= mask
			break
		}
	}

	addr, ok := netip.AddrFromSlice(bytes)
	if !ok {
		return netip.Addr{}, fmt.Errorf("invalid address %v", bytes)
	}
	return addr, nil
}
