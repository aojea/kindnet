package services

import (
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	utilpointer "k8s.io/utils/pointer"
)

var alwaysReady = func() bool { return true }

type FakeLoadBalancer struct{}

func (f FakeLoadBalancer) Apply(lb LB) error {
	fmt.Printf("Apply LB %+v\n", lb)
	return nil
}

func (f FakeLoadBalancer) Remove(lb LB) error {
	fmt.Printf("Remove LB %+v\n", lb)
	return nil
}

type serviceController struct {
	*Controller
	serviceStore       cache.Store
	endpointSliceStore cache.Store
}

func newController() *serviceController {
	client := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactory(client, 0)
	controller := NewController(client,
		informerFactory.Core().V1().Services(),
		informerFactory.Discovery().V1().EndpointSlices(),
		FakeLoadBalancer{},
	)
	controller.servicesSynced = alwaysReady
	controller.endpointSlicesSynced = alwaysReady
	return &serviceController{
		controller,
		informerFactory.Core().V1().Services().Informer().GetStore(),
		informerFactory.Discovery().V1().EndpointSlices().Informer().GetStore(),
	}
}

func TestSyncServices(t *testing.T) {
	serviceName := "test"
	ns := "test-ns"
	tests := []struct {
		name          string
		slice         *discovery.EndpointSlice
		service       *v1.Service
		updateTracker bool
	}{

		{
			name: "create service from Single Stack Service without endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports:       []discovery.EndpointPort{},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints:   []discovery.Endpoint{},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
					}},
				},
			},
			updateTracker: true,
		},
		{
			name: "create OVN LoadBalancer from Single Stack NodePort Service without endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports:       []discovery.EndpointPort{},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints:   []discovery.Endpoint{},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
						NodePort:   32766,
					}},
				},
			},
			updateTracker: true,
		},
		{
			name: "create OVN LoadBalancer from Single Stack Service with endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     utilpointer.StringPtr("tcp-example"),
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     utilpointer.Int32Ptr(int32(3456)),
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Conditions: discovery.EndpointConditions{
							Ready: utilpointer.BoolPtr(true),
						},
						Addresses: []string{"10.0.0.2"},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
					}},
				},
			},
			updateTracker: false,
		},
		{
			name: "create OVN LoadBalancer from Dual Stack Service with dual stack endpoints",
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName + "ab23",
					Namespace: ns,
					Labels:    map[string]string{discovery.LabelServiceName: serviceName},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     utilpointer.StringPtr("tcp-example"),
						Protocol: protoPtr(v1.ProtocolTCP),
						Port:     utilpointer.Int32Ptr(int32(3456)),
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Conditions: discovery.EndpointConditions{
							Ready: utilpointer.BoolPtr(true),
						},
						Addresses: []string{"10.0.0.2"},
					},
				},
			},
			service: &v1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
				Spec: v1.ServiceSpec{
					Type:       v1.ServiceTypeClusterIP,
					ClusterIP:  "192.168.1.1",
					ClusterIPs: []string{"192.168.1.1"},
					Selector:   map[string]string{"foo": "bar"},
					Ports: []v1.ServicePort{{
						Port:       80,
						Protocol:   v1.ProtocolTCP,
						TargetPort: intstr.FromInt(3456),
					}},
				},
			},
			updateTracker: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := newController()
			// Add objects to the Store
			controller.endpointSliceStore.Add(tt.slice)
			controller.serviceStore.Add(tt.service)
			if tt.updateTracker {
				controller.serviceTracker.updateKubernetesService(tt.service)
			}

			err := controller.syncServices(ns + "/" + serviceName)
			if err != nil {
				t.Errorf("syncServices error: %v", err)
			}

		})
	}
}

// A service can mutate its ports, we need to be sure we don´t left dangling ports
func TestUpdateServicePorts(t *testing.T) {

	ns := "testns"
	serviceName := "foo"
	slice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName + "ab23",
			Namespace: ns,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     utilpointer.StringPtr("tcp-example"),
				Protocol: protoPtr(v1.ProtocolTCP),
				Port:     utilpointer.Int32Ptr(int32(3456)),
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Conditions: discovery.EndpointConditions{
					Ready: utilpointer.BoolPtr(true),
				},
				Addresses: []string{"10.0.0.2"},
			},
		},
	}
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
		Spec: v1.ServiceSpec{
			Type:       v1.ServiceTypeClusterIP,
			ClusterIP:  "192.168.1.1",
			ClusterIPs: []string{"192.168.1.1"},
			Selector:   map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{{
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(3456),
			}},
		},
	}
	controller := newController()
	// Process the first service
	controller.endpointSliceStore.Add(slice)
	controller.serviceStore.Add(service)
	controller.syncServices(ns + "/" + serviceName)

	// Update the service with a different Port
	serviceNew := service.DeepCopy()
	serviceNew.Spec.Ports[0].Port = 8888
	controller.serviceStore.Delete(service)
	controller.serviceStore.Add(serviceNew)
	// sync service
	controller.syncServices(ns + "/" + serviceName)
	if controller.serviceTracker.hasServiceVIP(serviceName, ns, "192.168.1.1:80", v1.ProtocolTCP) {
		t.Fatalf("Service with port 80 should not exist")
	}
	if !controller.serviceTracker.hasServiceVIP(serviceName, ns, "192.168.1.1:8888", v1.ProtocolTCP) {
		t.Fatalf("Service with port 8888 should exist")
	}

}

// A service can mutate its ports, we need to be sure we don´t left dangling ports
func TestUpdateServiceEndpointsToHost(t *testing.T) {

	ns := "testns"
	serviceName := "foo"
	slice := &discovery.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName + "ab23",
			Namespace: ns,
			Labels:    map[string]string{discovery.LabelServiceName: serviceName},
		},
		Ports: []discovery.EndpointPort{
			{
				Name:     utilpointer.StringPtr("tcp-example"),
				Protocol: protoPtr(v1.ProtocolTCP),
				Port:     utilpointer.Int32Ptr(int32(3456)),
			},
		},
		AddressType: discovery.AddressTypeIPv4,
		Endpoints: []discovery.Endpoint{
			{
				Conditions: discovery.EndpointConditions{
					Ready: utilpointer.BoolPtr(true),
				},
				Addresses: []string{"10.128.0.2"},
			},
		},
	}
	service := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName, Namespace: ns},
		Spec: v1.ServiceSpec{
			Type:       v1.ServiceTypeClusterIP,
			ClusterIP:  "192.168.1.1",
			ClusterIPs: []string{"192.168.1.1"},
			Selector:   map[string]string{"foo": "bar"},
			Ports: []v1.ServicePort{{
				Port:       80,
				Protocol:   v1.ProtocolTCP,
				TargetPort: intstr.FromInt(3456),
			}},
		},
	}

	controller := newController()
	// Process the first service
	controller.endpointSliceStore.Add(slice)
	controller.serviceStore.Add(service)
	controller.syncServices(ns + "/" + serviceName)

	// Update endpoints with host network pod
	epsNew := slice.DeepCopy()
	epsNew.Endpoints = []discovery.Endpoint{
		{
			Conditions: discovery.EndpointConditions{
				Ready: utilpointer.BoolPtr(true),
			},
			Addresses: []string{"2.2.2.2"},
		}}
	controller.endpointSliceStore.Delete(slice)
	controller.endpointSliceStore.Add(epsNew)
	// sync service
	controller.syncServices(ns + "/" + serviceName)

} // protoPtr takes a Protocol and returns a pointer to it.
func protoPtr(proto v1.Protocol) *v1.Protocol {
	return &proto
}
