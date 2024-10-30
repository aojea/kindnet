package services

import (
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilpointer "k8s.io/utils/pointer"
)

func Test_getLbEndpoints(t *testing.T) {
	type args struct {
		slices  []*discovery.EndpointSlice
		svcPort v1.ServicePort
		family  v1.IPFamily
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "empty slices",
			args: args{
				slices: []*discovery.EndpointSlice{},
				svcPort: v1.ServicePort{
					Name:       "tcp-example",
					TargetPort: intstr.FromInt(80),
					Protocol:   v1.ProtocolTCP,
				},
				family: v1.IPv4Protocol,
			},
			want: []string{},
		},
		{
			name: "slices with endpoints",
			args: args{
				slices: []*discovery.EndpointSlice{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "svc-ab23",
							Namespace: "ns",
							Labels:    map[string]string{discovery.LabelServiceName: "svc"},
						},
						Ports: []discovery.EndpointPort{
							{
								Name:     utilpointer.StringPtr("tcp-example"),
								Protocol: protoPtr(v1.ProtocolTCP),
								Port:     utilpointer.Int32Ptr(int32(80)),
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
				},
				svcPort: v1.ServicePort{
					Name:       "tcp-example",
					TargetPort: intstr.FromInt(80),
					Protocol:   v1.ProtocolTCP,
				},
				family: v1.IPv4Protocol,
			},
			want: []string{"10.0.0.2:80"},
		},
		{
			name: "slices with different port name",
			args: args{
				slices: []*discovery.EndpointSlice{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "svc-ab23",
							Namespace: "ns",
							Labels:    map[string]string{discovery.LabelServiceName: "svc"},
						},
						Ports: []discovery.EndpointPort{
							{
								Name:     utilpointer.StringPtr("tcp-example-wrong"),
								Protocol: protoPtr(v1.ProtocolTCP),
								Port:     utilpointer.Int32Ptr(int32(8080)),
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
				},
				svcPort: v1.ServicePort{
					Name:       "tcp-example",
					TargetPort: intstr.FromInt(80),
					Protocol:   v1.ProtocolTCP,
				},
				family: v1.IPv4Protocol,
			},
			want: []string{},
		},
		{
			name: "slices and service without port name",
			args: args{
				slices: []*discovery.EndpointSlice{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "svc-ab23",
							Namespace: "ns",
							Labels:    map[string]string{discovery.LabelServiceName: "svc"},
						},
						Ports: []discovery.EndpointPort{
							{
								Protocol: protoPtr(v1.ProtocolTCP),
								Port:     utilpointer.Int32Ptr(int32(8080)),
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
				},
				svcPort: v1.ServicePort{
					TargetPort: intstr.FromInt(80),
					Protocol:   v1.ProtocolTCP,
				},
				family: v1.IPv4Protocol,
			},
			want: []string{"10.0.0.2:8080"},
		},
		{
			name: "slices with different IP family",
			args: args{
				slices: []*discovery.EndpointSlice{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "svc-ab23",
							Namespace: "ns",
							Labels:    map[string]string{discovery.LabelServiceName: "svc"},
						},
						Ports: []discovery.EndpointPort{
							{
								Name:     utilpointer.StringPtr("tcp-example"),
								Protocol: protoPtr(v1.ProtocolTCP),
								Port:     utilpointer.Int32Ptr(int32(80)),
							},
						},
						AddressType: discovery.AddressTypeIPv6,
						Endpoints: []discovery.Endpoint{
							{
								Conditions: discovery.EndpointConditions{
									Ready: utilpointer.BoolPtr(true),
								},
								Addresses: []string{"2001:db2::2"},
							},
						},
					},
				},
				svcPort: v1.ServicePort{
					Name:       "tcp-example",
					TargetPort: intstr.FromInt(80),
					Protocol:   v1.ProtocolTCP,
				},
				family: v1.IPv4Protocol,
			},
			want: []string{},
		},
		{
			name: "multiples slices with duplicate endpoints",
			args: args{
				slices: []*discovery.EndpointSlice{
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "svc-ab23",
							Namespace: "ns",
							Labels:    map[string]string{discovery.LabelServiceName: "svc"},
						},
						Ports: []discovery.EndpointPort{
							{
								Name:     utilpointer.StringPtr("tcp-example"),
								Protocol: protoPtr(v1.ProtocolTCP),
								Port:     utilpointer.Int32Ptr(int32(80)),
							},
						},
						AddressType: discovery.AddressTypeIPv4,
						Endpoints: []discovery.Endpoint{
							{
								Conditions: discovery.EndpointConditions{
									Ready: utilpointer.BoolPtr(true),
								},
								Addresses: []string{"10.0.0.2", "10.1.1.2"},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							Name:      "svc-ab23",
							Namespace: "ns",
							Labels:    map[string]string{discovery.LabelServiceName: "svc"},
						},
						Ports: []discovery.EndpointPort{
							{
								Name:     utilpointer.StringPtr("tcp-example"),
								Protocol: protoPtr(v1.ProtocolTCP),
								Port:     utilpointer.Int32Ptr(int32(80)),
							},
						},
						AddressType: discovery.AddressTypeIPv4,
						Endpoints: []discovery.Endpoint{
							{
								Conditions: discovery.EndpointConditions{
									Ready: utilpointer.BoolPtr(true),
								},
								Addresses: []string{"10.0.0.2", "10.2.2.2"},
							},
						},
					},
				},
				svcPort: v1.ServicePort{
					Name:       "tcp-example",
					TargetPort: intstr.FromInt(80),
					Protocol:   v1.ProtocolTCP,
				},
				family: v1.IPv4Protocol,
			},
			want: []string{"10.0.0.2:80", "10.1.1.2:80", "10.2.2.2:80"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getLbEndpoints(tt.args.slices, tt.args.svcPort, tt.args.family); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getLbEndpoints() = %v, want %v", got, tt.want)
			}
		})
	}
}
