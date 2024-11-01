// SPDX-License-Identifier: APACHE-2.0

package main

import (
	"bytes"
	"encoding/json"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Test_writeCNIConfig(t *testing.T) {
	tests := []struct {
		name    string
		node    *v1.Node
		mtu     int
		wantW   string
		wantErr bool
	}{
		{
			name: "ipv4 only and ptp plugin and start range",
			mtu:  1500,
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v1.NodeSpec{
					PodCIDRs: []string{"192.168.0.0/24"},
				},
				Status: v1.NodeStatus{
					Capacity: v1.ResourceList{
						v1.ResourcePods: resource.MustParse("110"),
					},
				},
			},
		},
		{
			name: "dual stack only and ptp plugin and start range",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v1.NodeSpec{
					PodCIDRs: []string{"192.168.0.0/24", "fd00:1:2:3::/96"},
				},
				Status: v1.NodeStatus{
					Capacity: v1.ResourceList{
						v1.ResourcePods: resource.MustParse("110"),
					},
				},
			},
		},
		{
			name: "ipv4 only and ptp plugin and no start range",
			mtu:  1500,
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v1.NodeSpec{
					PodCIDRs: []string{"192.168.0.0/24"},
				},
				Status: v1.NodeStatus{
					Capacity: v1.ResourceList{
						v1.ResourcePods: resource.MustParse("255"),
					},
				},
			},
		},
		{
			name: "dual stack only and ptp plugin and no start range",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "node0",
				},
				Spec: v1.NodeSpec{
					PodCIDRs: []string{"192.168.0.0/24", "fd00:1:2:3::/96"},
				},
				Status: v1.NodeStatus{
					Capacity: v1.ResourceList{
						v1.ResourcePods: resource.MustParse("255"),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		for _, cniTemplate := range []string{cniConfigTemplate, cniConfigTemplateBridge} {
			t.Run(tt.name, func(t *testing.T) {
				w := &bytes.Buffer{}
				data := ComputeCNIConfigInputs(tt.node)
				data.Mtu = tt.mtu
				if err := writeCNIConfig(w, cniTemplate, data); (err != nil) != tt.wantErr {
					t.Errorf("writeCNIConfig() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				t.Logf("CNI input:\n%#v", data)
				t.Logf("CNI config:\n%s", w.String())
				// is valid json
				if !json.Valid([]byte(w.String())) {
					t.Errorf("Invalid Json: %s", w.String())
				}
				if gotW := w.String(); gotW != tt.wantW {
					// TODO validate the content
					// t.Errorf("writeCNIConfig() = %v, want %v", gotW, tt.wantW)
				}
			})
		}
	}
}
