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

// Note: the example only works with the code within the same release/branch.
package main

import (
	"bytes"
	"os"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
)

var node *corev1.Node
var node2 *corev1.Node

func TestMain(m *testing.M) {
	// Create a node.
	node = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "node",
			CreationTimestamp: metav1.Time{Time: time.Now()},
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{
					Type:    corev1.NodeInternalIP,
					Address: "192.168.1.2",
				},
				{
					Type:    corev1.NodeExternalIP,
					Address: "10.0.0.2",
				},
			},
		},
	}

	os.Exit(m.Run())
}

func TestNewKindnet(t *testing.T) {
	type args struct {
		cniConfigWriter *CNIConfigWriter
		ipv6            bool
		kindnetConfig   *KindnetConfig
	}
	tests := []struct {
		name string
		args args
		want *Kindnet
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewKindnet(tt.args.cniConfigWriter, tt.args.ipv6, tt.args.kindnetConfig); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKindnet() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_internalIP(t *testing.T) {
	type args struct {
		node corev1.Node
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "get node internal ip",
			args: args{
				node: *node,
			},
			want: "192.168.1.2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := internalIP(tt.args.node); got != tt.want {
				t.Errorf("internalIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKindnet_syncRoutes(t *testing.T) {
	tests := []struct {
		name    string
		k       *Kindnet
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.k.syncRoutes(); (err != nil) != tt.wantErr {
				t.Errorf("Kindnet.syncRoutes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKindnet_syncMasqRules(t *testing.T) {
	tests := []struct {
		name    string
		k       *Kindnet
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.k.syncMasqRules(); (err != nil) != tt.wantErr {
				t.Errorf("Kindnet.syncMasqRules() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_postroutingJumpComment(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := postroutingJumpComment(); got != tt.want {
				t.Errorf("postroutingJumpComment() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKindnet_ensurePostroutingJump(t *testing.T) {
	tests := []struct {
		name    string
		k       *Kindnet
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.k.ensurePostroutingJump(); (err != nil) != tt.wantErr {
				t.Errorf("Kindnet.ensurePostroutingJump() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_writeNonMasqRule(t *testing.T) {
	type args struct {
		lines *bytes.Buffer
		cidr  string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeNonMasqRule(tt.args.lines, tt.args.cidr)
		})
	}
}

func Test_writeMasqRule(t *testing.T) {
	type args struct {
		lines *bytes.Buffer
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeMasqRule(tt.args.lines)
		})
	}
}

func Test_writeRule(t *testing.T) {
	type args struct {
		lines    *bytes.Buffer
		position utiliptables.RulePosition
		chain    utiliptables.Chain
		args     []string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeRule(tt.args.lines, tt.args.position, tt.args.chain, tt.args.args...)
		})
	}
}

func Test_writeLine(t *testing.T) {
	type args struct {
		lines *bytes.Buffer
		words []string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeLine(tt.args.lines, tt.args.words...)
		})
	}
}

func TestComputeCNIConfigInputs(t *testing.T) {
	type args struct {
		node corev1.Node
	}
	tests := []struct {
		name string
		args args
		want CNIConfigInputs
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ComputeCNIConfigInputs(tt.args.node); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ComputeCNIConfigInputs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCNIConfigWriter_Write(t *testing.T) {
	type args struct {
		inputs CNIConfigInputs
	}
	tests := []struct {
		name    string
		c       *CNIConfigWriter
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.c.Write(tt.args.inputs); (err != nil) != tt.wantErr {
				t.Errorf("CNIConfigWriter.Write() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_writeCNIConfig(t *testing.T) {
	type args struct {
		rawTemplate string
		data        CNIConfigInputs
	}
	tests := []struct {
		name    string
		args    args
		wantW   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &bytes.Buffer{}
			if err := writeCNIConfig(w, tt.args.rawTemplate, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("writeCNIConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotW := w.String(); gotW != tt.wantW {
				t.Errorf("writeCNIConfig() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
