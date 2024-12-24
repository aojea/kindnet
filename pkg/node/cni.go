// SPDX-License-Identifier: APACHE-2.0

package node

import (
	"io"
	"os"
	"reflect"
	"text/template"

	"github.com/pkg/errors"

	corev1 "k8s.io/api/core/v1"
	utilsnet "k8s.io/utils/net"
)

/* cni config management */

// CNIConfigInputs is supplied to the CNI config template
type CNIConfigInputs struct {
	PodCIDRs      []string
	RangeStart    []string
	DefaultRoutes []string
	Mtu           int
}

// ComputeCNIConfigInputs computes the template inputs for CNIConfigWriter
func ComputeCNIConfigInputs(node *corev1.Node) CNIConfigInputs {
	inputs := CNIConfigInputs{}
	podCIDRs, _ := utilsnet.ParseCIDRs(node.Spec.PodCIDRs) // already validated
	for _, podCIDR := range podCIDRs {
		inputs.PodCIDRs = append(inputs.PodCIDRs, podCIDR.String())
		// define the default route
		if utilsnet.IsIPv4CIDR(podCIDR) {
			inputs.DefaultRoutes = append(inputs.DefaultRoutes, "0.0.0.0/0")
		} else {
			inputs.DefaultRoutes = append(inputs.DefaultRoutes, "::/0")
		}
		// reserve the first IPs of the range
		size := utilsnet.RangeSize(podCIDR)
		podCapacity := node.Status.Capacity.Pods().Value()
		if podCapacity == 0 {
			podCapacity = 110 // default to 110
		}
		rangeStart := ""
		offset := size - podCapacity
		if offset > 10 { // reserve the first 10 addresses of the Pod range if there is capacity
			startAddress, err := utilsnet.GetIndexedIP(podCIDR, 10)
			if err == nil {
				rangeStart = startAddress.String()
			}
		}
		inputs.RangeStart = append(inputs.RangeStart, rangeStart)

	}
	return inputs
}

// CNIConfigPath is where kindnetd will write the computed CNI config
const CNIConfigPath = "/etc/cni/net.d/10-kindnet.conflist"

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
				{{- range $i, $route := .DefaultRoutes}}
				{{- if gt $i 0 }},{{end}}
				{ "dst": "{{ $route }}" }
				{{- end}}
			],
			"ranges": [
				{{- range $i, $cidr := .PodCIDRs}}
				{{- if gt $i 0 }},{{end}}
				[ { "subnet": "{{ $cidr }}" {{ if index $.RangeStart $i }}, "rangeStart": "{{ index $.RangeStart $i }}" {{ end -}} } ]
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

const cniConfigTemplateBridge = `
{
	"cniVersion": "0.4.0",
	"name": "kindnet",
	"plugins": [
	{
		"type": "bridge",
		"bridge": "kind-br",
		"ipMasq": false,
		"isGateway": true,
		"isDefaultGateway": true,
		"hairpinMode": true,
		"ipam": {
			"type": "host-local",
			"dataDir": "/run/cni-ipam-state",
			"ranges": [
				{{- range $i, $cidr := .PodCIDRs}}
				{{- if gt $i 0 }},{{end}}
				[ { "subnet": "{{ $cidr }}" {{ if index $.RangeStart $i }}, "rangeStart": "{{ index $.RangeStart $i }}" {{ end -}} } ]
				{{- end}}
			]
		}
		{{- if .Mtu}},
		"mtu": {{ .Mtu }}
		{{- end}}
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
	LastInputs CNIConfigInputs
	Mtu        int
	Bridge     bool
}

// Write will write the config based on
func (c *CNIConfigWriter) Write(inputs CNIConfigInputs) error {
	if reflect.DeepEqual(inputs, c.LastInputs) {
		return nil
	}

	// use an extension not recognized by CNI to write the contents initially
	// https://github.com/containerd/go-cni/blob/891c2a41e18144b2d7921f971d6c9789a68046b2/opts.go#L170
	// then we can rename to atomically make the file appear
	f, err := os.Create(c.Path + ".temp")
	if err != nil {
		return err
	}

	template := cniConfigTemplate
	if c.Bridge {
		template = cniConfigTemplateBridge
	}

	// actually write the config
	if err := writeCNIConfig(f, template, inputs); err != nil {
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
	c.LastInputs = inputs
	return nil
}

func writeCNIConfig(w io.Writer, rawTemplate string, data CNIConfigInputs) error {
	t, err := template.New("cni-json").Parse(rawTemplate)
	if err != nil {
		return errors.Wrap(err, "failed to parse cni template")
	}
	return t.Execute(w, &data)
}
