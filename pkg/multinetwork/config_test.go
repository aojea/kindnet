// SPDX-License-Identifier: APACHE-2.0

package multinetwork

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestValidateConfig(t *testing.T) {
	testCases := []struct {
		name    string
		config  string
		wantErr bool
	}{
		{
			name: "valid config",
			config: `
ips:
- 192.168.1.10/24
routes:
- destination: 10.0.0.0/8
  gateway: 192.168.1.1
dns:
- 8.8.8.8
name: eth1
`,
			wantErr: false,
		},
		{
			name: "invalid name",
			config: `
ips:
- 192.168.1.10/24
routes:
- destination: 10.0.0.0/8
  gateway: 192.168.1.1
dns:
- 8.8.8.8
name: very-long-interface-name
`,
			wantErr: true,
		},
		{
			name: "invalid ip",
			config: `
ips:
- a.b.c.d/24
routes:
- destination: 10.0.0.0/8
  gateway: 192.168.1.1
dns:
- 8.8.8.8
name: eth1
`,
			wantErr: true,
		},
		{
			name: "invalid route destination",
			config: `
ips:
- 192.168.1.10/24
routes:
- destination: a.b.c.d/8
  gateway: 192.168.1.1
dns:
- 8.8.8.8
name: eth1
`,
			wantErr: true,
		},
		{
			name:    "Empty config",
			config:  ``,
			wantErr: false,
		},
		{
			name: "invalid route",
			config: `
ips:
- 192.168.1.10/24
routes:
- destination: 10.0.0.0/8
dns:
- 8.8.8.8
name: eth1
`,
			wantErr: true,
		},
		{
			name: "invalid route",
			config: `
ips:
- 192.168.1.10/24
routes:
- gateway: 192.168.1.1
dns:
- 8.8.8.8
name: eth1
`,
			wantErr: true,
		},
		{
			name: "additional property",
			config: `
ips:
- 192.168.1.10/24
routes:
- destination: 10.0.0.0/8
  gateway: 192.168.1.1
dns:
- 8.8.8.8
name: eth1
foo: bar
`,
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := &runtime.RawExtension{}
			raw.Raw = []byte(tc.config)

			_, err := ValidateConfig(raw)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
		})
	}
}
