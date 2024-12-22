package apis

const SocketPath = "/run/cni-kindnet.sock"

type NetworkConfig struct {
	IPs       []string `json:"ips"`
	GatewayV4 string   `json:"gatewayV4"`
	GatewayV6 string   `json:"gatewayV6"`
	MTU       int      `json:"mtu"` // default to 1500 if not set
}
