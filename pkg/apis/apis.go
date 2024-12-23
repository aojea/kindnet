package apis

const (
	SocketPath    = "/run/cni-kindnet.sock"
	PluginName    = "cni-kindnet"
	HostPortMapv4 = "hostport-map-v4"
	HostPortMapv6 = "hostport-map-v6"
)

type NetworkConfig struct {
	IPs       []string `json:"ips"`
	GatewayV4 string   `json:"gatewayV4"`
	GatewayV6 string   `json:"gatewayV6"`
	MTU       int      `json:"mtu"` // default to 1500 if not set
}
