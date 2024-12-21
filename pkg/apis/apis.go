package apis

const SocketPath = "/run/cni-kindnet.sock"

type NetworkConfig struct {
	IPs []string `json:"ips"`
	MTU int      `json:"mtu"` // default to 1500 if not set
}
