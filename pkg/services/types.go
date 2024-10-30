package services

import v1 "k8s.io/api/core/v1"

// LoadBalancer
type LoadBalancer interface {
	Apply(lb LB) error
	Remove(lb LB) error
}

// LB represents a LoadBalancer object with one frontend [IP:Port] and Protocol
// and several backends as IP:Port
type LB struct {
	Frontend VirtualIP
	Backend  []string
}

type VirtualIP struct {
	vip      string
	protocol v1.Protocol
}
