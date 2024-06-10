# Simple Kubernetes Networking Plugin with IPv4, IPv6 and DualStack support

The main goal of the project is to have a simple Kubernetes Networking Plugin plugin for Kubernetes with
IPv4 and IPv6 support that provides the [Cluster
Networking](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

The idea was born because of the lack of IPv6 support in current CNI plugins
and because there are no automatic alternatives to create a multinode kubernetes
cluster with IPv6.

Kindnet evolved adding new features, as an embedded ipmasq agent and nowadays,
is the default CNI plugin for [KIND](https://github.com/kubernetes-sigs/kind)

All the original code was moved to the KIND project in-tree.
This repo is kept for new features development and for using it on "real" clusters.


## Kindnet components

A `kindnet-controller` that allows to configure dynamically the agents using the
configuration CR:

```yaml
apiVersion: "kindnet.io/v1alpha1"
kind: Configuration
metadata:
  name: kindnet
  namespace: kube-system
spec:
  kindnetdImage: ghcr.io/aojea/kindnetd:v1.1.0
```

A daemon named `kindnetd` with the following features:

* `CNI config`: configures the CNI plugin dropping the file `/etc/cni/net.d/10-kindnet.conflist`
* `routing`: install routes on the to the POD subnets in the other nodes
* `ip-masq`: non masquerade traffic that is directed to PODs

It uses the following [standard CNI
plugins](https://github.com/containernetworking/plugins) on the nodes:

* `ptp`: creates a veth pair and adds the host and the container to it.
* `host-local`: maintains a local database of allocated IPs. It uses the
  `ipRanges` capability to provide dynamic configuration for the Pods subnets.
* `portmap`: An iptables-based portmapping plugin. Maps ports from the host's
  address space to the container.

## Installation

Kindnet can be installed on your cluster using the manifest [install-kindnet.yaml](install-kindnet.yaml)

`kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml`

Once installed apply the desired configuration:

`kubectl create -f https://raw.githubusercontent.com/aojea/kindnet/master/docs/default-configuration.yaml`


## Configuration

TODO https://github.com/aojea/kindnet/issues/23

- [ ] NAT64
- [ ] Tunnel
- [ ] IPSec
- [ ] Network Policies
- [ ] Packet tracing
- [ ] DNS caching
- [ ] Multiple network interfaces


