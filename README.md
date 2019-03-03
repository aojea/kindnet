# Simple CNI plugin with IPv4 and IPv6 support

The main goal of the project is to have a simple CNI plugin for Kubernetes with
IPv4 and IPv6 support that provides the [Cluster
Networking](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

The idea was born because of the lack of IPv6 support in current CNI plugins
and because there are no automatic alternatives to create a multinode kubernetes
cluster with IPv6.

## Kindnet components

It uses the following [standard CNI
plugins](https://github.com/containernetworking/plugins)

* `bridge`: creates a bridge, adds the host and the container to it.
* `host-local`: maintains a local database of allocated IPs. It uses the
  `ipRanges` capability to provide dynamic configuration for the Pods subnets.
* `portmap`: An iptables-based portmapping plugin. Maps ports from the host's
  address space to the container.

And our own daemon:

* `kindnetd`:  polls the k8s api to get the list of Pod subnets assigned to 
each node and install static routes on the local host to the other nodes.

## Installation

The plugin can be installed using the manifest [install-kindnet.yaml](install-kindnet.yaml)

`kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml`

The manifest do the following:

1. Copy an update version of the `bridge` and `host-local` CNI standard CNI
plugins in /opt/cni/bin.

2. Install the configuration file in /etc/cni/net.d/10-kindnet.conflist

3. Rund a DaemonSet with the `kindnetd` daemon


## TODO

Rolling updates
Windows support
Multi-platform support


