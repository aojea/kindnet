# Simple CNI plugin with IPv4, IPv6 and DualStack support

The main goal of the project is to have a simple CNI plugin for Kubernetes with
IPv4 and IPv6 support that provides the [Cluster
Networking](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

The idea was born because of the lack of IPv6 support in current CNI plugins
and because there are no automatic alternatives to create a multinode kubernetes
cluster with IPv6.

The plugin only works on "simple" network environments, when all the cluster nodes
belong to the same subnet.

Kindnet evolved adding new features, as an embedded ipmasq agent and nowadays, 
is the default CNI plugin for [KIND](https://github.com/kubernetes-sigs/kind)

All the stable code was moved to the KIND project in-tree.
This repo is kept only for new features development and for experimenting
using it on "real" clusters.


## Kindnet components

It uses the following [standard CNI
plugins](https://github.com/containernetworking/plugins)

* `ptp`: creates a veth pair and adds the host and the container to it.
* `bridge`: creates a bridge, adds the host and the container to it.
* `host-local`: maintains a local database of allocated IPs. It uses the
  `ipRanges` capability to provide dynamic configuration for the Pods subnets.
* `portmap`: An iptables-based portmapping plugin. Maps ports from the host's
  address space to the container.

And a daemon named `kindnetd` with the following features:

* `CNI config`: configures the CNI plugin dropping the file `/etc/cni/net.d/10-kindnet.conflist`
* `routing`: install routes on the to the POD subnets in the other nodes
* `ip-masq`: non masquerade traffic that is directed to PODs 

## Installation

Kindnet can be installed on your cluster using the manifest [install-kindnet.yaml](install-kindnet.yaml)

`kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml`

By default, the `ptp` CNI plugin is used, but the `bridge` plugin can be selected by setting the environment
variable `CNI_BRIDGE` in the `kindnet-cni` container. You can use the following manifest directly:

`kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet-bridge.yaml`


Kindnet installation manifest has an init container that drop the CNI binaries in the folder `/opt/cni/bin/`, however, you can install them directly supressing the init container in the manifest and
following the next steps:

```sh
export ARCH="amd64"
export CNI_VERSION="v1.1.1"
export CNI_TARBALL="${CNI_VERSION}/cni-plugins-linux-${ARCH}-${CNI_VERSION}.tgz"
export CNI_URL="https://github.com/containernetworking/plugins/releases/download/${CNI_TARBALL}"
curl -sSL --retry 5 --output /tmp/cni.tgz "${CNI_URL}"
mkdir -p /opt/cni/bin
tar -C /opt/cni/bin -xzf /tmp/cni.tgz
rm -rf /tmp/cni.tgz
```

