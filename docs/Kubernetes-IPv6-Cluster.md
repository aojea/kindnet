# Kubernetes IPv6 Cluster with `kindnet`

## Overview

If you want to try Kubernetes with IPv6 you can have a working IPv6 cluster using
 then [kindnet CNI plugin](https://github.com/aojea/kindnet)

To test it we can use the [kind project](https://github.com/kubernetes-sigs/kind)
to create a Docker in Docker Kubernetes cluster in your host.

## Requirements

Support for IPv6 in `kind` is still a WIP, but you can use [this provisional fork](https://github.com/aojea/kind/releases/tag/v.0.1-alpha) in the meantime.

Remember that you have to enable IPv6 in your host and in [your Docker daemon](https://docs.docker.com/config/daemon/ipv6/)

## Instructions

1. Install the modified `kind` and the official `kubectl` binaries:

```
# Kubectl
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x kubectl
cp kubectl /usr/local/bin

# Kind with IPv6 support using kindnet
curl -LO https://github.com/aojea/kind/releases/download/v.0.1-alpha/kind_linux_amd64.gz
gunzip kind_linux_amd64.gz
chmod +x  kind_linux_amd64
cp kind_linux_amd64 /usr/local/bin/kind
```

2. Create a new `node-image` with the `kindnet` CNI plugin

`kind build node-image --base-image kindest/base:latest --type apt`

In this example we are using `apt` to create the kind image, but you can checkout
the [Kubernetes](https://github.com/kubernetes/kubernetes) repository and build 
the image  with `bazel`.

3. Create the config file with your topology. This example creates a k8s cluster with
 1 control plane node and 2 workers:  


```
kind: Config
apiVersion: kind.sigs.k8s.io/v1alpha2
nodes:
- role: control-plane
  replicas: 1
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta1
    kind: ClusterConfiguration
    metadata:
      name: config
    networking:
      podSubnet: "fd00:100::/64"
      serviceSubnet: "fd00:1234::/112"
- role: worker
  # replicas specifes the number of nodes to create with this configuration
  replicas: 2
```

4. Use the file to launch the cluster, in this case we assume the filename is 
`config-ipv6.yaml`

`kind create cluster --ipv6 --config config-ipv6.yaml --image kindest/node:latest`

## Check your cluster status

You can check that all the nodes have IPv6 addresses

```
 kubectl get nodes -o wide
NAME                 STATUS    ROLES     AGE       VERSION          INTERNAL-IP              EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION                CONTAINER-RUNTIME
kind-control-plane   Ready     master    3m9s      v1.14.0-beta.1   2001:db8:1::242:ac11:3   <none>        Ubuntu 18.04.1 LTS   4.12.14-lp150.12.45-default   docker://18.6.3
kind-worker1         Ready     <none>    2m31s     v1.14.0-beta.1   2001:db8:1::242:ac11:4   <none>        Ubuntu 18.04.1 LTS   4.12.14-lp150.12.45-default   docker://18.6.3
kind-worker2         Ready     <none>    2m16s     v1.14.0-beta.1   2001:db8:1::242:ac11:5   <none>        Ubuntu 18.04.1 LTS   4.12.14-lp150.12.45-default   docker://18.6.3
```

and the same with the services endpoints

```
kubectl -n kube-system get ep -o wide
NAME                      ENDPOINTS                                                        AGE
kube-controller-manager   <none>                                                           4m34s
kube-dns                  [fd00:100::2]:53,[fd00:100::3]:53,[fd00:100::2]:53 + 3 more...   4m17s
kube-scheduler            <none>                                                           4m36s
```

The pods can obtain IPv6 addresses:

```
 kubectl run -i --tty busybox12 --image=busybox --restart=Never -- sh
If you don't see a command prompt, try pressing enter.
/ # ip -6 a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qlen 1000
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 1500
    inet6 fd00:100::1:0:0:2/80 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::5c62:8aff:fe75:7ce0/64 scope link
       valid_lft forever preferred_lft forever
```

with pod connectivity between nodes (fd00:100::2 is the CoreDNS pod IPv6 address)


```
/ # ping fd00:100::2
PING fd00:100::2 (fd00:100::2): 56 data bytes
64 bytes from fd00:100::2: seq=0 ttl=62 time=0.181 ms
64 bytes from fd00:100::2: seq=1 ttl=62 time=0.151 ms
```

and pod to service connectivity (fd00:1234::a is the CoreDNS service IPv6 address)

```
/ # nc -zv fd00:1234::a 53
fd00:1234::a ([fd00:1234::a]:53) open
```

if you want to provide IPv4 access to your IPv6 applications you can use a
[Dual-Stack Ingress Controller](https://github.com/leblancd/kube-v6/tree/master/dual-stack-ingress)

## Acknowledgments

This work is based on @leblanc's [Instructions on how to instantiate a multi-node, IPv6-only Kubernetes cluster.](https://github.com/leblancd/kube-v6)

