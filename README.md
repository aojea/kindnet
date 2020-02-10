# Simple CNI plugin with IPv4 and IPv6 support

[![CircleCI](https://circleci.com/gh/aojea/kindnet.svg?style=svg)](https://circleci.com/gh/aojea/kindnet)

The main goal of the project is to have a simple CNI plugin for Kubernetes with
IPv4 and IPv6 support that provides the [Cluster
Networking](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

The idea was born because of the lack of IPv6 support in current CNI plugins
and because there are no automatic alternatives to create a multinode kubernetes
cluster with IPv6.

## Important

Kindnet is the default CNI plugin for [KIND](https://github.com/kubernetes-sigs/kind)
and the code was moved to the KIND prokect in-tree.

This repo is kept only for new feature development.

## Kindnet components

It uses the following [standard CNI
plugins](https://github.com/containernetworking/plugins)

* `ptp`: creates a veth pair and adds the host and the container to it.
* `host-local`: maintains a local database of allocated IPs. It uses the
  `ipRanges` capability to provide dynamic configuration for the Pods subnets.
* `portmap`: An iptables-based portmapping plugin. Maps ports from the host's
  address space to the container.


## Installation

The plugin can be installed using the manifest [install-kindnet.yaml](install-kindnet.yaml)

`kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/master/install-kindnet.yaml`


