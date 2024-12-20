---
title: "Quick Start"
date: 2024-12-17T14:47:05Z
weight: 1
---

## How it Works

KindNet uses a simple veth network interface to connect pods within the same node.  It leverages the host's network stack for external communication, eliminating the need for complex overlay networks.

## Installation

Kindnet can be installed on your cluster using the manifest [install-kindnet.yaml](install-kindnet.yaml)

```sh
kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/main/install-kindnet.yaml
```

By default, the `ptp` CNI plugin is used, but the `bridge` plugin can be selected by setting the environment
variable `CNI_BRIDGE` in the `kindnet-cni` container. You can use the following manifest directly:

```sh
kubectl create -f
https://raw.githubusercontent.com/aojea/kindnet/main/install-kindnet-bridge.yaml
```