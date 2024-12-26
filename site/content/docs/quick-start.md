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

Kindnet provides IPAM to the Pods and other functionality like Network Policies, check the documentation for more advanced use cases. 