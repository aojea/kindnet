---
title: "Network Policies"
date: 2024-12-24T11:30:40Z
Weight: 20
---

## Kubernetes Network Policies

Kindnet implements [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) using the [kube-network-policies](https://github.com/kubernetes-sigs/kube-network-policies) project, which employs a "first-packet inspection" approach:

When a new connection is attempted, the first packet is intercepted and evaluated against defined network policies in user space. This determines if the connection is allowed.  The resulting verdict is cached, optimizing subsequent traffic on that connection by avoiding repeated user space processing. If allowed, the host's dataplane (e.g., iptables) is programmed to handle further traffic efficiently.

## Admin Network Policies

Beyond standard Kubernetes Network Policies, Kindnet also supports Kubernetes [Admin Network Policies](https://network-policy-api.sigs.k8s.io/user-stories/). This powerful feature provides cluster administrators with greater control over network traffic by enabling them to define and enforce policies at the cluster level, complementing namespace-level policies.