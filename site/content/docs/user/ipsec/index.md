---
title: "IPSec"
date: 2025-01-17T12:39:58Z
Weight: 60
---

Kindnet provides an overlay network that enables communication between Pods and nodes within a Kind cluster using IPsec tunnels.

IPsec encrypts and authenticates traffic between nodes, ensuring confidentiality and integrity. This is especially important in clusters where the underlying network might not be trusted (e.g., a shared development network).

### IPsec Tunnel Mode in kindnetd

kindnetd leverages IPsec tunnel mode to create an overlay network that functions independently of the underlying network infrastructure. This is often referred to as "island mode" because the Kind cluster operates as a self-contained network island, isolated from the surrounding network.
