---
title: "Masquerading"
date: 2024-12-24T11:30:40Z
Weight: 40
---


### The Challenge of External Access

Kubernetes promotes a flat network model where pods can communicate directly with each other without Network Address Translation (NAT). However, for pods to access external resources or be accessible from outside the cluster, they need to use a public IP address. Traditional solutions often involve NAT gateways, which can introduce complexity, scalability bottlenecks, and connection tracking limitations.

### Node-Level Masquerading

Kindnet simplifies this process by utilizing the node's external IP address to masquerade the traffic originating from pods. This means that outgoing traffic from pods appears to originate from the node itself, eliminating the need for a separate NAT gateway.

### Controlling Masquerading Behavior

While Kindnet masquerades traffic from pod subnets by default, you have the flexibility to exclude specific IP ranges from masquerading. This is particularly useful when you need to connect to internal applications or services that should not have their traffic altered.

You can specify a comma-separated list of IP ranges to exclude from masquerading using Kindnet's configuration options. For example, to exclude the 192.168.1.0/24 and 10.10.0.0/16 ranges, you would use the following configuration:

```
--no-masquerade-cidr="192.168.1.0/24,10.10.0.0/16"
```
