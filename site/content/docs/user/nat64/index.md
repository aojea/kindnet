---
title: "NAT64"
date: 2024-12-24T11:30:40Z
Weight: 100
---

Kindnet simplifies IPv6 adoption in your Kubernetes cluster by providing built-in NAT64 functionality. This feature enables IPv6-only pods to communicate with IPv4 services outside the cluster, ensuring smooth operation even in dual-stack or IPv6-only environments.

### How it Works:

NAT64 allows IPv6-only nodes to transparently access IPv4 resources by translating IPv6 addresses to IPv4 addresses. Kindnet automatically configures a NAT64 gateway for your cluster when using IPv6, using the well-known prefix `64:ff9b::/96`. This means that any traffic destined for this prefix will be automatically translated to IPv4.

### DNS64 Configuration:

To leverage NAT64, you need to configure your DNS provider to offer DNS64 functionality. DNS64 synthesizes AAAA records (IPv6 addresses) for IPv4-only services, enabling IPv6-only clients to resolve these services.

### Recommended DNS Providers:

* **Google Public DNS64:** Google Public DNS provides a global DNS64 service that is easy to configure. You can use their IPv6 DNS server addresses (e.g., 2001:4860:4860::64) to enable DNS64. For more details, refer to the Google Public DNS64 documentation.

* **CoreDNS with DNS64 Plugin:** If you're using CoreDNS for your cluster's DNS, you can enable the DNS64 plugin. This plugin provides flexible configuration options for customizing DNS64 behavior. Refer to the CoreDNS documentation for instructions on how to configure the plugin.