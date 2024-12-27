---
title: "DNS cache"
date: 2024-12-27T12:39:58Z
Weight: 50
---

Kindnet enhances your cluster's network performance with a built-in DNS cache. This feature transparently intercepts DNS requests within your cluster and stores the results, reducing latency and improving name resolution speed.

### How it Works

When a pod in your cluster performs a DNS lookup, Kindnet checks its internal cache for the corresponding record. If found, the cached response is returned immediately, eliminating the need to query external DNS servers. If the record is not cached, Kindnet forwards the request to the configured upstream DNS server, stores the response in its cache, and then delivers it to the pod.

### Configuration

Kindnet's DNS cache is disabled by default and requires no specific configuration. It automatically captures DNS traffic destined for the configured DNS domain in your cluster and caches entries for 30 seconds. This caching duration strikes a balance between performance gains and ensuring that DNS records are relatively up-to-date.

### Note

The DNS cache feature complements and works in conjunction with external DNS providers. It acts as an intermediary layer, optimizing DNS resolution within your cluster without interfering with your existing DNS infrastructure.