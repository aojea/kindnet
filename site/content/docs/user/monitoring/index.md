---
title: "Monitoring"
date: 2024-12-24T11:30:40Z
Weight: 20
---

Kindnet provides monitoring capabilities by exposing key metrics that offer insights into the health and performance of your cluster's network. These metrics can be easily collected using Prometheus and visualized with Grafana for effective monitoring and troubleshooting.

### Metrics Endpoint

Kindnet exposes its metrics on an HTTP endpoint that can be configured through the --metrics-bind-address flag. By default, the endpoint is available at :19080/metrics. This endpoint provides data in the Prometheus exposition format, making it readily consumable by Prometheus.

### Collecting Metrics with Prometheus

To collect Kindnet metrics, you'll need to configure your Prometheus instance to scrape the metrics endpoint. This can be achieved by adding a new scrape configuration in your prometheus.yml file:

```yaml
scrape_configs:
  - job_name: 'kindnet'
    static_configs:
      - targets: ['localhost:19080']
```

This configuration instructs Prometheus to scrape the Kindnet metrics endpoint at regular intervals. You can adjust the targets field to match the address and port where your Kindnet metrics are exposed.

### Visualizing Metrics with Grafana

Once Prometheus is collecting Kindnet metrics, you can leverage Grafana to create informative dashboards for visualization and analysis. Grafana provides a wide range of visualization options, allowing you to create graphs, charts, and tables to represent the collected data.

You can create a Grafana dashboard to monitor key Kindnet metrics such as:

- **Network Traffic:** Track the amount of data transmitted and received by pods.
- **Connection Counts:** Monitor the number of active connections between pods and external services.
- **DNS Queries:** Observe the volume and latency of DNS queries within the cluster.
- **NAT64 Translations:** Track the number of IPv6 to IPv4 address translations performed by NAT64.

By visualizing these metrics, you can gain a comprehensive understanding of your cluster's network performance, identify potential bottlenecks, and proactively address issues that may arise.
