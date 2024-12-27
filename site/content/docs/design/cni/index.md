---
title: "CNI"
date: 2024-12-26T22:54:48Z
---

## CNI-kindnet

Kubernetes container runtimes relies on the Container Network Interface (CNI) standard to manage Pod networking. While CNI provides a general framework for container networking, its full feature set isn't necessary for Kubernetes environments. This presents an opportunity for optimization.

At its core, Kubernetes has two primary networking requirements for CNI:

- **IP Address Management (IPAM):** Assign IP addresses to Pods.
- **Interface Configuration:** Create and configure network interfaces within Pods.

Many CNI plugins, however, are designed for more complex scenarios beyond Kubernetes' needs. This can lead to unnecessary overhead and complexity.

**NOTE** Usually the "CNI plugin" term is used to refer to "Kubernetes network plugins", that offer more networking capabilities, like Services, Network Policies, ... `kindnet` is a Network Plugin that uses cni-kindnet to assign IP to Pods and create its interfaces.

Traditional CNI plugins often rely on in-memory data structures or external daemon processes to manage network state. This can introduce challenges:

- **Process Dependencies:** Relying on daemons creates extra dependencies. If a daemon crashes or fails to restart correctly, it can disrupt network operations and complicate recovery.

- **Reconciliation Overhead:** Maintaining consistency between in-memory state and the actual network configuration requires complex reconciliation loops, which can consume resources and introduce delays.

`cni-kindnet` leverages SQLite3, a lightweight database, to maintain state and streamline operations. This eliminates the need for external daemons or complex chaining, resulting in a more efficient and reliable plugin.

### Portmaps / HostPorts

`cni-kindnet` also implements the Kubernetes' hostPort feature. This feature allows you to map a port on the host machine directly to a port on a Pod, making the Pod accessible from outside the cluster network.

### Configuration

The CNI configuration file only expect the `ranges` field to be populated with the ranges used to provide IP addresses to the Pods. `kindnetd` obtains those ranges from the `node.Spec.PodCIDRs` field, but the design of the CNI allows to add additional ranges, useful for environments that require to extend the number of available IPs on the Nodes.

```json
{
  "cniVersion": "0.4.0",
  "name": "kindnet",
  "plugins": [
    {
      "type": "cni-kindnet",
      "ranges": [
        "10.244.2.0/24"
      ],
      "capabilities": {"portMappings": true}
    }
  ]
}
```

### Database Design

[![](https://mermaid.ink/img/pako:eNqVU01rwzAM_StB5_Y2dsitsB12KAx2GwGjxWpqqD-Q5Y3S5r_PaZaka7LCfLLfe3qWJfkEtdcEJRA_GWwYbeWKvILXsTif1-vzKe9ZLAZFTthQLMqi9k7QuNhrTUCrGF2TuXYI0Z2ugpfXzbaCK89Tv-9WzHauGcyIldEz0qGlRTAGrOdMWrIgGTK9Qk1QqDVTjOrzYYltUOgLj3-wY-zj3dgF1gnxLueuFp820VZSz7bzKs-LGNNHfucM1hRrNkGMd7_Mblv6z67sfRRlwoTntHuwM57JA3vxtT_cu-TGbGImxxZWYIktGp0H9pJyBbKnXEboZk3TDtNBunHrpJjEvx1dDaVwohWkoHNbfqYcyh0e4og-ayOeR5Aux23_My4fZAXsU7MfFQHdu_eDTfsNPzwQ8A?type=png)](https://mermaid.live/edit#pako:eNqVU01rwzAM_StB5_Y2dsitsB12KAx2GwGjxWpqqD-Q5Y3S5r_PaZaka7LCfLLfe3qWJfkEtdcEJRA_GWwYbeWKvILXsTif1-vzKe9ZLAZFTthQLMqi9k7QuNhrTUCrGF2TuXYI0Z2ugpfXzbaCK89Tv-9WzHauGcyIldEz0qGlRTAGrOdMWrIgGTK9Qk1QqDVTjOrzYYltUOgLj3-wY-zj3dgF1gnxLueuFp820VZSz7bzKs-LGNNHfucM1hRrNkGMd7_Mblv6z67sfRRlwoTntHuwM57JA3vxtT_cu-TGbGImxxZWYIktGp0H9pJyBbKnXEboZk3TDtNBunHrpJjEvx1dDaVwohWkoHNbfqYcyh0e4og-ayOeR5Aux23_My4fZAXsU7MfFQHdu_eDTfsNPzwQ8A)

There are three tables required to store the existing state of the Node.

* `ipam_ranges` table, contain the IP ranges used to provide IPs to Pods:

```sql
CREATE TABLE IF NOT EXISTS ipam_ranges (
  id INTEGER PRIMARY KEY AUTOINCREMENT, -- Unique identifier for the IP range
  subnet TEXT NOT NULL,                 -- Subnet in CIDR notation (e.g., "10.244.0.0/16")
  description TEXT                      -- Optional description of the IP range
);
```

* `pods` table, store all the Pods information:

```sql
CREATE TABLE IF NOT EXISTS pods (
  container_id TEXT PRIMARY KEY,     -- ID of the pod Sandbox on the container runtime
  name TEXT,                -- Kubernetes name of the pod
  namespace TEXT,           -- Kubernetes namespace of the pod
  uid TEXT,          			  -- Kubernetes UID of the pod
  netns TEXT NOT NULL,      -- Network namespace path of the pod
  ip_address_v4 TEXT,       -- IPv4 address assigned to the pod
  ip_address_v6 TEXT,       -- IPv6 address assigned to the pod
  ip_gateway_v4 TEXT,       -- IPv4 gateway assigned to the pod
  ip_gateway_v6 TEXT,       -- IPv6 gateway assigned to the pod
  interface_name TEXT NOT NULL,      -- Name of the network interface of the pod in the host
  interface_mtu INTEGER,             -- Interface mtu
  creation_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, -- Timestamp of pod creation
  UNIQUE (ip_address_v4),           -- Unique constraint for IPv4 address
  UNIQUE (ip_address_v6)            -- Unique constraint for IPv6 address
);
```

* `portmap_entries` table, entries will be automatically deleted once the associated Pod is deleted from the `pods` table.

```sql
CREATE TABLE IF NOT EXISTS portmap_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    container_id TEXT NOT NULL,
    host_ip TEXT NOT NULL,
    host_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    container_ip TEXT NOT NULL,
    container_port INTEGER NOT NULL,
    FOREIGN KEY (container_id) REFERENCES pods(container_id) ON DELETE CASCADE,
    UNIQUE (host_ip, host_port, protocol) -- Unique constraint
);
```

