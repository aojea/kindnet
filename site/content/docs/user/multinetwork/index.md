---
title: "Multi Network"
date: 2025-03-14T12:39:58Z
Weight: 70
---


Kindnet uses Dynamic Resource Allocation to provide native multi-network
capabilities to Kubernetes, for more information about the techical details
please check the [Multi Network Design docs](/docs/design/multinetwork/).

### Network Interface Modes

This solution provides flexibility in network interface configuration through
three primary modes: access, trunk, and hybrid.

* Access Mode

In access mode, the entire physical network interface is consumed by the. The interface
is moved entired to the Pod with its existing configuration.

* Trunk Mode (Macvlan)

In trunk mode, the physical network interface serves as a parent for multiple macvlan sub-interfaces. Each macvlan sub-interface provides a distinct network interface to pods, effectively allowing multiple isolated network connections to be created on the same physical link.

* Hybrid (Mixed) Mode

Hybrid (or mixed) mode combines the functionalities of both access and trunk modes. A single physical interface can be configured to operate as either an access or trunk port, or potentially both.

### Resource Driver Implementation

On startup, the driver scans the network interfaces in the host to determine initial capabilities.

The driver also monitors for changes in interface configuration.

When a ResourceClaim is created, the driver finds the matchin Network Interface:

* For access mode, it allocates the entire interface.

* For trunk mode, it creates a macvlan sub-interface.

The driver updates the available and allocatedTo fields in the ResourceClaim resource.

### Examples

```yaml
apiVersion: resource.k8s.io/v1beta1
kind: DeviceClass
metadata:
  name: kindnet-link-macvlan
spec:
  selectors:
    - cel:
        expression: device.driver == "dra.kindnet.es"
    - cel:
        expression: device.attributes["dra.kindnet.es"].mode == "trunk"
```

```yaml
apiVersion: resource.k8s.io/v1beta1
kind:  ResourceClaim
metadata:
  name: netdev-access
spec:
  devices:
    requests:
    - name: netdev-access
      deviceClassName: dra.kindnet.es
    config:
    - opaque:
        driver: dra.kindnet.es
        parameters:
          newName: "eth99"
          address: "192.168.2.2"
          mask: "255.255.255.0"
          mtu: "1500"
---
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  labels:
    app: pod
spec:
  containers:
  - name: ctr1
    image: registry.k8s.io/e2e-test-images/agnhost:2.39
  resourceClaims:
  - name: trunk
    resourceClaimName: kindnet-link-trunk
```