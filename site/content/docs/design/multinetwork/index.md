---
title: "Multi Network"
date: 2025-01-17T22:54:48Z
---

## Multi Network


Kubernetes' Dynamic Resource Allocation (DRA) framework enables advanced resource management, allowing users to request and consume resources beyond standard CPU and memory. The networking DRA driver leverages this framework to manage network interfaces, providing capabilities to allocate physical interfaces.

You can find more details about the big picture in the following presentation:

<iframe src="https://docs.google.com/presentation/d/e/2PACX-1vSmfWqZ6qbMkboeivuK3Lachvua00v40I6_-XaPlDSCGu6OfRYrtkWR6otiyRWy6mw2zqcHq-criV4S/embed?start=true&loop=true&delayms=3000" frameborder="0" width="960" height="569" allowfullscreen="true" mozallowfullscreen="true" webkitallowfullscreen="true"></iframe>

### Architecture

The networking DRA driver uses GRPC to communicate with the Kubelet via the [DRA API](https://github.com/kubernetes/kubernetes/blob/3bec2450efd29787df0f27415de4e8049979654f/staging/src/k8s.io/kubelet/pkg/apis/dra/v1beta1/api.proto) and the Container Runtime via [NRI](https://github.com/containerd/nri). This architecture facilitates the supportability and reduces the complexity of the solution.

The DRA driver, once the Pod network namespaces has been created, will receive a GRPC call from the Container Runtime via NRI to execute the corresponding configuration. A more detailed diagram can be found in:

[![](https://mermaid.ink/img/pako:eNp9UstuwyAQ_JUVp1ZNfoBDpMi-WFXdyLn6gs0mQTXgLtCHovx714nTWoobDgiW2dlhNEfReo1CioDvCV2LuVF7UrZ2wEul6F2yDdLl_pwa7DAul6vVU4nx09Mb5NUacjIfSBJK5toQ9oqwwuATtRgeHi-9pY8InmEw1_naRGUcxAPCtTPrlLF8Y10hgnIaMu92Zj_S3ZAMqpajwvtSrt_gXzDlMBhJS6iS23i95UmN_7pi_wADf1YWEniDdZ6P72VxfpjwMEmxCXPts55VBRy8f5sff981xoMb605ZDL1qGd4jqWi8C_esmiqGG7FTK2eF_eNhRqgi_lbCjI1T6lu4WAiLZJXRHMrj0FwLToXFWkg-atyp1MVa1O7E0CGg22_XChkp4UKkXjPfmGEhd6oLXEVtoqeXS9DPeT_9ABUC_8M?type=png)](https://mermaid.live/edit#pako:eNp9UstuwyAQ_JUVp1ZNfoBDpMi-WFXdyLn6gs0mQTXgLtCHovx714nTWoobDgiW2dlhNEfReo1CioDvCV2LuVF7UrZ2wEul6F2yDdLl_pwa7DAul6vVU4nx09Mb5NUacjIfSBJK5toQ9oqwwuATtRgeHi-9pY8InmEw1_naRGUcxAPCtTPrlLF8Y10hgnIaMu92Zj_S3ZAMqpajwvtSrt_gXzDlMBhJS6iS23i95UmN_7pi_wADf1YWEniDdZ6P72VxfpjwMEmxCXPts55VBRy8f5sff981xoMb605ZDL1qGd4jqWi8C_esmiqGG7FTK2eF_eNhRqgi_lbCjI1T6lu4WAiLZJXRHMrj0FwLToXFWkg-atyp1MVa1O7E0CGg22_XChkp4UKkXjPfmGEhd6oLXEVtoqeXS9DPeT_9ABUC_8M)

### Key Components

* **DRA Driver:**
    * Runs as a kindnet daemon on each node.
    * Communicates with the Kubelet and Container Runtime via GRPC.
    * Manages the allocation and configuration of network interfaces.
    * Monitors the state of network interfaces.
* **ResourceClaim:**
    * A Kubernetes resource that represents a user's request for a network interface.
    * Contains parameters specifying the desired interface mode and configuration.
* **NRI (Node Runtime Interface):**
    * Interface that the container runtime uses to communicate with the DRA driver.

## Workflow

1.  **User Request:** A user creates a `ResourceClaim` object to request a network interface.
2.  **Resource Allocation:** The DRA driver allocates a matching Network Interface resource based on the `ResourceClaim` parameters.
3.  **Pod Configuration:** When a pod using the `ResourceClaim` is scheduled, the DRA driver configures the network interface according to the requested mode.
4.  **Pod Execution:** The pod runs with the configured network interface.
5.  **Resource Deallocation:** When the pod is deleted, the DRA driver deallocates the network interface.
