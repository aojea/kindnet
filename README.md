# Kindnet: A Minimalistic Kubernetes Network Plugin

Kindnet is a simple and lightweight Kubernetes network plugin designed for performance and scalability.

<p align="center"><img alt="musselgrinho" src="./musselgrinho.png" width="300px" /></p>

## Goal

Born from years of experience running and debugging complex network issues in Kubernetes, Kindnet focuses on providing essential networking functionality without unnecessary complexity. It's opinionated by design, so you can focus on your applications, not your network.

## History

The original goal of the project was to have a simple networking plugin for Kubernetes with
IPv4 and IPv6 support that provides the [Cluster
Networking](https://kubernetes.io/docs/concepts/cluster-administration/networking/)

The idea was born because of the lack of IPv6 support in current CNI plugins
and because there are no automatic alternatives to create a multinode kubernetes
cluster with IPv6.

Kindnet evolved adding new features, as an embedded ipmasq agent and nowadays, 
is the default CNI plugin for [KIND](https://github.com/kubernetes-sigs/kind)
and is used for testing the [Kubernetes project](https://github.com/kubernetes/kubernetes).

All the stable code moves to the KIND project in-tree.
This repo is kept only for new features development and get feedback of people
using it on "real" clusters.

## Features

* Minimalistic design: Focuses on core networking essentials.
* High performance: Low overhead for optimal network throughput.
* Scalability: Handles growing clusters with ease.
* Simplicity: Easy to set up and configure.
* Just works: Provides reliable and seamless networking for your pods.

## Use Cases

* Resource-constrained environments: Ideal for small deployments or edge computing.
* Performance-critical applications: Minimizes network latency for demanding workloads.
* Development and testing: Provides a simple and reliable network for Kubernetes testing.
* Learning Kubernetes networking: A great tool for understanding the basics of Kubernetes networking.

## How it Works

Kindnet uses a simple point to point model to connect pods within the same node.  It leverages the host's network stack for external communication, eliminating the need for complex overlay networks.

## Installation

Kindnet can be installed on your cluster using the manifest [install-kindnet.yaml](install-kindnet.yaml)

```sh
kubectl create -f https://raw.githubusercontent.com/aojea/kindnet/main/install-kindnet.yaml
```

## Contributing
 
Please report any issues in the Github project.
The bar for new features is really high and has to be stricted aligned with the [Goal](#goal) of the project.
Per example, adding networking overlay functionality is out of the scope of the project.

## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [Slack](https://slack.k8s.io/)
- [Mailing List](https://groups.google.com/a/kubernetes.io/g/dev)

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).

[owners]: https://git.k8s.io/community/contributors/guide/owners.md
[Creative Commons 4.0]: https://git.k8s.io/website/LICENSE

## License

Kindnet is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.
