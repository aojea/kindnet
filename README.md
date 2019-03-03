# Simple CNI plugin with IPv4 and IPv6 support

The main goal of the project is to provide
[kind](https://github.com/kubernetes-sigs/kind) with a simple CNI that
supports IPv4 and IPv6 and to reduce and minimize the dependencies on external
projects for testing.

This is a simple daemon that polls the k8s api to get the list of nodes and the
podCIDR assigned and install static routes to provide connectivity.

In addition, the container has the last version of the  cniplugin, that can be
used to deploy them inside the k8s nodes.

TODO

Rolling updates
Windows support
Multi-platform support


