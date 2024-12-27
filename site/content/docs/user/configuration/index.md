---
title: "Configuration Options"
date: 2024-12-27T12:39:58Z
Weight: 10
---

Kindnet can be customized through the use of flags passed to the kind create cluster command. These flags allow you to adjust various aspects of the network environment.

### Feature flags:

```
  -control-plane-endpoint string
        The URL of the control plane
  -dns-caching
        If set, enable Kubernetes DNS caching (default false)
  -hostname-override string
        If non-empty, will be used as the name of the Node that kube-network-policies is running on. If unset, the node name is assumed to be the same as the node's hostname.
  -masquerading
        masquerade with the Node IP the cluster to external traffic (default true)
  -metrics-bind-address string
        The IP address and port for the metrics server to serve on (default ":19080")
  -nat64
        If set, enable NAT64 using the reserved prefix 64:ff9b::/96 on IPv6 only clusters (default true on IPv6 clusters)
  -network-policy
        If set, enable Network Policies (default true) (default true)
  -no-masquerade-cidr string
        Comma seperated list of CIDRs that will not be masqueraded.
  -fastpath-threshold int
        The number of packets after the traffic is offloaded to the fast path, zero disables it (default 20).
```

### Log flags:

Kindnet uses [klog](https://github.com/kubernetes/klog) for logging, so all those flags and features are available:

```
  -add_dir_header
        If true, adds the file directory to the header of the log messages
  -alsologtostderr
        log to standard error as well as files (no effect when -logtostderr=true)
  -log_backtrace_at value
        when logging hits line file:N, emit a stack trace
  -log_dir string
        If non-empty, write log files in this directory (no effect when -logtostderr=true)
  -log_file string
        If non-empty, use this log file (no effect when -logtostderr=true)
  -log_file_max_size uint
        Defines the maximum size a log file can grow to (no effect when -logtostderr=true). Unit is megabytes. If the value is 0, the maximum file size is unlimited. (default 1800)
  -logtostderr
        log to standard error instead of files (default true)
  -one_output
        If true, only write logs to their native severity level (vs also writing to each lower severity level; no effect when -logtostderr=true)
  -skip_headers
        If true, avoid header prefixes in the log messages
  -skip_log_headers
        If true, avoid headers when opening log files (no effect when -logtostderr=true)
  -stderrthreshold value
        logs at or above this threshold go to stderr when writing to files and stderr (no effect when -logtostderr=true or -alsologtostderr=true) (default 2)
  -v value
        number for the log level verbosity
  -vmodule value
        comma-separated list of pattern=N settings for file-filtered logging
```