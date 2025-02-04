---
title: "FAQ"
date: 2025-02-04T17:33:28+01:00
draft: true
---

## Where are the binary files located in pod started by daemon set?

The Kindnet lightweight daemon binary file is located in:

```bash
/bin/kindnetd
```

The CNI plugin binary file is located in:

```bash
/opt/cni/bin/cni-kindnet
```

## Where is configuration file used by CNI in pod tarted by daemon set?

```bash
/etc/cni/net.d/10-kindnet.conflist
```

## How to check `Kindnet` logs ?

In order to retrieve and follow the logs of the `kindnet` DaemonSet in the `kube-system` namespace, use command:

```bash
kubectl -n kube-system logs ds/kindnet -f
```

If there is a need to debug specific pod running on selected node, check at first pod name:

```bash
kubectl get pods -n kube-system -l app=kindnet -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName
```

then verify logs:

```bash
kubectl -n kube-system logs kindnet-z5tst -f
```

In order to change log verbosity, edit `install-kindnet.yaml` used for `kindnet` configuration or use imperative approach to change option `-v`:

```bash
kubectl -n kube-system edit ds/kindnet
```

More information about log flags can be found in [Configuration Options](../../user/configuration/).

## How to access `SQLite3` database?

**Prerequisite**: Install `sqlite3`, `jq` and `kubectl` for your OS.

1. Prepare [the bash script to copy files from the SQLite3 database to your local machine](sqlite_copy_files.sh):

```bash
#!/bin/bash

NAMESPACE="kube-system"
LABEL_SELECTOR="app=kindnet"
CONTAINER_NAME="kindnet-cni"
DEST_DIR="./db"

# Create destination directory if it doesn't exist
mkdir -p $DEST_DIR

# Get the names of worker nodes
WORKER_NODES=$(kubectl get nodes -o json | jq -r '.items[] | select(.metadata.labels["node-role.kubernetes.io/control-plane"] | not) | .metadata.name')

# Loop through each worker node and get the Kindnet pods running on them
for NODE in $WORKER_NODES; do
  echo "Getting pods on worker node: $NODE"
  PODS=$(kubectl get pods -n $NAMESPACE -l $LABEL_SELECTOR --field-selector spec.nodeName=$NODE -o custom-columns=:metadata.name)
  
  # Loop through each pod and copy the files
  for POD in $PODS; do
    echo "Copying files from pod: $POD, container: $CONTAINER_NAME"
    kubectl cp $NAMESPACE/$POD:var/lib/cni-kindnet/cni.db $DEST_DIR/$POD-cni.db -c $CONTAINER_NAME 2>/dev/null
    kubectl cp $NAMESPACE/$POD:var/lib/cni-kindnet/cni.db-wal $DEST_DIR/$POD-cni.db-wal -c $CONTAINER_NAME 2>/dev/null
    kubectl cp $NAMESPACE/$POD:var/lib/cni-kindnet/cni.db-shm $DEST_DIR/$POD-cni.db-shm -c $CONTAINER_NAME 2>/dev/null
  done
done

echo "Files copied to $DEST_DIR"
```

2. Copy files by executing [sqlite_copy_files.sh](./sqlite_copy_files.sh) e.g.:

```
Getting pods on worker node: home-lab-worker
Copying files from pod: kindnet-sgtxm, container: kindnet-cni
Getting pods on worker node: home-lab-worker2
Copying files from pod: kindnet-j7s8r, container: kindnet-cni
Files copied to ./db
```

3. Access SQLite3 database:

```bash
sqlite3 db/kindnet-j7s8r-cni.db

SQLite version 3.43.2 2023-10-10 13:08:14
Enter ".help" for usage hints.
sqlite> .tables
ipam_ranges      pods             portmap_entries

sqlite> select * from pods limit 1;
159d3e9f868f1fdb36c4ace370888f4a900ebdabb5bf623b298f28a2f243b440|local-path-provisioner-57c5987fd4-gq4jb|local-path-storage|91e3e22d-5cdb-4851-b3c8-5211dba96b5d|/var/run/netns/cni-37f62d39-c60c-6257-d150-d4cc6c790403|192.168.1.209||192.168.1.0||knetc098226f|65535|2025-02-04 16:37:33

sqlite> select * from ipam_ranges;
1|192.168.1.0/24|
```
