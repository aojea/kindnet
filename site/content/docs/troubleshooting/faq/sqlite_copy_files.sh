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