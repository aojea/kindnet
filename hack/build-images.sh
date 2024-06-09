#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPT_ROOT=$(cd $(dirname ${BASH_SOURCE})/.. && pwd)
echo "SCRIPT_ROOT ${SCRIPT_ROOT}"
# docker image registry, default to upstream
REGISTRY=${REGISTRY:-ghcr.io/aojea}
# tag based on date-sha
TAG=${TAG:-$(date +v%Y%m%d)-$(git describe --always --dirty)}

echo "Creating controller image ${REGISTRY}/kindnet-controller:${TAG}"
docker build . -f Dockerfile.kindnet-controller -t ${REGISTRY}/kindnet-controller:${TAG}

echo "Creating kindnetd image ${REGISTRY}/kindnetd:${TAG}"
docker build . -f Dockerfile.kindnetd -t ${REGISTRY}/kindnetd:${TAG}
