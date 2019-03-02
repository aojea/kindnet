# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG BASE_IMAGE="ubuntu:18.04"
FROM ${BASE_IMAGE}

# Install curl
RUN apt-get update && \
    apt-get install -y curl && \
    rm -rf /var/lib/apt/lists/* 

# Install CNI binaries to /kindnet/cni
ARG ARCH="amd64"
ARG CNI_VERSION="v0.7.4"
ARG CNI_TARBALL="cni-plugins-${ARCH}-${CNI_VERSION}.tgz"
ARG CNI_BASE_URL="https://github.com/containernetworking/plugins/releases/download/"
ARG CNI_URL="${CNI_BASE_URL}${CNI_VERSION}/${CNI_TARBALL}"
RUN curl -sSL --retry 5 --output /tmp/cni.tgz "${CNI_URL}" \
    && sha256sum /tmp/cni.tgz \
    && mkdir -p /kindnet/cni \
    && tar -C /kindnet/cni -xzf /tmp/cni.tgz \
    && rm -rf /tmp/cni.tgz

COPY ./kindnetd /kindnetd
CMD /kindnetd
