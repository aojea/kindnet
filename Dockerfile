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

ARG GOARCH="amd64"
# STEP 1: Build kindnetd binary
FROM golang:1.18 AS builder
# golang envs
ARG GOARCH="amd64"
ARG CNI_VERSION="v1.1.1"
ARG GOOS=linux
ENV CGO_ENABLED=0
ENV GO111MODULE="on"
ENV GOPROXY=https://proxy.golang.org
# copy in sources
WORKDIR /src
COPY . .
# build
RUN CGO_ENABLED=0 go build -o /go/bin/kindnetd ./cmd/kindnetd
# Install CNI plugins
RUN echo "Installing CNI binaries ..." \
    && export CNI_TARBALL="${CNI_VERSION}/cni-plugins-linux-${GOARCH}-${CNI_VERSION}.tgz" \
    && export CNI_URL="https://github.com/containernetworking/plugins/releases/download/${CNI_TARBALL}" \
    && curl -sSL --retry 5 --output /tmp/cni.tgz "${CNI_URL}" \
    && mkdir -p /opt/cni/bin \
    && tar -C /opt/cni/bin -xzf /tmp/cni.tgz \
    && rm -rf /tmp/cni.tgz \
    && find /opt/cni/bin -type f -not \( \
         -iname host-local \
         -o -iname ptp \
         -o -iname bridge \
         -o -iname portmap \
         -o -iname loopback \
      \) \
      -delete
# STEP 2: Build small image
FROM registry.k8s.io/build-image/debian-iptables:bullseye-v1.4.0
COPY --from=builder --chown=root:root /go/bin/kindnetd /bin/kindnetd
COPY --from=builder --chown=root:root /opt/cni/bin /opt/cni/bin
CMD ["/bin/kindnetd"]
