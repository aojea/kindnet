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

# STEP 1: Build kindnetd binary
FROM --platform=$BUILDPLATFORM golang:1.23 AS builder
# golang envs
ARG CNI_VERSION="v1.5.1"
ENV CGO_ENABLED=0
# copy in sources
WORKDIR /src
COPY . .
# build
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/kindnetd ./cmd/kindnetd
# Install CNI plugins
RUN echo "Installing CNI binaries ..." \
    && export CNI_TARBALL="${CNI_VERSION}/cni-plugins-linux-${TARGETARCH}-${CNI_VERSION}.tgz" \
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
      \) \
      -delete
# STEP 2: Build small image
FROM registry.k8s.io/build-image/distroless-iptables:v0.6.2
COPY --from=builder --chown=root:root /go/bin/kindnetd /bin/kindnetd
COPY --from=builder --chown=root:root /opt/cni/bin /opt/cni/bin
CMD ["/bin/kindnetd"]
