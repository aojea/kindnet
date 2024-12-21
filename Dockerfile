# SPDX-License-Identifier: APACHE-2.0

# STEP 1: Build kindnetd binary
FROM --platform=$BUILDPLATFORM golang:1.23 AS builder
# golang envs
ENV CGO_ENABLED=0
# copy in sources
WORKDIR /src
COPY . .
# build
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/kindnetd ./cmd/kindnetd
# Install CNI plugins
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/cni-kindnet ./cmd/cniplugin
# STEP 2: Build small image
FROM registry.k8s.io/build-image/distroless-iptables:v0.6.5
COPY --from=builder --chown=root:root /go/bin/kindnetd /bin/kindnetd
COPY --from=builder --chown=root:root /go/bin/cni-kindnet /opt/cni/bin/cni-kindnet
CMD ["/bin/kindnetd"]
