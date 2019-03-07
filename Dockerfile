# STEP 1: Build executable binary
FROM golang:1.12 AS builder

# Install CNI binaries to /kindnet/cni
ARG CNI_VERSION="v0.7.4"
ARG CNI_BASE_URL="https://github.com/containernetworking/plugins/releases/download/"
RUN export ARCH=$(dpkg --print-architecture) \
    && export CNI_TARBALL="cni-plugins-${ARCH}-${CNI_VERSION}.tgz" \
    && export CNI_URL="${CNI_BASE_URL}${CNI_VERSION}/${CNI_TARBALL}" \
    && curl -sSL --retry 5 --output /tmp/cni.tgz "${CNI_URL}" \
    && sha256sum /tmp/cni.tgz \
    && mkdir -p /kindnet/cni \
    && tar -C /kindnet/cni -xzf /tmp/cni.tgz \
    && rm -rf /tmp/cni.tgz

# Compile the application
WORKDIR /go/src/kindnet
COPY . .
RUN go get -d -v ./...
RUN go build -o /go/bin/kindnet

# STEP 2: Build small image
FROM scratch

COPY --from=builder /kindnet/cni /kindnet/cni
COPY --from=builder /go/bin/kindnet /go/bin/kindnet

CMD ["/go/bin/kindnet"]
