# SPDX-License-Identifier: APACHE-2.0

# STEP 1: Build kindnetd binary
FROM --platform=$BUILDPLATFORM golang:1.25@sha256:5502b0e56fca23feba76dbc5387ba59c593c02ccc2f0f7355871ea9a0852cebe AS builder
ARG TARGETARCH BUILDARCH BUILDPLATFORM TARGETPLATFORM
# setup cross-compiler, do this early so it can be cached
RUN touch /cc-env ;\
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      if [ "$TARGETARCH" = "arm64" ] ; then \
        apt-get update && apt-get -y install gcc-aarch64-linux-gnu ;\
        echo 'export CC=aarch64-linux-gnu-gcc;' >> /cc-env ;\
      elif [ "$TARGETARCH" = "amd64" ]; then \
        apt-get update && apt-get -y install gcc-x86-64-linux-gnu ;\
        echo 'export CC=x86_64-linux-gnu-gcc;' >> /cc-env ;\
      fi \
    fi && \
    cat /cc-env
# copy in sources
WORKDIR /src
COPY . .
# cache package fetch when iterating on the steps below
RUN go mod download
# build kindnetd
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/kindnetd ./cmd/kindnetd
WORKDIR /src/cmd/cni-kindnet
# build cni-kindnet, sqlite requires CGO
RUN . /cc-env && CGO_ENABLED=1 GOARCH=$TARGETARCH \
    go build \
      -ldflags="-extldflags=-static" -tags sqlite_omit_load_extension,osusergo,netgo \
      -o /go/bin/cni-kindnet .

# STEP 2: Build small image
FROM gcr.io/distroless/static-debian12:debug
COPY --from=builder --chown=root:root /go/bin/kindnetd /bin/kindnetd
COPY --from=builder --chown=root:root /go/bin/cni-kindnet /opt/cni/bin/cni-kindnet
CMD ["/bin/kindnetd"]
