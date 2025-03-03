# SPDX-License-Identifier: APACHE-2.0

# STEP 1: Build kindnetd binary
FROM --platform=$BUILDPLATFORM golang:1.24@sha256:3f7444391c51a11a039bf0359ee81cc64e663c17d787ad0e637a4de1a3f62a71 AS builder
ARG TARGETARCH BUILDPLATFORM TARGETPLATFORM
# copy in sources
WORKDIR /src
COPY . .
# build
RUN CGO_ENABLED=0 GOARCH=$TARGETARCH go build -o /go/bin/kindnetd ./cmd/kindnetd
WORKDIR /src/cmd/cni-kindnet
# sqlite requires CGO
RUN if [ "$TARGETARCH" = "arm64" ] ; then \
      apt-get update && apt-get -y install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu ;\
      CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOARCH=$TARGETARCH go build -ldflags="-extldflags=-static" -tags sqlite_omit_load_extension,osusergo,netgo -o /go/bin/cni-kindnet . ;\
  else \
      CGO_ENABLED=1 GOARCH=$TARGETARCH go build -ldflags="-extldflags=-static" -tags sqlite_omit_load_extension,osusergo,netgo -o /go/bin/cni-kindnet . ;\
  fi

# STEP 2: Build small image
FROM gcr.io/distroless/static-debian12:debug
COPY --from=builder --chown=root:root /go/bin/kindnetd /bin/kindnetd
COPY --from=builder --chown=root:root /go/bin/cni-kindnet /opt/cni/bin/cni-kindnet
CMD ["/bin/kindnetd"]
