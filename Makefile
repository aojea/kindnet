REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin
BINARY_NAME?=kindnet

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED


build:
	go build -v -o "$(OUT_DIR)/$(BINARY_NAME)" ./cmd/kindnetd/
	cd ./cmd/cni-kindnet/ && CGO_ENABLED=1 go build -v -ldflags="-extldflags=-static" -tags sqlite_omit_load_extension,osusergo,netgo -o "$(OUT_DIR)/cni-kindnet" .

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...
	cd ./cmd/cni-kindnet ; CGO_ENABLED=1 go test -v -ldflags="-extldflags=-static" -tags sqlite_omit_load_extension,osusergo,netgo -race -count 1 .

verify:
	hack/lint.sh
	hack/verify-updated.sh

update:
	go mod tidy
	gofmt -s -w ./
	hack/update-license-header.sh

# get image name from directory we're building
IMAGE_NAME=kindnetd
# docker image registry, default to upstream
REGISTRY?=ghcr.io/aojea
# tag based on date-sha
TAG?=$(shell echo "$$(date +v%Y%m%d)-$$(git describe --always --dirty)")
# the full image tag
IMAGE?=$(REGISTRY)/$(IMAGE_NAME):$(TAG)
PLATFORMS?=linux/amd64,linux/arm64
PROGRESS?=auto
# required to enable buildx
export DOCKER_CLI_EXPERIMENTAL=enabled

image-build:
	docker buildx build . \
		--progress="${PROGRESS}" \
		--platform="${PLATFORMS}" \
		--tag="${IMAGE}" --load
