REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin
BINARY_NAME?=kindnet

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED


build:
	go build -v -o "$(OUT_DIR)/$(BINARY_NAME)" ./cmd/kindnetd/

clean:
	rm -rf "$(OUT_DIR)/"

test:
	CGO_ENABLED=1 go test -v -race -count 1 ./...

# code linters
lint:
	hack/lint.sh

update:
	go mod tidy && go mod vendor

# get image name from directory we're building
IMAGE_NAME=kindnetd
# docker image registry, default to upstream
REGISTRY?=ghcr.io/aojea
# tag based on date-sha
TAG?=$(shell echo "$$(date +v%Y%m%d)-$$(git describe --always --dirty)")
# the full image tag
IMAGE?=$(REGISTRY)/$(IMAGE_NAME):$(TAG)

# required to enable buildx
export DOCKER_CLI_EXPERIMENTAL=enabled
image-build:
# docker buildx build --platform=${PLATFORMS} $(OUTPUT) --progress=$(PROGRESS) -t ${IMAGE} --pull $(EXTRA_BUILD_OPT) .
	docker build . -t ${IMAGE}


# Generate code
code-generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="./hack/boilerplate.go.txt" \
		crd:crdVersions=v1 paths="./apis/..." output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) object:headerFile="./hack/boilerplate.go.txt" \
		paths="./apis/..."

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
		set -e ;\
		CONTROLLER_GEN_TMP_DIR="$$(mktemp -d)" ;\
		cd "$$CONTROLLER_GEN_TMP_DIR" ;\
		go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.15.0 ; \
		rm -rf "$$CONTROLLER_GEN_TMP_DIR" ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif