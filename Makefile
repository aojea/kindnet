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

update: update-vendor generate

verify:
	hack/verify-all.sh

# Generate code
generate:
	hack/update-codegen.sh

update-vendor:
	go mod tidy && go mod vendor

image-build:
	hack/build-images.sh




