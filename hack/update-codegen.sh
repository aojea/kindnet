#!/usr/bin/env bash


set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPT_ROOT=$(cd $(dirname ${BASH_SOURCE})/.. && pwd)
echo "SCRIPT_ROOT ${SCRIPT_ROOT}"
cd ${SCRIPT_ROOT}

(
  # To support running this script from anywhere, first cd into this directory,
  # and then install with forced module mode on and fully qualified name.
  readonly GOFLAGS="-mod=vendor"
  cd "$(dirname "${0}")"
  GO111MODULE=on go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.15.0
  # GO111MODULE=on go install k8s.io/code-generator/cmd/{defaulter-gen,client-gen,lister-gen,informer-gen,deepcopy-gen,register-gen}
)


echo "Generating CRD artifacts"
controller-gen rbac:roleName=kindnet crd \
  object:headerFile="${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
  paths="${SCRIPT_ROOT}/pkg/apis/..." \
  output:crd:dir="${SCRIPT_ROOT}/apis"

source "${SCRIPT_ROOT}/hack/kube_codegen.sh"

THIS_PKG="github.com/aojea/kindnet"

kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}"

kube::codegen::gen_client \
    --with-watch \
    --output-dir "${SCRIPT_ROOT}/apis/generated" \
    --output-pkg "${THIS_PKG}/apis/generated" \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/pkg/apis"
