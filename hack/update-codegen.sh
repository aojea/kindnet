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
  cd "$(dirname "${0}")"
  go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.15.0
)


echo "Generating CRD artifacts"
controller-gen rbac:roleName=kindnet crd \
  object:headerFile="${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
  paths="${SCRIPT_ROOT}/pkg/apis/..." \
  output:crd:dir="${SCRIPT_ROOT}/apis"

# https://raw.githubusercontent.com/kubernetes/code-generator/release-1.30/kube_codegen.sh
source "${SCRIPT_ROOT}/hack/kube_codegen.sh"

THIS_PKG="github.com/aojea/kindnet"

kube::codegen::gen_client \
    --with-watch \
    --output-dir "${SCRIPT_ROOT}/apis/generated" \
    --output-pkg "${THIS_PKG}/apis/generated" \
    --boilerplate "${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/pkg/apis"
