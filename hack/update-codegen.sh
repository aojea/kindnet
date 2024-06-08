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
  GO111MODULE=on go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.15.0
)

echo "Generating configuration CRD clientset"
"${SCRIPT_ROOT}/hack/kube_codegen.sh" all \
  github.com/aojea/kindnet/crds/client \
  github.com/aojea/kindnet/apis \
  "configuration:v1alpha1" \
  --go-header-file "${SCRIPT_ROOT}/hack/boilerplate.go.txt"

echo "Generating CRD artifacts"
controller-gen crd \
  object:headerFile="${SCRIPT_ROOT}/hack/boilerplate.go.txt" \
  paths="${SCRIPT_ROOT}/apis/..." \
  output:crd:artifacts:config="${SCRIPT_ROOT}/crds"
