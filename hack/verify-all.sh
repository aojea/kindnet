#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPT_ROOT=$(cd $(dirname ${BASH_SOURCE})/.. && pwd)
echo "SCRIPT_ROOT ${SCRIPT_ROOT}"

echo "Running all verification scripts"

for f in ${SCRIPT_ROOT}/hack/verify-*.sh; do
  if [[ $f = "${SCRIPT_ROOT}/hack/verify-all.sh" ]]; then
    continue
  fi
  $f
done