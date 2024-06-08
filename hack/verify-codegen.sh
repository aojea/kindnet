#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly SCRIPT_ROOT=$(cd $(dirname ${BASH_SOURCE})/.. && pwd)
echo "SCRIPT_ROOT ${SCRIPT_ROOT}"

${SCRIPT_ROOT}/hack/update-codegen.sh

# Test for diffs
diffs=$(git status --porcelain | wc -l)
if [[ ${diffs} -gt 0 ]]; then
  git status >&2
  git diff >&2
  echo "Generated files need to be updated" >&2
  echo "Please run 'hack/update-codegen.sh'" >&2
  exit 1
fi

echo "Generated files are up to date"