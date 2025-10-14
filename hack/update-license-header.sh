#!/bin/bash
# Copyright 2025 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

cd $REPO_ROOT

# The boilerplate file to use
readonly BOILERPLATE_FILE="${1:-hack/boilerplate.go.txt}"

# The temporary file to use
readonly TMP_FILE=$(mktemp)

# The list of files to check
readonly FILES=$(find . -name "*.go" -not -path "./vendor/*" -not -path "./bin/*")

# The function to update the license header
update_license_header() {
  local file="$1"
  local boilerplate_file="$2"
  local tmp_file="$3"
  
  # Create a temporary file
  cp "${boilerplate_file}" "${tmp_file}"

  # Add a blank line after the boilerplate
  echo "" >> "${tmp_file}"

  # Add the rest of the file
  cat "${file}" >> "${tmp_file}"

  # Replace the original file
  mv "${tmp_file}" "${file}"
}

# Loop through all the files
for file in ${FILES}; do
  # Check if the file has the license header
  if ! grep -q "Copyright" "${file}"; then
    echo "Updating license header for ${file}"
    update_license_header "${file}" "${BOILERPLATE_FILE}" "${TMP_FILE}"
  fi
done

# Clean up the temporary file
rm -f "${TMP_FILE}"