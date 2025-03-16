#!/bin/bash
# Copyright 2025 Antonio Ojea
# SPDX-License-Identifier: Apache-2.0


set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

cd $REPO_ROOT
make update

diffs=$(git status --porcelain | wc -l)
if [[ ${diffs} -gt 0 ]]; then
  git status >&2
  git diff >&2
  exit 1
fi