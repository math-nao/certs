#!/bin/bash

set -e
set -x

echo "Starting..."

version="$1"

if [ -z "${version}" ]; then
  echo "Version is missing"
  exit 1
fi

charts_path="charts"

mkdir -p "${charts_path}"

# macos
sed -E -i '' "s/^(version:) .*$/\1 ${version}/g" certs/Chart.yaml
sed -E -i '' "s/^(  tag:) .*$/\1 ${version}/g" certs/values.yaml

helm package --debug certs

mv -f certs-*.tgz "${charts_path}"/

helm repo index "${charts_path}" --url "https://math-nao.github.io/certs/${charts_path}"

echo "Done."