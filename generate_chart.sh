#!/bin/bash

set -e
set -x

echo "Starting..."

version="$1"

if [ -z "${version}" ]; then
  echo "Version is missing"
  exit 1
fi

helm lint certs

charts_dir="charts"
build_dir="build"
registry="mathnao"

mkdir -p "${charts_dir}" "${build_dir}"

# clean build dir
rm -rf "${build_dir:?}"/*

# macos
sed -E -i '' "s/^(version:) .*$/\1 ${version}/g" certs/Chart.yaml
sed -E -i '' "s/^(  tag:) .*$/\1 ${version}/g" certs/values.yaml
sed -E -i '' "s/(CERTS_VERSION)=.*$/\1=${version}/g" Dockerfile

helm package --debug --destination "${build_dir}" certs

helm repo index "${build_dir}" --url "https://math-nao.github.io/certs/${charts_dir}" --merge "${charts_dir}/index.yaml"

mv -f "${build_dir}/index.yaml" "${charts_dir}"
mv -f "${build_dir}/"certs-*.tgz "${charts_dir}"

docker build --platform linux/amd64 -t "${registry}/certs:${version}" .
docker push "${registry}/certs:${version}"

docker tag "${registry}/certs:${version}" "${registry}/certs:latest"
docker push "${registry}/certs:latest"

echo "Done."