#!/bin/bash

set -e
set -x

echo "Starting..."

CHARTS_PATH="charts"

mkdir -p "${CHARTS_PATH}"

helm package certs

mv -f certs-*.tgz "${CHARTS_PATH}"/

helm repo index "${CHARTS_PATH}" --url "https://math-nao.github.io/certs/${CHARTS_PATH}"

echo "Done."