#!/bin/bash
# Copyright 2019 Mathieu Naouache

set -e

echo "wait few seconds in case ingress rule is deployed at the same as it is in demo"
sleep 30

if [ "${KUBERNETES_SERVICE_HOST}" = "" ]; then
  echo "No k8s api server found"
  exit 1
fi

APISERVER="${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}"
CA_FILE="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CERTS_SECRET_NAME=""
CONF_SECRET_NAME=""
IS_SECRET_CERTS_ALREADY_EXISTS="false"
IS_SECRET_CONF_ALREADY_EXISTS="false"
ACME_CA_FILE="/root/certs/ca.crt"
ACME_CERT_FILE="/root/certs/tls.crt"
ACME_KEY_FILE="/root/certs/tls.key"
CERTS_DNS=""
CERTS_IS_STAGING="false"
CERTS_IS_DEBUG="false"
CERTS_ARGS=""
CERTS_CMD_TO_USE=""

verbose() {
  echo "$@"
}

info() {
  verbose "Info: $@"
}

debug() {
  if [ "${CERTS_IS_DEBUG}" = "true" ]; then
    verbose "Debug: $@"
  fi
}

k8s_api_call() {
  local METHOD="$1"
  shift
  local URI="$1"
  shift
  local ARGS="$@"

  local RES_FILE=$(mktemp /tmp/res.XXXX)
  curl -i -X "${METHOD}" --cacert "${CA_FILE}" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json' -H "Content-Type: application/json" https://${APISERVER}${URI} ${ARGS} -o ${RES_FILE}
  cat ${RES_FILE} > /dev/stderr
  local STATUS_CODE=$(cat ${RES_FILE} | grep 'HTTP/2' | awk '{printf $2}')
  rm -f "${RES_FILE}"
  echo ${STATUS_CODE}
}

get_data_for_secret_json() {
  local DATA="$@"
  echo -e ${DATA} | base64 -w 0
}

get_file_data_for_secret_json() {
  local FILE="$1"
  cat "${FILE}" | base64 -w 0
}

format_res_file() {
  local FILE="$1"
  local LINE_NUMBER=$(grep -nr '{' ${FILE} | head -1 | awk -F':' '{printf $1}')
  local TOTAL_LINE=$(cat ${FILE} | wc -l)
  local LINE_TO_KEEP=$((${TOTAL_LINE} - ${LINE_NUMBER} + 2))
  local FORMATTED_RES=$(cat ${FILE} | tail -n ${LINE_TO_KEEP})
  echo "${FORMATTED_RES}" > "${FILE}"
}

get_domain_root() {
  local DOMAIN_FOUND=$(find /acme.sh/*.* -type d | head -1)
  if [ "${DOMAIN_FOUND}" != "" ]; then
    echo $(basename "${DOMAIN_FOUND}" 2>/dev/null)
  fi
}

get_cert_hash() {
  local DOMAIN_NAME_ROOT=$(get_domain_root)
  if [ "${DOMAIN_NAME_ROOT}" != "" ]; then
    echo $(md5sum "/acme.sh/${DOMAIN_NAME_ROOT}/fullchain.cer")
  fi
}

starter() {
  info "Initialize environment..."

  local RES_FILE=$(mktemp /tmp/init_env.XXXX)
  local STATUS_CODE=$(k8s_api_call "GET" "/apis/extensions/v1beta1/namespaces/${NAMESPACE}/ingresses" 2>${RES_FILE})

  if [ "${STATUS_CODE}" = "200" ]; then
    format_res_file "${RES_FILE}"
    
    local INGRESSES_FILTERED=$(cat "${RES_FILE}" | jq -c '.items | .[] | select(.metadata.annotations."acme.kubernetes.io/enable"=="true")')
    rm -f "${RES_FILE}"

    if [ "${INGRESSES_FILTERED}" = "" ]; then
      info "No matching ingress found"
      return
    fi

    for ingress in ${INGRESSES_FILTERED}; do
      CERTS_DNS=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/dns"')
      CERTS_CMD_TO_USE=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/cmd-to-use"')

      local IS_DNS_VALID="true"
      if [ "${CERTS_DNS}" = "null" -o  "${CERTS_DNS}" = "" ]; then
        info "No dns configuration found"
        IS_DNS_VALID="false"
        # convert null to empty string
        CERTS_DNS=""
      fi

      local IS_CMD_TO_USE_VALID="true"
      if [ "${CERTS_CMD_TO_USE}" = "null" -o  "${CERTS_CMD_TO_USE}" = "" ]; then
        info "No cmd to use found"
        IS_CMD_TO_USE_VALID="false"
        # convert null to empty string
        CERTS_CMD_TO_USE=""
      fi

      if [ "${IS_DNS_VALID}" = "false" -a "${IS_CMD_TO_USE_VALID}" = "false" ]; then
        return
      fi

      CERTS_ARGS=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/add-args"')
      if [ "${CERTS_ARGS}" = "null" -o  "${CERTS_ARGS}" = "" ]; then
        info "No cmd args found"
        # convert null to empty string
        CERTS_ARGS=""
      fi

      if [ "$(echo "${ingress}" | jq -c '. | select(.metadata.annotations."acme.kubernetes.io/staging"=="true")' | wc -l)" = "1"  ]; then
        CERTS_IS_STAGING="true"
      fi

      if [ "$(echo "${ingress}" | jq -c '. | select(.metadata.annotations."acme.kubernetes.io/debug"=="true")' | wc -l)" = "1"  ]; then
        CERTS_IS_DEBUG="true"
      fi

      TLS_INPUTS=$(echo "${ingress}" | jq -c '.spec.tls | .[]')
      for input in ${TLS_INPUTS}; do
        local SECRETNAME=$(echo ${input} | jq -rc '.secretName')
        local HOSTS=$(echo ${input} | jq -rc '.hosts | .[]' | tr '\n' ' ')
        # no quotes on the last argument please
        generate_cert "${SECRETNAME}" ${HOSTS}
      done
    done
  else
    info "Invalid status code found: ${STATUS_CODE}"
  fi
}

generate_cert() {
  local NAME="$1"
  shift
  local DOMAINS="$@"

  debug "Generate certs for" \
   " dns: ${CERTS_DNS}," \
   " is_staging: ${CERTS_IS_STAGING}," \
   " is_debug: ${CERTS_IS_DEBUG}," \
   " args: ${CERTS_ARGS}," \
   " cmd to use: ${CERTS_CMD_TO_USE}," \
   " name: ${NAME}," \
   " domains: ${DOMAINS}"

  # update global variables
  CERTS_SECRET_NAME="${NAME}"
  CONF_SECRET_NAME="${NAME}-conf"

  # get previous conf if it exists
  load_conf_from_secret

  # prepare acme cmd args
  ACME_ARGS="--issue --ca-file '${ACME_CA_FILE}' --cert-file '${ACME_CERT_FILE}' --key-file '${ACME_KEY_FILE}'"

  if [ "${CERTS_IS_DEBUG}" = "true" ]; then
    ACME_ARGS="${ACME_ARGS} --debug"
  fi
  
  if [ "${CERTS_ARGS}" != "" ]; then
    ACME_ARGS="${ACME_ARGS} ${CERTS_ARGS}"
  fi

  if [ "${CERTS_IS_STAGING}" = "true" ]; then
    ACME_ARGS="${ACME_ARGS} --staging"
  fi
  
  if [ "${CERTS_DNS}" != "" ]; then
    ACME_ARGS="${ACME_ARGS} --dns '${CERTS_DNS}'"
  fi

  for domain in ${DOMAINS}; do
    if [ "${domain}" != "" ]; then
      ACME_ARGS="${ACME_ARGS} -d ${domain}"
    fi
  done

  # use the custom acme arg set by user if it exists
  local ACME_CMD="acme.sh ${ACME_ARGS}"
  if [ "${CERTS_CMD_TO_USE}" != "" ]; then
    ACME_CMD="${CERTS_CMD_TO_USE}"
  fi
  
  # get the domain root used by acme
  local DOMAIN_NAME_ROOT=$(get_domain_root)
  debug "domain name root: ${DOMAIN_NAME_ROOT}"

  # get current cert hash
  CURRENT_CERT_HASH=$(get_cert_hash)

  # generate certs
  debug "Running cmd: ${ACME_CMD}"
  RC=0
  eval "${ACME_CMD}" || RC=$? && true

  info "acme.sh return code: ${RC}"

  if [ "${RC}" != "0" -a "${RC}" != "2" ]; then
    info "An acme.sh error occurred"
    exit 1
  fi
  
  # update domain name root after certs creation
  DOMAIN_NAME_ROOT=$(get_domain_root)

  # get new cert hash
  NEW_CERT_HASH=$(get_cert_hash)

  # update secrets only if certs has been updated
  if [ "${CURRENT_CERT_HASH}" != "${NEW_CERT_HASH}" ]; then
    info "Certificate change, updating..."
    add_certs_to_secret
    add_conf_to_secret "${DOMAIN_NAME_ROOT}"
  else
    info "No certificate change, nothing to do"
  fi
}

add_certs_to_secret() {
  info "Adding certs to secret..."

  SECRET_FILE="/root/secret.certs.json"

  SECRET_JSON=$(echo '{}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg kind "Secret" '. + {kind: $kind}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg name "${CERTS_SECRET_NAME}" '. + {metadata: { name: $name }}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq '. + {data: {}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg cacert "$(get_file_data_for_secret_json "${ACME_CA_FILE}")" '. * {data: {"ca.crt": $cacert}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg tlscert "$(get_file_data_for_secret_json "${ACME_CERT_FILE}")" '. * {data: {"tls.crt": $tlscert}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg tlskey "$(get_file_data_for_secret_json "${ACME_KEY_FILE}")" '. * {data: {"tls.key": $tlskey}}')

  echo -e "${SECRET_JSON}" > "${SECRET_FILE}"

  local STATUS_CODE=""
  if [ "${IS_SECRET_CERTS_ALREADY_EXISTS}" = "false" ]; then
    info "Adding certs"
    STATUS_CODE=$(k8s_api_call "POST" /api/v1/namespaces/${NAMESPACE}/secrets --data "@${SECRET_FILE}" 2>/dev/null)
  else
    info "Updating certs"
    STATUS_CODE=$(k8s_api_call "PUT" /api/v1/namespaces/${NAMESPACE}/secrets/${CERTS_SECRET_NAME} --data "@${SECRET_FILE}" 2>/dev/null)
  fi

  debug "Status code: ${STATUS_CODE}"

  if [ "${STATUS_CODE}" = "200" -o "${STATUS_CODE}" = "201" ]; then
    info "Certs sucessfully added"
  else
    info "Certs not added"
  fi

  rm -f "${SECRET_FILE}"
}

load_conf_from_secret() {
  info "Loading conf from secret..."
  
  local RES_FILE=$(mktemp /tmp/load_conf.XXXX)
  local STATUS_CODE=$(k8s_api_call "GET" /api/v1/namespaces/${NAMESPACE}/secrets/${CONF_SECRET_NAME} 2>${RES_FILE})

  if [ "${STATUS_CODE}" = "200" ]; then
    info "Adding conf"
    IS_SECRET_CONF_ALREADY_EXISTS="true"
    format_res_file "${RES_FILE}"
    local TMP_TAR_FILE=$(mktemp /tmp/tar_file.XXXX)
    cat ${RES_FILE} | jq -r '.data.conf' | base64 -d > "${TMP_TAR_FILE}"
    tar -xf "${TMP_TAR_FILE}" -C /
    rm -f "${TMP_TAR_FILE}"
  else
    info "Invalid status code found: ${STATUS_CODE}, configuration not loaded"
  fi

  rm -f "${RES_FILE}"
}

add_conf_to_secret() {
  info "Adding conf to secret..."

  local DOMAIN="$1"

  tar -cvf config.tar /acme.sh/${DOMAIN}

  SECRET_FILE="/root/secret.conf.json"

  SECRET_JSON=$(echo '{}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg kind "Secret" '. + {kind: $kind}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg name "${CONF_SECRET_NAME}" '. + {metadata: { name: $name }}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq '. + {data: {}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg conf "$(get_file_data_for_secret_json /root/config.tar)" '. * {data: {conf: $conf}}')

  echo "${SECRET_JSON}" > "${SECRET_FILE}"

  local STATUS_CODE=""
  if [ "${IS_SECRET_CONF_ALREADY_EXISTS}" = "false" ]; then
    info "Adding conf"
    STATUS_CODE=$(k8s_api_call "POST" /api/v1/namespaces/${NAMESPACE}/secrets --data "@${SECRET_FILE}" 2>/dev/null)
  else
    info "Updating conf"
    STATUS_CODE=$(k8s_api_call "PUT" /api/v1/namespaces/${NAMESPACE}/secrets/${CONF_SECRET_NAME} --data "@${SECRET_FILE}" 2>/dev/null)
  fi

  debug "Status code: ${STATUS_CODE}"

  if [ "${STATUS_CODE}" = "200" -o "${STATUS_CODE}" = "201" ]; then
    info "Conf sucessfully added"
  else
    info "Conf not added"
  fi

  rm -f "${SECRET_FILE}"
}

starter
