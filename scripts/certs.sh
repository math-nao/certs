#!/bin/sh
# Copyright 2019 Mathieu Naouache

set -e

echo "Version: ${CERTS_VERSION}"
echo "wait few seconds in case ingress rule is deployed at the same as it is in demo"
sleep 30

current_folder=$(dirname "$(readlink -f "$0")")
report_file="${current_folder}/report.log"
#initialize file content
echo "" > "${report_file}"

on_exit() {
  echo "Exiting..."
  
  source "${current_folder}/after.sh"

  if [ "${ACME_DEBUG}" = "true" ]; then
    echo "Report file content:"
    cat "${report_file}"
  fi
}

trap on_exit EXIT

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
IS_SECRET_CONF_ALREADY_EXISTS="false"
ACME_CA_FILE="/root/certs/ca.crt"
ACME_CERT_FILE="/root/certs/tls.crt"
ACME_FULLCHAIN_FILE="/root/certs/fullchain.crt"
ACME_KEY_FILE="/root/certs/tls.key"
ACME_DEBUG="${ACME_DEBUG-false}"
CERTS_DNS=""
CERTS_IS_STAGING="false"
CERTS_ARGS=""
CERTS_CMD_TO_USE=""
CERTS_PRE_CMD=""
CERTS_POST_CMD=""
CERTS_ONSUCCESS_CMD=""
CERTS_ONERROR_CMD=""
K8S_API_URI_NAMESPACE="namespaces/${NAMESPACE}"
if [ "${ACME_MANAGE_ALL_NAMESPACES}" = "true" ]; then
  K8S_API_URI_NAMESPACE=""
fi

verbose() {
  echo "$@"
}

info() {
  verbose "Info: $@"
}

debug() {
  if [ "${ACME_DEBUG}" = "true" ]; then
    verbose "Debug: $@"
  fi
}

add_to_report() {
  if [ "${ACME_DEBUG}" = "true" ]; then
    echo "$@" >> "${report_file}"
  fi
}

k8s_api_call() {
  local METHOD="$1"
  shift
  local URI="$1"
  shift
  local ARGS="$@"

  local RES_FILE=$(mktemp /tmp/res.XXXX)
  local CONTENT_TYPE="application/json"
  if [ "${METHOD}" = "PATCH" ]; then
    # https://stackoverflow.com/a/63139804
    CONTENT_TYPE="application/strategic-merge-patch+json"
  fi
  curl -i -X "${METHOD}" --cacert "${CA_FILE}" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json' -H "Content-Type: ${CONTENT_TYPE}" https://${APISERVER}${URI} ${ARGS} -o ${RES_FILE}
  
  cat ${RES_FILE} > /dev/stderr
  local STATUS_CODE=$(cat ${RES_FILE} | grep 'HTTP/' | awk '{printf $2}')
  add_to_report "$(cat "${RES_FILE}")"
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

get_domain_folder() {
  local DOMAIN_NAME="$1"
  local IS_ECC_CERTIFICATE="$2"
  local IS_CUSTOM_DOMAIN="$3"

  if [ -z "${DOMAIN_NAME}" ]; then
    return
  fi

  local DOMAIN_FOLDER
  DOMAIN_FOLDER="/acme.sh/$(echo "${DOMAIN_NAME}")"
  
  if [ "${IS_ECC_CERTIFICATE}" = "true" ]; then
    DOMAIN_FOLDER="${DOMAIN_FOLDER}_ecc"
  fi

  if [ -d "${DOMAIN_FOLDER}" ]; then
    echo "${DOMAIN_FOLDER}"
    return
  fi

  # in case of custom domain, try to find the domain folder
  if [ "${IS_CUSTOM_DOMAIN}" = "true" ]; then
    local LATEST_MODIFIED_FOLDER
    LATEST_MODIFIED_FOLDER=$(ls -td /acme.sh/* | head -1)
    if [ -n "${LATEST_MODIFIED_FOLDER}" ]; then
      echo "${LATEST_MODIFIED_FOLDER}"
      return
    fi
  fi
}

get_cert_hash() {
  local DOMAIN_FOLDER="$1"

  if [ -d "${DOMAIN_FOLDER}" ]; then
    echo $(md5sum "${DOMAIN_FOLDER}/fullchain.cer" | awk '{ print $1 }')
  fi
}

starter() {
  info "Initialize environment..."

  if [ -n "${EAB_KID}" ] && [ -n "${EAB_HMAC_KEY}" ]; then
    # use zerossl as default CA
    acme.sh --set-default-ca --server zerossl
    # register zerossl account
    acme.sh --register-account \
        --eab-kid "${EAB_KID}" \
        --eab-hmac-key "${EAB_HMAC_KEY}"
  else
    # use letsencrypt as default CA
    acme.sh --set-default-ca --server letsencrypt
  fi

  local URI="/apis/networking.k8s.io/v1"
  if [ -n "${K8S_API_URI_NAMESPACE}" ]; then
    URI="${URI}/${K8S_API_URI_NAMESPACE}"
  fi
  URI="${URI}/ingresses"

  local RES_FILE=$(mktemp /tmp/init_env.XXXX)
  local STATUS_CODE=$(k8s_api_call "GET" "${URI}" 2>${RES_FILE})

  if [ "${STATUS_CODE}" = "200" ]; then
    format_res_file "${RES_FILE}"
    
    local INGRESSES_FILTERED=$(cat "${RES_FILE}" | jq -c '.items | .[] | select(.metadata.annotations."acme.kubernetes.io/enable"=="true")')
    add_to_report "$(cat "${RES_FILE}")"
    rm -f "${RES_FILE}"

    if [ "${INGRESSES_FILTERED}" = "" ]; then
      info "No matching ingress found"
      return
    fi

    IFS=$'\n'
    for ingress in ${INGRESSES_FILTERED}; do
      unset IFS

      CERTS_DNS=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/dns"')
      CERTS_CMD_TO_USE=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/cmd-to-use"')
      if [ "${CERTS_CMD_TO_USE}" = "null" ]; then
        CERTS_CMD_TO_USE=""
      fi

      CERTS_PRE_CMD=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/pre-cmd"')
      if [ "${CERTS_PRE_CMD}" = "null" ]; then
        CERTS_PRE_CMD=""
      fi

      CERTS_POST_CMD=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/post-cmd"')
      if [ "${CERTS_POST_CMD}" = "null" ]; then
        CERTS_POST_CMD=""
      fi

      CERTS_ONSUCCESS_CMD=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/on-success-cmd"')
      if [ "${CERTS_ONSUCCESS_CMD}" = "null" ]; then
        CERTS_ONSUCCESS_CMD=""
      fi

      CERTS_ONERROR_CMD=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/on-error-cmd"')
      if [ "${CERTS_ONERROR_CMD}" = "null" ]; then
        CERTS_ONERROR_CMD=""
      fi

      local CERT_NAMESPACE=$(echo "${ingress}" | jq -rc '.metadata.namespace')

      if [ -n "${ACME_NAMESPACES_WHITELIST}" ]; then
        local is_namespace_found="false"
        for namespace in ${ACME_NAMESPACES_WHITELIST}; do
          if [ "${CERT_NAMESPACE}" = "${namespace}" ]; then
            is_namespace_found="true"
            break
          fi
        done

        if [ "${is_namespace_found}" != "true" ]; then
          info "Namespace '${CERT_NAMESPACE}' not in whitelist"
          continue
        fi
      fi

      local IS_DNS_VALID="true"
      if [ "${CERTS_DNS}" = "null" ] || [  "${CERTS_DNS}" = "" ]; then
        info "No dns configuration found"
        IS_DNS_VALID="false"
        # convert null to empty string
        CERTS_DNS=""
      fi

      local IS_CMD_TO_USE_VALID="true"
      if [ "${CERTS_CMD_TO_USE}" = "null" ] || [ "${CERTS_CMD_TO_USE}" = "" ]; then
        info "No cmd to use found"
        IS_CMD_TO_USE_VALID="false"
        # convert null to empty string
        CERTS_CMD_TO_USE=""
      fi

      if [ "${IS_DNS_VALID}" = "false" ] && [ "${IS_CMD_TO_USE_VALID}" = "false" ]; then
        return
      fi

      CERTS_ARGS=$(echo "${ingress}" | jq -rc '.metadata.annotations."acme.kubernetes.io/add-args"')
      if [ "${CERTS_ARGS}" = "null" ] || [  "${CERTS_ARGS}" = "" ]; then
        info "No cmd args found"
        # convert null to empty string
        CERTS_ARGS=""
      fi

      if [ "$(echo "${ingress}" | jq -c '. | select(.metadata.annotations."acme.kubernetes.io/staging"=="true")' | wc -l)" = "1"  ]; then
        CERTS_IS_STAGING="true"
      fi

      TLS_INPUTS=$(echo "${ingress}" | jq -c '.spec.tls | .[]')
      for input in ${TLS_INPUTS}; do
        local SECRETNAME=$(echo ${input} | jq -rc '.secretName')
        local HOSTS=$(echo ${input} | jq -rc '.hosts | .[]' | tr '\n' ' ')
        # no quotes on the last argument please
        generate_cert "${CERT_NAMESPACE}" "${SECRETNAME}" ${HOSTS}
      done
    done
  else
    info "Invalid status code found: ${STATUS_CODE}"
  fi
}

generate_cert() {
  local CERT_NAMESPACE="$1"
  shift
  local NAME="$1"
  shift
  local DOMAINS="$@"

  info "Generate certs for" \
   " dns: ${CERTS_DNS}," \
   " is_staging: ${CERTS_IS_STAGING}," \
   " is_debug: ${ACME_DEBUG}," \
   " args: ${CERTS_ARGS}," \
   " cmd to use: ${CERTS_CMD_TO_USE}," \
   " pre-cmd: ${CERTS_PRE_CMD}," \
   " post-cmd: ${CERTS_POST_CMD}," \
   " name: ${NAME}," \
   " namespace: ${CERT_NAMESPACE}," \
   " domains: ${DOMAINS}"

  # update global variables
  CERTS_SECRET_NAME="${NAME}"
  CONF_SECRET_NAME="${NAME}-conf"
  IS_SECRET_CONF_ALREADY_EXISTS="false"

  # get previous conf if it exists
  load_conf_from_secret "${CERT_NAMESPACE}"

  # prepare acme cmd args
  ACME_ARGS="--issue --ca-file '${ACME_CA_FILE}' --cert-file '${ACME_CERT_FILE}' --fullchain-file '${ACME_FULLCHAIN_FILE}' --key-file '${ACME_KEY_FILE}'"

  if [ "${ACME_DEBUG}" = "true" ]; then
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

  local MAIN_DOMAIN=""
  for domain in ${DOMAINS}; do
    if [ "${domain}" != "" ]; then
      # set the first domain as the main domain
      if [ -z "${MAIN_DOMAIN}" ]; then
        MAIN_DOMAIN="${domain}"
      fi
      ACME_ARGS="${ACME_ARGS} -d ${domain}"
    fi
  done

  debug "main domain: ${MAIN_DOMAIN}"

  # use the custom acme arg set by user if it exists
  local ACME_CMD="acme.sh ${ACME_ARGS}"
  if [ "${CERTS_CMD_TO_USE}" != "" ]; then
    ACME_CMD="${CERTS_CMD_TO_USE}"
  fi

  local IS_ECC_CERTIFICATE="false"
  if [ -n "$(echo ${ACME_CMD} | grep ' --keylength ec-')" ]; then
    IS_ECC_CERTIFICATE="true"
  fi

  local IS_CUSTOM_DOMAIN="false"
  if [ -n "$(echo ${ACME_CMD} | grep ' -d ')" ]; then
    IS_CUSTOM_DOMAIN="true"
  fi

  local DOMAIN_FOLDER=$(get_domain_folder "${MAIN_DOMAIN}" "${IS_ECC_CERTIFICATE}" "${IS_CUSTOM_DOMAIN}")
  debug "domain folder: ${DOMAIN_FOLDER}"


  # get current cert hash
  CURRENT_CERT_HASH=$(get_cert_hash "${DOMAIN_FOLDER}")
  debug "current cert hash: ${CURRENT_CERT_HASH}"

  # pre-cmd
  if [ -n "${CERTS_PRE_CMD}" ]; then
    debug "Running pre-cmd: ${CERTS_PRE_CMD}"
    pre_cmd_rc=0
    eval "${CERTS_PRE_CMD}" || pre_cmd_rc=$? && true
    info "pre-cmd return code: ${pre_cmd_rc}"
  else
    debug "No pre-cmd"
  fi

  # generate certs
  debug "Running cmd: ${ACME_CMD}"
  RC=0
  eval "${ACME_CMD}" || RC=$? && true
  info "acme.sh return code: ${RC}"

  # post-cmd
  if [ -n "${CERTS_POST_CMD}" ]; then
    debug "Running post-cmd: ${CERTS_POST_CMD}"
    post_cmd_rc=0
    eval "${CERTS_POST_CMD}" || post_cmd_rc=$? && true
    info "post-cmd return code: ${post_cmd_rc}"
  else
    debug "No post-cmd"
  fi

  if [ "${RC}" = "2" ]; then
    info "Certificate current. No renewal needed"
    return
  fi

  if [ "${RC}" != "0" ]; then
    info "An acme.sh error occurred"
    if [ -n "${CERTS_ONERROR_CMD}" ]; then
      eval "$(format_cmd "${CERTS_ONERROR_CMD}")" || true
    fi
    exit 1
  fi

  # update domain folder with new folder created
  DOMAIN_FOLDER=$(get_domain_folder "${MAIN_DOMAIN}" "${IS_ECC_CERTIFICATE}" "${IS_CUSTOM_DOMAIN}")
  debug "domain folder: ${DOMAIN_FOLDER}"

  # get new cert hash
  NEW_CERT_HASH=$(get_cert_hash "${DOMAIN_FOLDER}")
  debug "new cert hash: ${NEW_CERT_HASH}"

  # update secrets only if certs has been updated
  if [ "${CURRENT_CERT_HASH}" != "${NEW_CERT_HASH}" ]; then
    info "Certificate change, updating..."
    add_certs_to_secret "${CERT_NAMESPACE}"
    add_conf_to_secret "${CERT_NAMESPACE}" "${DOMAIN_FOLDER}"
  else
    info "No certificate change, nothing to do"
  fi

  # onsuccess-cmd
  if [ -n "${CERTS_ONSUCCESS_CMD}" ]; then
    debug "Running onsuccess-cmd: ${CERTS_ONSUCCESS_CMD}"
    onsuccess_cmd_rc=0
    eval "${CERTS_ONSUCCESS_CMD}" || onsuccess_cmd_rc=$? && true
    info "onsuccess return code: ${onsuccess_cmd_rc}"
  else
    debug "No onsuccess-cmd"
  fi
}

add_certs_to_secret() {
  info "Adding certs to secret..."

  local CERT_NAMESPACE="$1"

  SECRET_FILE="/root/secret.certs.json"

  SECRET_JSON=$(echo '{}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg kind "Secret" '. + {kind: $kind}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg name "${CERTS_SECRET_NAME}" '. + {metadata: { name: $name }}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq '. + {data: {}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg cacert "$(get_file_data_for_secret_json "${ACME_CA_FILE}")" '. * {data: {"ca.crt": $cacert}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg tlscert "$(get_file_data_for_secret_json "${ACME_FULLCHAIN_FILE}")" '. * {data: {"tls.crt": $tlscert}}')
  SECRET_JSON=$(echo ${SECRET_JSON} | jq --arg tlskey "$(get_file_data_for_secret_json "${ACME_KEY_FILE}")" '. * {data: {"tls.key": $tlskey}}')

  echo -e "${SECRET_JSON}" > "${SECRET_FILE}"

  local STATUS_CODE_CHECKER=$(k8s_api_call "GET" "/api/v1/namespaces/${CERT_NAMESPACE}/secrets/${CERTS_SECRET_NAME}" 2>${RES_FILE})

  debug "Status code checker: ${STATUS_CODE_CHECKER}"

  local STATUS_CODE=""
  if [ "${STATUS_CODE_CHECKER}" != "200" ]; then
    info "Adding certs"
    STATUS_CODE=$(k8s_api_call "POST" "/api/v1/namespaces/${CERT_NAMESPACE}/secrets" --data "@${SECRET_FILE}" 2>/dev/null)
  else
    info "Updating certs"
    STATUS_CODE=$(k8s_api_call "PATCH" "/api/v1/namespaces/${CERT_NAMESPACE}/secrets/${CERTS_SECRET_NAME}" --data "@${SECRET_FILE}" 2>/dev/null)
  fi

  debug "Status code: ${STATUS_CODE}"

  if [ "${STATUS_CODE}" = "200" ] || [ "${STATUS_CODE}" = "201" ]; then
    info "Certs sucessfully added"
  else
    info "Certs not added"
  fi

  rm -f "${SECRET_FILE}"
}

load_conf_from_secret() {
  info "Loading conf from secret..."

  local CERT_NAMESPACE="$1"

  local RES_FILE=$(mktemp /tmp/load_conf.XXXX)
  local STATUS_CODE=$(k8s_api_call "GET" "/api/v1/namespaces/${CERT_NAMESPACE}/secrets/${CONF_SECRET_NAME}" 2>${RES_FILE})

  debug "Status code: ${STATUS_CODE}"

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

  local CERT_NAMESPACE="$1"
  shift
  local DOMAIN_FOLDER="$1"

  if [ -z "${DOMAIN_FOLDER}" ]; then
    info "no folder found for domain"
    return
  fi

  if [ ! -d "${DOMAIN_FOLDER}" ]; then
    info "domain folder is not a directory"
    return
  fi

  tar -cvf config.tar ${DOMAIN_FOLDER}

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
    STATUS_CODE=$(k8s_api_call "POST" "/api/v1/namespaces/${CERT_NAMESPACE}/secrets" --data "@${SECRET_FILE}" 2>/dev/null)
  else
    info "Updating conf"
    STATUS_CODE=$(k8s_api_call "PUT" "/api/v1/namespaces/${CERT_NAMESPACE}/secrets/${CONF_SECRET_NAME}" --data "@${SECRET_FILE}" 2>/dev/null)
  fi

  debug "Status code: ${STATUS_CODE}"

  if [ "${STATUS_CODE}" = "200" ] || [ "${STATUS_CODE}" = "201" ]; then
    info "Conf sucessfully added"
  else
    info "Conf not added"
  fi

  rm -f "${SECRET_FILE}"
}

format_cmd() {
  echo "$1" | sed -r "s@#domains#@${DOMAINS}@g"
}

source "${current_folder}/before.sh"

starter
