#!/bin/sh
# Copyright 2019 Mathieu Naouache

set -e

echo "Version: ${CERTS_VERSION}"
echo "wait few seconds in case ingress rule is deployed at the same as it is in demo"
#sleep 30

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
CERT_NAMESPACE=""
ACME_CA_FILE="/root/certs/ca.crt"
ACME_CERT_FILE="/root/certs/tls.crt"
ACME_FULLCHAIN_FILE="/root/certs/fullchain.crt"
ACME_KEY_FILE="/root/certs/tls.key"
ACME_DEBUG="${ACME_DEBUG-false}"
ACME_UPDATE_ARGS_ERR=""
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
  echo "$@" 1>&2
}

info() {
  verbose "Info: $*"
}

debug() {
  if [ "${ACME_DEBUG}" = "true" ]; then
    verbose "Debug: $*"
  fi
}

add_to_report() {
  if [ "${ACME_DEBUG}" = "true" ]; then
    echo "$@" >> "${report_file}"
  fi
}

k8s_api_call() {
  method="$1"
  shift
  uri="$1"
  shift
  args="$@"

  res_file=$(mktemp /tmp/res.XXXX)
  content_type="application/json"
  if [ "${method}" = "PATCH" ]; then
    # https://stackoverflow.com/a/63139804
    content_type="application/strategic-merge-patch+json"
  fi
  curl -i -X "${method}" --cacert "${CA_FILE}" -H "Authorization: Bearer $TOKEN" -H 'Accept: application/json' -H "Content-Type: ${content_type}" "https://${APISERVER}${uri}" ${args} -o "${res_file}"
  
  cat "${res_file}" > /dev/stderr
  status_code=$(cat "${res_file}" | grep 'HTTP/' | awk '{printf $2}')
  add_to_report "$(cat "${res_file}")"
  rm -f "${res_file}"
  echo "${status_code}"
}

get_data_for_secret_json() {
  data="$*"
  echo "${data}" | base64 -w 0
}

get_file_data_for_secret_json() {
  file="$1"
  base64 -w 0 < "${file}"
}

format_res_file() {
  file="$1"
  line_number=$(grep -nr '{' "${file}" | head -1 | awk -F':' '{printf $1}')
  total_lines=$(wc -l < "${file}")
  line_to_keep=$((total_lines - line_number + 2))
  formatted_res=$(tail -n ${line_to_keep} < "${file}")
  echo "${formatted_res}" > "${file}"
}

get_domain_folder() {
  domain_name="$1"
  is_ecc_certificate="$2"
  is_custom_domain="$3"

  if [ -z "${domain_name}" ]; then
    return
  fi

  domain_folder="/acme.sh/${domain_name}"

  if [ -d "${domain_folder}" ]; then
    echo "${domain_folder}"
    return
  fi

  if [ -d "${domain_folder}_ecc" ]; then
    echo "${domain_folder}_ecc"
    return
  fi

  # in case of custom domain, try to find the domain folder
  if [ "${is_custom_domain}" = "true" ]; then
    latest_modified_folder=$(find /acme.sh ! -path /acme.sh -type d -name "*.*" | head -1)
    if [ -n "${latest_modified_folder}" ]; then
      echo "${latest_modified_folder}"
      return
    fi
  fi
}

get_cert_hash() {
  domain_folder="$1"

  if [ -d "${domain_folder}" ]; then
    echo $(md5sum "${domain_folder}/fullchain.cer" | awk '{ print $1 }')
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
  
  parse_ingresses

  parse_httproutes
}

parse_ingresses() {
  elems=$(get_api_kind_elems "networking.k8s.io/v1" "ingresses" | jq -c '.items | .[] | select(.metadata.annotations."acme.kubernetes.io/enable"=="true")')

  if [ "${elems}" = "" ]; then
    info "No matching ingress found"
    return
  fi

  IFS=$'\n'
  for elem in ${elems}; do
    unset IFS

    debug "elem: ${elem}"

    update_acme_args "${elem}"
    if [ "${ACME_UPDATE_ARGS_ERR}" = "invalid_namespace" ]; then
      continue
    elif [ "${ACME_UPDATE_ARGS_ERR}" = "invalid_command" ]; then
      return
    fi

    inputs=$(get_secret_name_and_hostnames_from_ingress "${elem}")
    for input in ${inputs}; do
      if [ -z "${input}" ]; then
        continue
      fi

      debug "input: ${input}"

      secret_name_val=$(echo "${input}" | sed -r 's@:.*$@@')
      secret_name_hosts=$(echo "${input}" | sed -r 's@^.*:@@' | sed -r 's@;@ @g')
      # no quotes on the last argument please
      generate_cert "${CERT_NAMESPACE}" "${secret_name_val}" ${secret_name_hosts}
    done
  done
}

parse_httproutes() {
  info "parse_httproutes"

  elems=$(get_api_kind_elems "gateway.networking.k8s.io/v1" "httproutes" | jq -c '.items | .[] | select(.metadata.annotations."acme.kubernetes.io/enable"=="true")')

  if [ "${elems}" = "" ]; then
    info "No matching httproute found"
    return
  fi

  IFS=$'\n'
  for elem in ${elems}; do
    unset IFS

    debug "elem: ${elem}"

    update_acme_args "${elem}"

    if [ "${ACME_UPDATE_ARGS_ERR}" = "invalid_namespace" ]; then
      continue
    elif [ "${ACME_UPDATE_ARGS_ERR}" = "invalid_command" ]; then
      return
    fi

    inputs=$(get_secret_name_and_hostnames_from_httproute "${elem}")
    for input in ${inputs}; do
      if [ -z "${input}" ]; then
        continue
      fi

      debug "input: ${input}"

      secret_name_val=$(echo "${input}" | sed -r 's@:.*$@@')
      secret_name_hosts=$(echo "${input}" | sed -r 's@^.*:@@' | sed -r 's@;@ @g')
      # no quotes on the last argument please
      generate_cert "${CERT_NAMESPACE}" "${secret_name_val}" ${secret_name_hosts}
    done
  done
}

update_acme_args() {
  info "update_acme_args"

  input="$1"

  CERTS_DNS=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/dns"')

  CERTS_CMD_TO_USE=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/cmd-to-use"')
  if [ "${CERTS_CMD_TO_USE}" = "null" ]; then
    CERTS_CMD_TO_USE=""
  fi

  CERTS_PRE_CMD=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/pre-cmd"')
  if [ "${CERTS_PRE_CMD}" = "null" ]; then
    CERTS_PRE_CMD=""
  fi

  CERTS_POST_CMD=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/post-cmd"')
  if [ "${CERTS_POST_CMD}" = "null" ]; then
    CERTS_POST_CMD=""
  fi

  CERTS_ONSUCCESS_CMD=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/on-success-cmd"')
  if [ "${CERTS_ONSUCCESS_CMD}" = "null" ]; then
    CERTS_ONSUCCESS_CMD=""
  fi

  CERTS_ONERROR_CMD=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/on-error-cmd"')
  if [ "${CERTS_ONERROR_CMD}" = "null" ]; then
    CERTS_ONERROR_CMD=""
  fi

  CERT_NAMESPACE=$(echo "${input}" | jq -rc '.metadata.namespace')

  if [ -n "${ACME_NAMESPACES_WHITELIST}" ]; then
    is_namespace_found="false"
    for namespace in ${ACME_NAMESPACES_WHITELIST}; do
      if [ "${CERT_NAMESPACE}" = "${namespace}" ]; then
        is_namespace_found="true"
        break
      fi
    done

    if [ "${is_namespace_found}" != "true" ]; then
      info "Namespace '${CERT_NAMESPACE}' not in whitelist"
      ACME_UPDATE_ARGS_ERR="invalid_namespace"
      return
    fi
  fi

  is_dns_valid="true"
  if [ "${CERTS_DNS}" = "null" ] || [  "${CERTS_DNS}" = "" ]; then
    info "No dns configuration found"
    is_dns_valid="false"
    # convert null to empty string
    CERTS_DNS=""
  fi

  is_cmd_to_use_valid="true"
  if [ "${CERTS_CMD_TO_USE}" = "null" ] || [ "${CERTS_CMD_TO_USE}" = "" ]; then
    info "No cmd to use found"
    is_cmd_to_use_valid="false"
    # convert null to empty string
    CERTS_CMD_TO_USE=""
  fi

  if [ "${is_dns_valid}" = "false" ] && [ "${is_cmd_to_use_valid}" = "false" ]; then
    ACME_UPDATE_ARGS_ERR="invalid_command"
    return
  fi

  CERTS_ARGS=$(echo "${input}" | jq -rc '.metadata.annotations."acme.kubernetes.io/add-args"')
  if [ "${CERTS_ARGS}" = "null" ] || [  "${CERTS_ARGS}" = "" ]; then
    info "No cmd args found"
    # convert null to empty string
    CERTS_ARGS=""
  fi

  if [ "$(echo "${input}" | jq -c '. | select(.metadata.annotations."acme.kubernetes.io/staging"=="true")' | wc -l)" = "1"  ]; then
    CERTS_IS_STAGING="true"
  fi
}

get_api_kind_elems() {
  uri="/apis/$1"
  if [ -n "${K8S_API_URI_NAMESPACE}" ]; then
    uri="${uri}/${K8S_API_URI_NAMESPACE}"
  fi
  uri="${uri}/$2"

  res_file=$(mktemp /tmp/init_env.XXXX)
  status_code=$(k8s_api_call "GET" "${uri}" 2>"${res_file}")
  
  if [ "${status_code}" != "200" ]; then
    info "Invalid status code found: ${status_code}"
  fi
    
  format_res_file "${res_file}"
  
  cat "${res_file}"
}

get_secret_name_and_hostnames_from_ingress() {
  info "get_secret_name_and_hostnames_from_ingress"

  result=""
  
  secret_names=""
  tls_inputs=$(echo "$1" | jq -c '.spec.tls | .[]')
  for input in ${tls_inputs}; do
    secret_name=$(echo "${input}" | jq -rc '.secretName')
    if [ -z "${secret_name}" ]; then
      continue
    fi

    secret_names="${secret_names} ${secret_name}"

    hosts=$(echo "${input}" | jq -rc '.hosts | .[]')
    for host in ${hosts}; do
      if [ -z "${host}" ]; then
        continue
      fi

      echo "${host}" >> "${secret_name}.list"
    done
  done

  for secret_name in ${secret_names}; do    
    if [ -z "${secret_name}" ]; then
      continue
    fi

    if [ -f "${secret_name}.list" ]; then
      result="${result} ${secret_name}:$(sort < "${secret_name}.list" | uniq | tr '\n' ';')"
    fi
  done

  debug "result: ${result}"

  echo "${result}"
}

get_secret_name_and_hostnames_from_httproute() {
  info "get_secret_name_and_hostnames_from_httproute"

  result=""
  gateway_name=$(echo "$1" | jq -rc '.spec.parentRefs[0].name')
  secret_names=$(get_secretnames_from_gateway "${gateway_name}")
  hosts=$(echo "${1}" | jq -rc '.spec.hostnames | .[]' | tr '\n' ' ')
  
  for host in ${hosts}; do
    if [ -z "${host}" ]; then
      continue
    fi
    
    secret_name_found=""
    global_secret_name=""
    
    for secret_name in ${secret_names}; do
      if [ -z "${secret_name}" ]; then
        continue
      fi

      secret_name_val=$(echo "${secret_name}" | sed -r 's@:.*$@@')
      secret_name_host=$(echo "${secret_name}" | sed -r 's@^.*:@@')
      if [ "${secret_name_host}" = "${host}" ]; then
        secret_name_found="${secret_name_val}"
        break
      elif echo "${secret_name_host}" | grep -qe '^\*'; then
        # check that host is matching secret_name_host subdomain
        # host: test.example.com, secret_name_host: *.example.com
        if echo "${host}" | grep -qe ".${secret_name_host}"; then
          secret_name_found="${secret_name_host}"
          break
        fi
      fi

      if [ -z "${secret_name_host}" ]; then
        global_secret_name="${secret_name_val}"
      fi
    done

    if [ -z "${secret_name_found}" ] && [ -n "${global_secret_name}" ]; then
      secret_name_found="${global_secret_name}"
    fi

    if [ -z "${secret_name_found}" ]; then
      continue
    fi

    echo "${host}" >> "${secret_name_found}.list"
  done

  for secret_name in ${secret_names}; do
    secret_name_val=$(echo "${secret_name}" | sed -r 's@:.*$@@')
    
    if [ -z "${secret_name_val}" ]; then
      continue
    fi

    if [ -f "${secret_name_val}.list" ]; then
      result="${result} ${secret_name_val}:$(sort < "${secret_name_val}.list" | uniq | tr '\n' ';')"
    fi
  done

  debug "result: ${result}"

  echo "${result}"
}

get_secretnames_from_gateway() {
  info "get_secretnames_from_gateway"

  result=""

  inputs=$(get_api_kind_elems "gateway.networking.k8s.io/v1" "gateways/$1" | jq -rc '.spec.listeners | .[] | select (.tls.certificateRefs[0].name!=null)')
  for input in ${inputs}; do
    host=$(echo "${input}" | jq -rc '.hostname | select (.!=null)')
    secret_name=$(echo "${input}" | jq -rc '.tls.certificateRefs[0].name | select (.!=null)')
    if [ -n "${result}" ]; then
      result="${result} "
    fi
    result="${result} ${secret_name}:${host}"
  done

  debug "result: ${result}"

  echo "${result}"
}

generate_cert() {
  cert_namespace="$1"
  shift
  name="$1"
  shift
  domains="$*"

  info "Generate certs for" \
   " dns: ${CERTS_DNS}," \
   " is_staging: ${CERTS_IS_STAGING}," \
   " is_debug: ${ACME_DEBUG}," \
   " args: ${CERTS_ARGS}," \
   " cmd to use: ${CERTS_CMD_TO_USE}," \
   " pre-cmd: ${CERTS_PRE_CMD}," \
   " post-cmd: ${CERTS_POST_CMD}," \
   " name: ${name}," \
   " namespace: ${cert_namespace}," \
   " domains: ${domains}"

  # update global variables
  CERTS_SECRET_NAME="${name}"
  CONF_SECRET_NAME="${name}-conf"
  IS_SECRET_CONF_ALREADY_EXISTS="false"

  # get previous conf if it exists
  load_conf_from_secret "${cert_namespace}"

  # prepare acme cmd args
  acme_args="--issue --ca-file '${ACME_CA_FILE}' --cert-file '${ACME_CERT_FILE}' --fullchain-file '${ACME_FULLCHAIN_FILE}' --key-file '${ACME_KEY_FILE}'"

  if [ "${ACME_DEBUG}" = "true" ]; then
    acme_args="${acme_args} --debug"
  fi
  
  if [ "${CERTS_ARGS}" != "" ]; then
    acme_args="${acme_args} ${CERTS_ARGS}"
  fi

  if [ "${CERTS_IS_STAGING}" = "true" ]; then
    acme_args="${acme_args} --staging"
  fi
  
  if [ "${CERTS_DNS}" != "" ]; then
    acme_args="${acme_args} --dns '${CERTS_DNS}'"
  fi

  main_domain=""
  for domain in ${domains}; do
    if [ "${domain}" != "" ]; then
      # set the first domain as the main domain
      if [ -z "${main_domain}" ]; then
        main_domain="${domain}"
      fi
      acme_args="${acme_args} -d ${domain}"
    fi
  done

  debug "main domain: ${main_domain}"

  # use the custom acme arg set by user if it exists
  acme_cmd="acme.sh ${acme_args}"
  if [ "${CERTS_CMD_TO_USE}" != "" ]; then
    acme_cmd="${CERTS_CMD_TO_USE}"
  fi

  is_ecc_certificate="false"
  if [ -n "$(echo "${acme_cmd}" | grep ' --keylength ec-')" ]; then
    is_ecc_certificate="true"
  fi

  is_custom_domain="false"
  if [ -n "$(echo "${acme_cmd}" | grep ' -d ')" ]; then
    is_custom_domain="true"
  fi

  domain_folder=$(get_domain_folder "${main_domain}" "${is_ecc_certificate}" "${is_custom_domain}")
  debug "domain folder: ${domain_folder}"


  # get current cert hash
  current_cert_hash=$(get_cert_hash "${domain_folder}")
  debug "current cert hash: ${current_cert_hash}"

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
  debug "Running cmd: ${acme_cmd}"
  rc=0
  eval "${acme_cmd}" || rc=$? && true
  info "acme.sh return code: ${rc}"

  # post-cmd
  if [ -n "${CERTS_POST_CMD}" ]; then
    debug "Running post-cmd: ${CERTS_POST_CMD}"
    post_cmd_rc=0
    eval "${CERTS_POST_CMD}" || post_cmd_rc=$? && true
    info "post-cmd return code: ${post_cmd_rc}"
  else
    debug "No post-cmd"
  fi

  if [ "${rc}" = "2" ]; then
    info "Certificate current. No renewal needed"
    return
  fi

  if [ "${rc}" != "0" ]; then
    info "An acme.sh error occurred"
    if [ -n "${CERTS_ONERROR_CMD}" ]; then
      eval "$(format_cmd "${CERTS_ONERROR_CMD}")" || true
    fi
    exit 1
  fi

  # update domain folder with new folder created
  domain_folder=$(get_domain_folder "${main_domain}" "${IS_ECC_CERTIFICATE}" "${IS_CUSTOM_DOMAIN}")
  debug "domain folder: ${domain_folder}"

  # get new cert hash
  new_cert_hash=$(get_cert_hash "${domain_folder}")
  debug "new cert hash: ${new_cert_hash}"

  # update secrets only if certs has been updated
  if [ "${current_cert_hash}" != "${new_cert_hash}" ]; then
    info "Certificate change, updating..."
    add_certs_to_secret "${cert_namespace}"
    add_conf_to_secret "${cert_namespace}" "${domain_folder}"
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

  cert_namespace="$1"

  secret_file="/root/secret.certs.json"

  secret_json='{}'
  secret_json=$(echo "${secret_json}" | jq --arg kind "Secret" '. + {kind: $kind}')
  secret_json=$(echo "${secret_json}" | jq --arg name "${CERTS_SECRET_NAME}" '. + {metadata: { name: $name }}')
  secret_json=$(echo "${secret_json}" | jq '. + {data: {}}')
  secret_json=$(echo "${secret_json}" | jq --arg cacert "$(get_file_data_for_secret_json "${ACME_CA_FILE}")" '. * {data: {"ca.crt": $cacert}}')
  secret_json=$(echo "${secret_json}" | jq --arg tlscert "$(get_file_data_for_secret_json "${ACME_FULLCHAIN_FILE}")" '. * {data: {"tls.crt": $tlscert}}')
  secret_json=$(echo "${secret_json}" | jq --arg tlskey "$(get_file_data_for_secret_json "${ACME_KEY_FILE}")" '. * {data: {"tls.key": $tlskey}}')

  echo -e "${secret_json}" > "${secret_file}"

  res_file=$(mktemp /tmp/add_cert.XXXX)
  status_code_checker=$(k8s_api_call "GET" "/api/v1/namespaces/${cert_namespace}/secrets/${CERTS_SECRET_NAME}" 2>"${res_file}")

  debug "Status code checker: ${status_code_checker}"

  status_code=""
  if [ "${status_code_checker}" != "200" ]; then
    info "Adding certs"
    status_code=$(k8s_api_call "POST" "/api/v1/namespaces/${cert_namespace}/secrets" --data "@${secret_file}" 2>/dev/null)
  else
    info "Updating certs"
    status_code=$(k8s_api_call "PATCH" "/api/v1/namespaces/${cert_namespace}/secrets/${CERTS_SECRET_NAME}" --data "@${secret_file}" 2>/dev/null)
  fi

  debug "Status code: ${status_code}"

  if [ "${status_code}" = "200" ] || [ "${status_code}" = "201" ]; then
    info "Certs sucessfully added"
  else
    info "Certs not added"
  fi

  rm -f "${secret_file}"
}

load_conf_from_secret() {
  info "Loading conf from secret..."

  cert_namespace="$1"

  res_file=$(mktemp /tmp/load_conf.XXXX)
  status_code=$(k8s_api_call "GET" "/api/v1/namespaces/${cert_namespace}/secrets/${CONF_SECRET_NAME}" 2>"${res_file}")

  debug "Status code: ${status_code}"

  if [ "${status_code}" = "200" ]; then
    info "Adding conf"
    IS_SECRET_CONF_ALREADY_EXISTS="true"
    format_res_file "${res_file}"
    tmp_tar_file=$(mktemp /tmp/tar_file.XXXX)
    cat "${res_file}" | jq -r '.data.conf' | base64 -d > "${tmp_tar_file}"
    tar -xf "${tmp_tar_file}" -C /
    rm -f "${tmp_tar_file}"
  else
    info "Invalid status code found: ${status_code}, configuration not loaded"
  fi

  rm -f "${res_file}"
}

add_conf_to_secret() {
  info "Adding conf to secret..."

  cert_namespace="$1"
  shift
  domain_folder="$1"

  if [ -z "${domain_folder}" ]; then
    info "no folder found for domain"
    return
  fi

  if [ ! -d "${domain_folder}" ]; then
    info "domain folder is not a directory"
    return
  fi

  tar -cvf config.tar ${domain_folder}

  secret_file="/root/secret.conf.json"

  secret_json='{}'
  secret_json=$(echo "${secret_json}" | jq --arg kind "Secret" '. + {kind: $kind}')
  secret_json=$(echo "${secret_json}" | jq --arg name "${CONF_SECRET_NAME}" '. + {metadata: { name: $name }}')
  secret_json=$(echo "${secret_json}" | jq '. + {data: {}}')
  secret_json=$(echo "${secret_json}" | jq --arg conf "$(get_file_data_for_secret_json /root/config.tar)" '. * {data: {conf: $conf}}')

  echo "${secret_json}" > "${secret_file}"

  status_code=""
  if [ "${IS_SECRET_CONF_ALREADY_EXISTS}" = "false" ]; then
    info "Adding conf"
    status_code=$(k8s_api_call "POST" "/api/v1/namespaces/${cert_namespace}/secrets" --data "@${secret_file}" 2>/dev/null)
  else
    info "Updating conf"
    status_code=$(k8s_api_call "PUT" "/api/v1/namespaces/${cert_namespace}/secrets/${CONF_SECRET_NAME}" --data "@${secret_file}" 2>/dev/null)
  fi

  debug "Status code: ${status_code}"

  if [ "${status_code}" = "200" ] || [ "${status_code}" = "201" ]; then
    info "Conf sucessfully added"
  else
    info "Conf not added"
  fi

  rm -f "${secret_file}"
}

format_cmd() {
  echo "$1" | sed -r "s@#domains#@${DOMAINS}@g"
}

source "${current_folder}/before.sh"

starter
