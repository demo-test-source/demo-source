#!/usr/bin/env bash
#******************************************************************************
# Licensed Materials - Property of IBM
# (c) Copyright IBM Corporation 2025. All Rights Reserved.
#
# Note to U.S. Government Users Restricted Rights:
# Use, duplication or disclosure restricted by GSA ADP Schedule
# Contract with IBM Corp.
#******************************************************************************

# -------------[ Pretty logging ]-------------
BLUE='\033[1;34m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; NC='\033[0m'
info()  { printf "${BLUE}➜ %s${NC}\n" "$*"; }
ok()    { printf "${GREEN}✔ %s${NC}\n" "$*"; }
warn()  { printf "${YELLOW}⚠ %s${NC}\n" "$*"; }
err()   { printf "${RED}✖ %s${NC}\n" "$*" >&2; }
sep()   { printf "\n"; printf '%*s\n' "$(tput cols 2>/dev/null || echo 80)" '' | tr ' ' '-'; printf "\n"; }
dbg() {
  if [[ "${DEBUG:-false}" == "true" ]]; then
    printf "🛠  [DEBUG] %s\n" "$*"
    read -p "Press Enter to continue"
  fi
}

# -------------[ Usage ]-------------
usage() {
  cat <<EOF
Usage: $0 -n <NAMESPACE> -r <RELEASE_NAME> [-d]

Required:
  -n   Namespace (OpenShift project) where APIC is installed
  -r   APIC Release Name

Optional:
  -d   Enable debug output

Examples:
  $0 -n apic -r apic-rel
  $0 -n apic -r apic-rel -d
EOF
  exit 1
}

# -------------[ Args ]-------------
DEBUG=false
NAMESPACE=""
RELEASE_NAME=""

while getopts ":n:r:dh" opt; do
  case "${opt}" in
    n) NAMESPACE="${OPTARG}" ;;
    r) RELEASE_NAME="${OPTARG}" ;;
    d) DEBUG=true ;;
    h) usage ;;
    \?) usage ;;
  esac
done

[[ -z "${NAMESPACE}" || -z "${RELEASE_NAME}" ]] && usage

# -------------[ Preflight ]-------------
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1"; exit 1; }
}
need_cmd oc
need_cmd jq
need_cmd curl
need_cmd base64
need_cmd awk
need_cmd tr
# tput is optional (sep() falls back to 80)
command -v tput >/dev/null 2>&1 || true

# Small helpers to reduce repetition
ocjp()      { oc get "$1" ${3:+-n "$3"} -o jsonpath="$2"; }
ocroute()   { oc get route -n "$1" "$2" -o jsonpath='{.spec.host}'; }
ocsecret()  { oc get secret -n "$2" "$1" -o json; }
first_match_route_name() { # <namespace> <grep-pattern>
  oc get routes -n "$1" | grep -m1 "$2" | awk '{print $1}'
}

# -------------[ Temp files + mkjson ]-------------
cleanup_files=()
cleanup() { for f in "${cleanup_files[@]:-}"; do [[ -f "$f" ]] && rm -f -- "$f"; done; }
trap cleanup EXIT

# mkjson: create a temp file, write JSON/text into it, echo the filename
mkjson() {
  local tmp; tmp="$(mktemp)" || { err "mktemp failed"; exit 1; }
  cleanup_files+=("$tmp")
  if [ $# -gt 0 ]; then printf '%s\n' "$1" >"$tmp"; else cat >"$tmp"; fi
  printf '%s\n' "$tmp"
}

# -------------[ Constants ]-------------
PROVIDER_ORG="main-demo"
CATALOG="main-demo-catalog"
CONSUMER_ORG="${PROVIDER_ORG}-corp"
CORG_OWNER_USERNAME="${PROVIDER_ORG}-corg-admin"
CORG_OWNER_PASSWORD="engageibmAPI1"

APIC_CLIENT_ID="599b7aef-8841-4ee2-88a0-84d49c4d6ff2"
APIC_CLIENT_SECRET="0ea28423-e73b-47d4-b40e-ddb45c48bb0c"

# -------------[ Discover APIC endpoints ]-------------
info "Discovering APIC platform API route…"
API_RESOURCE_NAME="$(first_match_route_name "$NAMESPACE" "${RELEASE_NAME:0:10}.*platform-api")"
[[ -z "${API_RESOURCE_NAME}" ]] && { err "Could not find platform-api route"; exit 1; }
API_EP="$(ocroute "$NAMESPACE" "$API_RESOURCE_NAME")"
ok "APIC endpoint: https://${API_EP}"

APIC_CLOUD_MANAGER_RESOURCE_NAME="$(first_match_route_name "$NAMESPACE" "${RELEASE_NAME:0:10}.*admin")"
APIC_CLOUD_MANAGER_UI_EP="$(ocroute "$NAMESPACE" "$APIC_CLOUD_MANAGER_RESOURCE_NAME")"
ok "Cloud Manager UI: https://${APIC_CLOUD_MANAGER_UI_EP}"

APIC_MANAGER_ROUTE_NAME="$(first_match_route_name "$NAMESPACE" "${RELEASE_NAME:0:10}.*api-manager")"
APIC_MANAGER_EP="$(ocroute "$NAMESPACE" "$APIC_MANAGER_ROUTE_NAME")"
ok "API Manager: https://${APIC_MANAGER_EP}"
sep

# -------------[ Authenticate as admin (default-idp-1) ]-------------
info "Authenticating as APIC admin (default-idp-1 realm)…"
admin_idp="admin/default-idp-1"
admin_password="$(oc get secret -n "$NAMESPACE" "${RELEASE_NAME}-mgmt-admin-pass" -o json | jq -r .data.password | base64 --decode)"

dbg "admin_idp = ${admin_idp}"
dbg "admin_password = ${admin_password}"

authenticate() { # <realm> <username> <password> -> echoes token
  local realm="$1" username="$2" password="$3"
  
  
  [ "$DEBUG" = true ] && echo "curl -X POST https://${API_EP}/api/token -s -k -H \"Content-Type: application/json\" -H \"Accept: application/json\" -d '{ \"realm\": \"${realm}\", \"username\": \"${username}\", \"password\": \"${password}\", \"client_id\": \"599b7aef-8841-4ee2-88a0-84d49c4d6ff2\", \"client_secret\": \"0ea28423-e73b-47d4-b40e-ddb45c48bb0c\", \"grant_type\": \"password\" }'"

  response=`curl -X POST https://${API_EP}/api/token \
                 -s -k -H "Content-Type: application/json" -H "Accept: application/json" \
                 -d "{ \"realm\": \"${realm}\",
                       \"username\": \"${username}\",
                       \"password\": \"${password}\",
                       \"client_id\": \"599b7aef-8841-4ee2-88a0-84d49c4d6ff2\",
                       \"client_secret\": \"0ea28423-e73b-47d4-b40e-ddb45c48bb0c\",
                       \"grant_type\": \"password\" }"`

  [ "$DEBUG" = true ] && echo "[DEBUG] $(echo ${response} | jq .)"

  if [[ "$(echo ${response} | jq -r '.status')" == "401" ]]; then
    printf "$CROSS"
    echo "[ERROR] Failed to authenticate"
    exit 1
  fi

  echo ${response} | jq -r '.access_token'
}

admin_token="$(authenticate "$admin_idp" "admin" "$admin_password")" || exit 1
ok "Admin token acquired"
dbg "admin_token: ${admin_token}"
sep

# -------------[ Get Integration Keycloak token endpoint ]-------------
info "Fetching Integration Keycloak token endpoint…"

# Use Cloud Manager host for user registries (platform API returns 400 HTML)
ik_headers="$(mktemp)"; cleanup_files+=("$ik_headers")
ik_body="$(mktemp)";    cleanup_files+=("$ik_body")

curl -sSk -D "$ik_headers" -o "$ik_body" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer ${admin_token}" \
  "https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin" >/dev/null

ik_status="$(awk 'toupper($1)=="HTTP/"{code=$2} END{print code}' "$ik_headers")"
ik_ct="$(awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}' "$ik_headers" | tr -d '\r')"
dbg "user-registries HTTP $ik_status CT=${ik_ct:-unknown}"

if ! [[ "$ik_status" =~ ^2 ]] || ! grep -qi "application/json" <<<"${ik_ct:-}"; then
  # Fallback older path
  curl -sSk -D "$ik_headers" -o "$ik_body" \
    -H "Accept: application/json" \
    -H "Authorization: Bearer ${admin_token}" \
    "https://${APIC_CLOUD_MANAGER_UI_EP}/api/orgs/admin/user-registries" >/dev/null
  ik_status="$(awk 'toupper($1)=="HTTP/"{code=$2} END{print code}' "$ik_headers")"
  ik_ct="$(awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}' "$ik_headers" | tr -d '\r')"
  dbg "fallback user-registries HTTP $ik_status CT=${ik_ct:-unknown}"
fi

[[ "$ik_status" =~ ^2 ]] || { err "User registries request failed (HTTP $ik_status)"; exit 1; }
grep -qi "application/json" <<<"${ik_ct:-}" || { err "Expected JSON but got ${ik_ct:-unknown}"; exit 1; }

IK_TOKEN_ENDPOINT="$(
  jq -r '
    .results[]
    | select(.name|test("integration[-]?keycloak"; "i"))
    | .configuration.token_endpoint.endpoint // empty
  ' "$ik_body" | head -n1
)"
[[ -n "${IK_TOKEN_ENDPOINT}" && "${IK_TOKEN_ENDPOINT}" != "null" ]] || { err "integration-keycloak token endpoint not found"; exit 1; }
ok "IK token endpoint: ${IK_TOKEN_ENDPOINT}"
sep

# -------------[ Keycloak client info for this APIC release ]-------------
info "Getting Keycloak client ID/secret for release ${RELEASE_NAME}…"
KEYCLOAK_CLIENT_ID="$(oc get secret "keycloak-client-secret-${RELEASE_NAME}-keycloak-client" -n "${NAMESPACE}" -o jsonpath='{.data.CLIENT_ID}' | base64 --decode | tr -d '\r\n%')"
KEYCLOAK_CLIENT_SECRET="$(oc get secret "keycloak-client-secret-${RELEASE_NAME}-keycloak-client" -n "${NAMESPACE}" -o jsonpath='{.data.CLIENT_SECRET}' | base64 --decode | tr -d '\r\n%')"
dbg "KEYCLOAK_CLIENT_ID=${KEYCLOAK_CLIENT_ID}"
dbg "KEYCLOAK_CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET}"
sep

# -------------[ Configure Keycloak client: enable directAccessGrants + audience mapper ]-------------
CONFIGURE_KEYCLOAK_CONFIG() { # <apic_keycloak_client>
  local client="$1"
  info "Configuring Keycloak client '${client}' (enable Direct Access Grants, add audience mapper)…"

  # Find Keycloak route/namespace
  local kc_ns; kc_ns="$(oc get route keycloak -n ibm-common-services -o jsonpath='{.metadata.namespace}' 2>/dev/null || true)"
  [[ -z "$kc_ns" ]] && kc_ns="$(oc get route keycloak -n "${NAMESPACE}" -o jsonpath='{.metadata.namespace}')"

  local KC_HOST; KC_HOST="$(oc get route keycloak -n "${kc_ns}" -o jsonpath='{.spec.host}')"
  dbg "KEYCLOAK HOST: ${KC_HOST}"

  # Admin creds
  local KC_ADMIN_USER KC_ADMIN_PASS
  KC_ADMIN_USER="$(oc get secret cs-keycloak-initial-admin -n "${kc_ns}" -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')"
  KC_ADMIN_PASS="$(oc get secret cs-keycloak-initial-admin -n "${kc_ns}" -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')"

  # Admin token
  local KC_TOKEN
  KC_TOKEN="$(
    curl -sS -X POST "https://${KC_HOST}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=${KC_ADMIN_USER}" -d "password=${KC_ADMIN_PASS}" -d "grant_type=password" -d "client_id=admin-cli" \
      | jq -r '.access_token'
  )"
  dbg "KC_TOKEN: ${KC_TOKEN}"

  # Client lookup
  local KC_CLIENT_JSON UUID GRANT
  KC_CLIENT_JSON="$(
    curl -sS -X GET "https://${KC_HOST}/admin/realms/cloudpak/clients?clientId=${client}" \
      -H "Authorization: Bearer ${KC_TOKEN}"
  )"
  dbg "KC client JSON: ${KC_CLIENT_JSON}"
  UUID="$(jq -r '.[].id' <<<"$KC_CLIENT_JSON")"
  GRANT="$(jq -r '.[].directAccessGrantsEnabled' <<<"$KC_CLIENT_JSON")"
  [[ -n "$UUID" && "$UUID" != "null" ]] || { err "Keycloak client '${client}' not found"; exit 1; }

  if [[ "$GRANT" == "true" ]]; then
    ok "Direct Access Grants already enabled"
  else
    info "Enabling Direct Access Grants…"
    curl -sS -X PUT "https://${KC_HOST}/admin/realms/cloudpak/clients/${UUID}" \
      -H "Authorization: Bearer ${KC_TOKEN}" -H "Content-Type: application/json" \
      -d '{"directAccessGrantsEnabled": true}' >/dev/null
    sleep 5
    ok "Direct Access Grants enabled"
  fi

  # Audience mapper
  info "Adding audience mapper…"
  local audf
  audf="$(mkjson "$(jq -n --arg n "apic-audience-mapper" --arg a "$client" \
    '{name:$n,protocol:"openid-connect",protocolMapper:"oidc-audience-mapper",consentRequired:false,
      config:{"included.client.audience":$a,"access.token.claim":"true","id.token.claim":"true"}}')")"

  curl -sS -X POST "https://${KC_HOST}/admin/realms/cloudpak/clients/${UUID}/protocol-mappers/models" \
    -H "Authorization: Bearer ${KC_TOKEN}" -H "Content-Type: application/json" \
    --data @"${audf}" >/dev/null || warn "Audience mapper may already exist"
  ok "Audience mapper configured"

  # Verify integration-admin email
  info "Ensuring integration-admin has a verified email…"
  local INTEGRATION_ADMIN_ID
  INTEGRATION_ADMIN_ID="$(
    curl -sS -X GET "https://${KC_HOST}/admin/realms/cloudpak/users?username=integration-admin" \
      -H "Authorization: Bearer ${KC_TOKEN}" | jq -r '.[0].id'
  )"
  dbg "INTEGRATION_ADMIN_ID: ${INTEGRATION_ADMIN_ID}"

  if [[ -n "${INTEGRATION_ADMIN_ID}" && "${INTEGRATION_ADMIN_ID}" != "null" ]]; then
    curl -sS -X PUT "https://${KC_HOST}/admin/realms/cloudpak/users/${INTEGRATION_ADMIN_ID}" \
      -H "Authorization: Bearer ${KC_TOKEN}" -H "Content-Type: application/json" \
      -d '{"email":"theprocrastinator@example.com","emailVerified":true}' >/dev/null || true
    ok "integration-admin email set & verified"
  else
    warn "integration-admin user not found; skipping email update"
  fi

  sep
}
CONFIGURE_KEYCLOAK_CONFIG "${KEYCLOAK_CLIENT_ID}"

# -------------[ Fetch integration-admin initial creds ]-------------
info "Fetching integration-admin temporary credentials…"
INTEGRATION_ADMIN_SECRET_NAMESPACE="$(
  oc get secret integration-admin-initial-temporary-credentials -n ibm-common-services -o jsonpath='{.metadata.namespace}' 2>/dev/null || true
)"
[[ -z "$INTEGRATION_ADMIN_SECRET_NAMESPACE" ]] && INTEGRATION_ADMIN_SECRET_NAMESPACE="${NAMESPACE}"

INTEGRATION_ADMIN_USRNAME="$(oc get secret integration-admin-initial-temporary-credentials -n "${INTEGRATION_ADMIN_SECRET_NAMESPACE}" -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')"
INTEGRATION_ADMIN_PWD="$(oc get secret integration-admin-initial-temporary-credentials -n "${INTEGRATION_ADMIN_SECRET_NAMESPACE}" -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')"
ok "integration-admin user: ${INTEGRATION_ADMIN_USRNAME}"
sep

# -------------[ IK token (resource-owner password) ]-------------
info "Getting access token from Integration Keycloak for integration-admin…"
TOKEN="$(
  curl -sSk -X POST "${IK_TOKEN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password" \
    -d "client_id=${KEYCLOAK_CLIENT_ID}" \
    -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
    -d "username=${INTEGRATION_ADMIN_USRNAME}" \
    -d "password=${INTEGRATION_ADMIN_PWD}" | jq -r '.access_token'
)"
[[ -n "${TOKEN}" && "${TOKEN}" != "null" ]] || { err "Failed to obtain Integration Keycloak token"; exit 1; }
ok "IK token acquired"
sep

# -------------[ Cloud org creation ]-------------
org_name="main-demo"
org_title="main-demo"

info "Looking up owner URL for integration-admin in Integration Keycloak registry…"
userf="$(mkjson "$(jq -n --arg u "$INTEGRATION_ADMIN_USRNAME" '{username:$u,remote:false}')")"
OWNER_LOOKUP_URL="https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin/integration-keycloak/search"
OWNER_URL="$(
  curl -sSk -X POST "${OWNER_LOOKUP_URL}" \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    --data @"${userf}" | jq -r '.results[].url' | head -n1
)"
[[ -n "${OWNER_URL}" && "${OWNER_URL}" != "null" ]] || { err "Owner URL not found for ${INTEGRATION_ADMIN_USRNAME}"; exit 1; }
ok "Owner URL: ${OWNER_URL}"

info "Creating provider org '${org_name}' (idempotent)…"
orgf="$(mkjson "$(jq -n --arg t "$org_title" --arg n "$org_name" --arg u "$OWNER_URL" '{title:$t,name:$n,owner_url:$u}')")"
curl -sSk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/orgs" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data @"${orgf}" >/dev/null || true
ok "Org ensured"
sep

# -------------[ Catalog creation ]-------------
cat_name="main-demo-catalog"
cat_title="main-demo-catalog"
cat_description="Test Catalog"

info "Getting org URL for ${org_name}…"
ORG_URL="$(
  curl -sSk -X GET "https://${APIC_CLOUD_MANAGER_UI_EP}/api/orgs/${org_name}" \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" | jq -r '.url'
)"
[[ -n "${ORG_URL}" && "${ORG_URL}" != "null" ]] || { err "Org URL not found"; exit 1; }
ok "Org URL: ${ORG_URL}"

info "Creating catalog '${cat_name}' (idempotent)…"
catf="$(mkjson "$(jq -n --arg n "$cat_name" --arg t "$cat_title" --arg s "$cat_description" '{name:$n,title:$t,summary:$s}')")"
curl -sSk -X POST "${ORG_URL}/catalogs" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data @"${catf}" >/dev/null || true
ok "Catalog ensured"
sep

# -------------[ Create Consumer Org + Owner ]-------------
info "Discovering Consumer Org & owner…"

# Helper: get Keycloak host + admin token (re-uses the same cluster Keycloak)
get_kc_admin() {
  local kc_ns; kc_ns="$(oc get route keycloak -n ibm-common-services -o jsonpath='{.metadata.namespace}' 2>/dev/null || true)"
  [[ -z "$kc_ns" ]] && kc_ns="$(oc get route keycloak -n "${NAMESPACE}" -o jsonpath='{.metadata.namespace}')"
  KC_HOST="$(oc get route keycloak -n "${kc_ns}" -o jsonpath='{.spec.host}')"

  local KC_ADMIN_USER KC_ADMIN_PASS
  KC_ADMIN_USER="$(oc get secret cs-keycloak-initial-admin -n "${kc_ns}" -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')"
  KC_ADMIN_PASS="$(oc get secret cs-keycloak-initial-admin -n "${kc_ns}" -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')"

  KC_TOKEN="$(
    curl -sS -X POST "https://${KC_HOST}/realms/master/protocol/openid-connect/token" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "username=${KC_ADMIN_USER}" -d "password=${KC_ADMIN_PASS}" \
      -d "grant_type=password" -d "client_id=admin-cli" \
    | jq -r '.access_token'
  )"
  [[ -n "${KC_TOKEN}" && "${KC_TOKEN}" != "null" ]] || { err "Failed to obtain Keycloak admin token"; exit 1; }
}

# Ensure a Keycloak user exists (realm: cloudpak) with a known password
ensure_kc_user() { # <username> <password> <email>
  local user="$1" pass="$2" email="$3"
  dbg "Ensuring Keycloak user '${user}' exists in realm 'cloudpak'…"

  local uid
  uid="$(
    curl -sS -X GET "https://${KC_HOST}/admin/realms/cloudpak/users?username=${user}" \
      -H "Authorization: Bearer ${KC_TOKEN}" | jq -r '.[0].id // empty'
  )"

  if [[ -z "$uid" ]]; then
    info "Creating Keycloak user '${user}'…"
    local payload; payload="$(mkjson "$(jq -n --arg u "$user" --arg e "$email" \
      '{username:$u, email:$e, enabled:true, emailVerified:true}')")"
    curl -sS -o /dev/null -w "%{http_code}" \
      -X POST "https://${KC_HOST}/admin/realms/cloudpak/users" \
      -H "Authorization: Bearer ${KC_TOKEN}" -H "Content-Type: application/json" \
      --data @"${payload}" | grep -qE '^(200|201|204)$' || warn "User creation may have already happened"

    uid="$(
      curl -sS -X GET "https://${KC_HOST}/admin/realms/cloudpak/users?username=${user}" \
        -H "Authorization: Bearer ${KC_TOKEN}" | jq -r '.[0].id // empty'
    )"
  else
    ok "Keycloak user '${user}' already exists"
  fi

  if [[ -n "$uid" ]]; then
    info "Setting password for '${user}'…"
    local pw; pw="$(mkjson "$(jq -n --arg p "$pass" '{type:"password", value:$p, temporary:false}')")"
    curl -sS -o /dev/null -w "%{http_code}" \
      -X PUT "https://${KC_HOST}/admin/realms/cloudpak/users/${uid}/reset-password" \
      -H "Authorization: Bearer ${KC_TOKEN}" -H "Content-Type: application/json" \
      --data @"${pw}" | grep -qE '^(200|204)$' || warn "Password set may have been skipped"
  else
    err "Could not determine user id for '${user}' after creation"; exit 1
  fi
}

# 1) Ensure the Consumer Org owner account exists in Keycloak
get_kc_admin
ensure_kc_user "${CORG_OWNER_USERNAME}" "${CORG_OWNER_PASSWORD}" "${CORG_OWNER_USERNAME}@example.com"
ok "Consumer Org owner ensured in Keycloak"
sep

# 2) Find the APIC registry URL for that user (owner_url)
info "Resolving owner URL for '${CORG_OWNER_USERNAME}' via Integration Keycloak registry…"
corg_owner_query="$(mkjson "$(jq -n --arg u "$CORG_OWNER_USERNAME" '{username:$u,remote:false}')")"
CORG_OWNER_URL="$(
  curl -sSk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin/integration-keycloak/search" \
    -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    --data @"${corg_owner_query}" | jq -r '.results[].url' | head -n1
)"
[[ -n "${CORG_OWNER_URL}" && "${CORG_OWNER_URL}" != "null" ]] || { err "Owner URL not found for ${CORG_OWNER_USERNAME}"; exit 1; }
ok "Owner URL: ${CORG_OWNER_URL}"
sep

# 3) Create (or ensure) the Consumer Org under the provider org
info "Creating Consumer Org '${CONSUMER_ORG}' (idempotent)…"
corg_payload="$(mkjson "$(jq -n --arg n "$CONSUMER_ORG" --arg t "$CONSUMER_ORG" --arg u "$CORG_OWNER_URL" '{name:$n,title:$t,owner_url:$u}')")"
curl -sSk -X POST "${ORG_URL}/consumer-orgs" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data @"${corg_payload}" >/dev/null || true
ok "Consumer Org ensured"
sep

# 4) Ensure the owner is a member with 'owner' role
info "Ensuring '${CORG_OWNER_USERNAME}' is an owner member of '${CONSUMER_ORG}'…"
CORG_URL="$(
  curl -sSk -X GET "${ORG_URL}/consumer-orgs/${CONSUMER_ORG}" \
    -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/json" | jq -r '.url'
)"
[[ -n "${CORG_URL}" && "${CORG_URL}" != "null" ]] || { err "Consumer Org URL not found"; exit 1; }

member_payload="$(mkjson "$(jq -n --arg u "$CORG_OWNER_URL" --argjson roles '["owner"]' '{user_url:$u, roles:$roles}')")"
curl -sSk -X POST "${CORG_URL}/members" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data @"${member_payload}" >/dev/null || true
ok "Owner membership ensured"
sep

# 5) Ensure the catalog is visible to the Consumer Org
info "Granting catalog '${CATALOG}' visibility to '${CONSUMER_ORG}' (idempotent)…"
CAT_URL="$(
  curl -sSk -X GET "${ORG_URL}/catalogs/${CATALOG}" \
    -H "Authorization: Bearer ${TOKEN}" -H "Accept: application/json" | jq -r '.url'
)"
[[ -n "${CAT_URL}" && "${CAT_URL}" != "null" ]] || { err "Catalog URL not found"; exit 1; }

visibility_payload="$(mkjson "$(jq -n --arg u "$CORG_URL" '{target_url:$u}')")"
curl -sSk -X POST "${CAT_URL}/visibility" \
  -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
  --data @"${visibility_payload}" >/dev/null || true
ok "Catalog visibility ensured"

sep
ok "All done ✅"
