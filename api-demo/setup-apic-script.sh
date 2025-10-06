
#!/bin/bash
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

first_match_route_name() { # <namespace> <grep-pattern>
  oc get routes -n "$1" | grep -m1 "$2" | awk '{print $1}'
}
ocroute()   { oc get route -n "$1" "$2" -o jsonpath='{.spec.host}'; }

# -------------[ Constants ]-------------
PROVIDER_ORG="main-demo"
CATALOG="main-demo-catalog"
CONSUMER_ORG="${PROVIDER_ORG}-corp"
CORG_OWNER_USERNAME="${PROVIDER_ORG}-corg-admin"
CORG_OWNER_PASSWORD="engageibmAPI1"

APIC_CLIENT_ID="599b7aef-8841-4ee2-88a0-84d49c4d6ff2"
APIC_CLIENT_SECRET="0ea28423-e73b-47d4-b40e-ddb45c48bb0c"



info "[INFO] Discovering APIC platform API route…"
API_RESOURCE_NAME="$(first_match_route_name "$NAMESPACE" "${RELEASE_NAME:0:10}.*platform-api")"
[[ -z "${API_RESOURCE_NAME}" ]] && { err "Could not find platform-api route"; exit 1; }
API_EP="$(ocroute "$NAMESPACE" "$API_RESOURCE_NAME")"
ok "APIC endpoint: https://${API_EP}"


sep



function authenticate() {
  realm=${1}
  username=${2}
  password=${3}

  info "AUTHENTICATE AS ${username} USER..."

  dbg "curl -X POST \"https://${API_EP}/api/token\" -s -k \
    -H \"Content-Type: application/json\" -H \"Accept: application/json\" \
    -d \"$(jq -nc \
            --arg realm \"$realm\" \
            --arg username \"$username\" \
            --arg password \"$password\" \
            --arg client_id '599b7aef-8841-4ee2-88a0-84d49c4d6ff2' \
            --arg client_secret '0ea28423-e73b-47d4-b40e-ddb45c48bb0c' \
            --arg grant_type 'password' \
            '{realm:$realm,username:$username,password:$password,client_id:$client_id,client_secret:$client_secret,grant_type:$grant_type}')\""

  response=`curl -X POST https://${API_EP}/api/token \
                 -s -k -H "Content-Type: application/json" -H "Accept: application/json" \
                 -d "{ \"realm\": \"${realm}\",
                       \"username\": \"${username}\",
                       \"password\": \"${password}\",
                       \"client_id\": \"599b7aef-8841-4ee2-88a0-84d49c4d6ff2\",
                       \"client_secret\": \"0ea28423-e73b-47d4-b40e-ddb45c48bb0c\",
                       \"grant_type\": \"password\" }"`
  dbg "$(jq . <<<"${response}")"
  if [[ "$(echo ${response} | jq -r '.status')" == "401" ]]; then
    printf "$CROSS"
    echo "[ERROR] Failed to authenticate"
    exit 1
  fi
  RESULT=`echo ${response} | jq -r '.access_token'`
  return 0
}


# -------------[ Configure Keycloak client: enable directAccessGrants + audience mapper ]-------------
function CONFIGURE_KEYCLOAK_CONFIG(){

  APIC_KEYCLOAK_CLIENT=$1
  info "[INFO] Configuring Keycloak client '${APIC_KEYCLOAK_CLIENT}' (enable Direct Access Grants, add audience mapper)…"

  ####################################################################################
  # IN THIS CODE BLOCK WE ARE ENABLING THE GRANT ACCESS FOR THE APIC KEYCLOAK CLIENT #
  ####################################################################################

  info "[INFO] FETCHING KEYCLOAK ROUTE..."
  KEYCLOAK_NAMESPACE=$(oc get route keycloak -n ibm-common-services -o jsonpath='{.metadata.namespace}') # Check for keycloak route in ibm-common-services namespace, applicable for cluster-wide install
  if [ -z "$KEYCLOAK_NAMESPACE" ]; then
    KEYCLOAK_NAMESPACE=$(oc get route keycloak -n ${NAMESPACE} -o jsonpath='{.metadata.namespace}')
  else
    printf "$CROSS"
    err "[ERROR] KEYCLOAK ROUTE NOT FOUND..."
    info "[INFO] KEYCLOAK IS REQUIRED..."
    exit 1
  fi

  ok "KEYCLOAK_NAMESPACE=${KEYCLOAK_NAMESPACE}"
  dbg "KEYCLOAK_NAMESPACE: ${KEYCLOAK_NAMESPACE}"

  KEYCLOAK_ROUTE=$(oc get route keycloak -n ${KEYCLOAK_NAMESPACE} -o jsonpath='{.spec.host}' )
  ok "KEYCLOAK_ROUTE=${KEYCLOAK_ROUTE}"
  dbg " KEYCLOAK_ROUTE: ${KEYCLOAK_ROUTE}" 

  info "[INFO]FETCHING KEYCLOAK ADMIN USR/PWD..."
  KEYCLOAK_ADMIN_USRNAME=$(oc get secret cs-keycloak-initial-admin -n ${KEYCLOAK_NAMESPACE} -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')
  KEYCLOAK_ADMIN_PWD=$(oc get secret cs-keycloak-initial-admin -n ${KEYCLOAK_NAMESPACE} -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')

  if [[ -z "$KEYCLOAK_ADMIN_USRNAME" || -z "$KEYCLOAK_ADMIN_PWD" ]]; then
    err "[ERROR] MISSING KEYCLOAK_ADMIN_USRNAME='$KEYCLOAK_ADMIN_USRNAME' OR KEYCLOAK_ADMIN_PWD='$KEYCLOAK_ADMIN_PWD'"
    exit 1
  fi

  dbg " KEYCLOAK_ADMIN_SECRET_NAMESPACE: ${KEYCLOAK_NAMESPACE}" 
  dbg "KEYCLOAK_ADMIN_USRNAME: ${KEYCLOAK_ADMIN_USRNAME}"
  dbg "KEYCLOAK_ADMIN_PWD: ${KEYCLOAK_ADMIN_PWD}"


  info "[INFO] FETCH KEYCLOAK TOKEN..."

  dbg "KC_TOKEN: curl -X POST \"https://${KEYCLOAK_ROUTE}/realms/master/protocol/openid-connect/token\" -H \"Content-Type: application/x-www-form-urlencoded\" -d \"username=${KEYCLOAK_ADMIN_USRNAME}\" -d \"password=${KEYCLOAK_ADMIN_PWD}\" -d \"grant_type=password\" -d \"client_id=admin-cli\" | jq -r '.access_token'"

  KC_TOKEN=$(curl -X POST "https://${KEYCLOAK_ROUTE}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KEYCLOAK_ADMIN_USRNAME}" -d "password=${KEYCLOAK_ADMIN_PWD}" -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

  dbg "KEYCLOAK TOKEN: ${KC_TOKEN}"

  dbg "KEYCLOAK CLIENT: curl -X GET \"https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients?clientId=${APIC_KEYCLOAK_CLIENT}\" -H \"Authorization: Bearer ${KC_TOKEN}\""

  KC_CLIENT=$(curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients?clientId=${APIC_KEYCLOAK_CLIENT}" \
  -H "Authorization: Bearer $KC_TOKEN")

  info "[INFO] KEYCLOAK CLIENT: $KC_CLIENT"

  sep

  info "[INFO] GET UUID: "$KC_CLIENT" | jq -r '.[].id'"

  sep

  UUID=$(echo "$KC_CLIENT" | jq -r '.[].id')
  if [[ -z "$UUID" ]]; then
    err "[ERROR] UUID: $UUID"
    exit 1
  fi


  GRANT=$(echo "$KC_CLIENT" | jq -r '.[].directAccessGrantsEnabled')
  if [[ -z "$GRANT" ]]; then
    err "[ERROR] GRANT: $GRANT"
    exit 1
  fi

  info "[INFO] CURRENT GRANT STATUS: $GRANT"


  if [ $GRANT == "true" ] ; then
    info "[INFO] GRANT ALREADY ENABLED"
  else
    echo "ENABLING GRANT..."
    dbg "curl -X PUT \"https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/${UUID}\" -H \"Content-Type: application/json\" -H \"Authorization: Bearer ${KC_TOKEN}\" -d '{\"directAccessGrantsEnabled\": true}'"

    # Enabling the Grant type
    curl -X PUT "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/$UUID" \
    -H "Content-Type: application/json" -H "Authorization: Bearer $KC_TOKEN" -d '{"directAccessGrantsEnabled": true}'

    sleep 30

    KC_RESPONSE=$(curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients?clientId=${APIC_KEYCLOAK_CLIENT}" -H "Authorization: Bearer $KC_TOKEN")
    GRANT=$(echo "$KC_RESPONSE" | jq -r '.[].directAccessGrantsEnabled')

    info "[INFO] GRANT STATUS: ${GRANT}"
  fi

  ####################################################################################
  # IN THE FOLLOWING CODE BLOCK WE ARE CONFIGURING GROUP MAPPER FOR THIS CLIENT      #
  ####################################################################################
  

  ####################################################################################
  # CREATING JSON FOR THE MAPPER                                                     #
  ####################################################################################

  sep
cat > aud.json<<EOF
    {
    "name": "test-mapper",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-audience-mapper",
    "consentRequired": false,
    "config": {
      "included.client.audience": "$APIC_KEYCLOAK_CLIENT",
      "access.token.claim": "true",
      "id.token.claim": "true"
      }
    }
EOF

  cat aud.json

  info "[INFO] APPLYING THE AUD.JSON"

  dbg "CURL COMMAND FOR SETTING UP: curl -X POST \"https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/${UUID}/protocol-mappers/models\" -H \"Authorization: Bearer ${KC_TOKEN}\" -H \"Content-Type: application/json\" -d @aud.json"

  curl -X POST https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/$UUID/protocol-mappers/models \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d @aud.json

  sep

  # FETCH USERID FOR INTEGRATION-ADMIN USER
  dbg "curl -X GET \"https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users?username=integration-admin\" -H \"Authorization: Bearer ${KC_TOKEN}\""

  INTEGRATION_ADMIN_ID=$(curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users?username=integration-admin" \
    -H "Authorization: Bearer $KC_TOKEN" | jq -r '.[0].id')

  dbg "INTEGRATION_ADMIN_ID: $INTEGRATION_ADMIN_ID"
  if [[ -z "$INTEGRATION_ADMIN_ID" ]]; then
    err "[ERROR] INTEGRATION_ADMIN_ID: ${INTEGRATION_ADMIN_ID} is empty"
    exit 1
  fi
 
  # ADD EMAIL ID FOR THE INTEGRATION_ADMIN USER
  dbg "curl -X PUT \"https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users/${INTEGRATION_ADMIN_ID}\" \
     -H \"Authorization: Bearer ${KC_TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d '{\"email\":\"theprocrastinator@example.com\",\"emailVerified\":true}'"

RES=$(curl -X PUT "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users/${INTEGRATION_ADMIN_ID}" \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "email": "theprocrastinator@example.com",
        "emailVerified": true
      }')
 dbg "RESPONSE: $RES"

}

sep

info "[INFO] LOGGING IN ${API_EP} ..."

admin_idp=admin/default-idp-1
admin_password=$(oc get secret -n $NAMESPACE ${RELEASE_NAME}-mgmt-admin-pass -o json | jq -r .data.password | base64 --decode)

info "[INFO] REALM: ${admin_idp} USERNAME:admin PASSWORD:${admin_password}"

if [[ -z "$admin_idp" || -z "$admin_password" ]]; then
  err "[ERROR] ONE OF REALM: ${admin_idp} USERNAME:admin OR PASSWORD:${admin_password} is EMPTY"
  exit 1
fi

sep

authenticate "${admin_idp}" "admin" "${admin_password}" # Function call
admin_token="${RESULT}"

dbg " ADMIN TOKEN: ${admin_token}"

sep


## Get Keycloak URL for Cloudpak user registry
info "[INFO] GETTING CLOUDPAK USER REGISTRY..."

dbg "curl -X GET \"https://${API_EP}/api/orgs/admin/user-registries\" -s -k -H \"Accept: application/json\" -H \"Authorization: Bearer ${admin_token}\""

response=`curl -X GET https://${API_EP}/api/orgs/admin/user-registries \
               -s -k -H "Accept: application/json" \
               -H "Authorization: Bearer ${admin_token}"`

IK_TOKEN_ENDPOINT=$(echo "${response}" | jq -r '.results[] | select(.name == "integration-keycloak") .configuration.token_endpoint.endpoint')

dbg "IK_TOKEN_ENDPOINT: $IK_TOKEN_ENDPOINT"

sep

APIC_CLOUD_MANAGER_RESOURCE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*admin" | awk '{print $1}')

info "[INFO] APIC_CLOUD_MANAGER_RESOURCE_NAME: $APIC_CLOUD_MANAGER_RESOURCE_NAME"

APIC_CLOUD_MANAGER_UI_EP=$(oc get route -n $NAMESPACE ${APIC_CLOUD_MANAGER_RESOURCE_NAME} -o jsonpath='{.spec.host}')

info "[INFO] APIC_CLOUD_MANAGER_UI_EP: $APIC_CLOUD_MANAGER_UI_EP"

sep

info "[INFO] FINDING THE KEYCLOAK CLIENT FOR APIC RELEASE: ${RELEASE_NAME}...."

KEYCLOAK_CLIENT_ID=$(oc get secret keycloak-client-secret-${RELEASE_NAME}-keycloak-client -n ${NAMESPACE} -o jsonpath='{.data.CLIENT_ID}' | base64 --decode | tr -d '\r\n%')
KEYCLOAK_CLIENT_SECRET=$(oc get secret keycloak-client-secret-${RELEASE_NAME}-keycloak-client -n ${NAMESPACE} -o jsonpath='{.data.CLIENT_SECRET}' | base64 --decode | tr -d '\r\n%')
dbg "KEYCLOAK CLIENT ID: ${KEYCLOAK_CLIENT_ID}"
dbg "KEYCLOAK CLIENT SECRET: ${KEYCLOAK_CLIENT_SECRET}"

sep

CONFIGURE_KEYCLOAK_CONFIG $KEYCLOAK_CLIENT_ID # Function call

info "[INFO] FETCHING THE INTEGRATION_ADMIN LOGIN CREDENTIALS..."

KEYCLOAK_NAMESPACE=$(oc get route keycloak -n ibm-common-services -o jsonpath='{.metadata.namespace}') # Check for keycloak route in ibm-common-services namespace, applicable for cluster-wide install
if [ -z "$KEYCLOAK_NAMESPACE" ]; then
  KEYCLOAK_NAMESPACE=$(oc get route keycloak -n ${NAMESPACE} -o jsonpath='{.metadata.namespace}')
else
  printf "$CROSS"
  err "[ERROR] KEYCLOAK NAMESPACE NOT FOUND..."
  info "[INFO] KEYCLOAK IS REQUIRED..."
  exit 1
fi

INTEGRATION_ADMIN_SECRET_NAMESPACE=$(oc get secret integration-admin-initial-temporary-credentials -n ibm-common-services -o jsonpath='{.metadata.namespace}')

if [ -z "$INTEGRATION_ADMIN_SECRET_NAMESPACE" ]; then
    dbg "KEYCLOAK_NAMESPACE: ${KEYCLOAK_NAMESPACE}"
    INTEGRATION_ADMIN_SECRET_NAMESPACE=$(oc get secret integration-admin-initial-temporary-credentials -n ${KEYCLOAK_NAMESPACE} -o jsonpath='{.metadata.namespace}')
else
  err "[ERROR] UNABLE TO FETCH INTEGRATION_ADMIN_SECRET_NAMESPACE: $INTEGRATION_ADMIN_SECRET_NAMESPACE"
  exit 1
fi

info "[INFO] INTEGRATION_ADMIN_SECRET_NAMESPACE: ${INTEGRATION_ADMIN_SECRET_NAMESPACE}"

sep

INTEGRATION_ADMIN_USRNAME=$(oc get secret integration-admin-initial-temporary-credentials -n ${INTEGRATION_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')
INTEGRATION_ADMIN_PWD=$(oc get secret integration-admin-initial-temporary-credentials -n ${INTEGRATION_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')

info "[INFO] INTEGRATION_ADMIN_USRNAME: ${INTEGRATION_ADMIN_USRNAME}"
info "[INFO] INTEGRATION_ADMIN_PWD: ${INTEGRATION_ADMIN_PWD}"

sep

org_name="main-demo" #Org name that needs to be created
org_title="main-demo" #Org title 

cat_name="main-demo-catalog"  #catalog name that needs to be created
cat_title="main-demo-catalog"  #catalog title
cat_description="Test Catalog"  #catalog description



#Get the access token
info "[INFO] GET ACCESS TOKEN FOR INTEGRATION KEYCLOAK USER FOR ${$KEYCLOAK_CLIENT_ID}..."
dbg "curl -sk -X POST \"${IK_TOKEN_ENDPOINT}\" \
     -H \"Content-Type: application/x-www-form-urlencoded\" \
     -d \"grant_type=password\" \
     -d \"client_id=${KEYCLOAK_CLIENT_ID}\" \
     -d \"client_secret=${KEYCLOAK_CLIENT_SECRET}\" \
     -d \"username=${INTEGRATION_ADMIN_USRNAME}\" \
     -d \"password=${INTEGRATION_ADMIN_PWD}\" \
     | jq -r '.access_token'"

TOKEN=$(curl -sk -X POST "$IK_TOKEN_ENDPOINT" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=password" -d "client_id=$KEYCLOAK_CLIENT_ID" -d "client_secret=$KEYCLOAK_CLIENT_SECRET" -d "username=$INTEGRATION_ADMIN_USRNAME" -d "password=$INTEGRATION_ADMIN_PWD" | jq -r '.access_token')
echo -e "\n"
info "[INFO] TOKEN: ${TOKEN}"

sep

info "[INFO] CREATE THE USER JSON FOR OWNER URL.."

cat > user.json<<EOF
{
  "username": "$INTEGRATION_ADMIN_USRNAME",
  "remote": false
}
EOF

cat user.json
echo -e "\n"
#Fetch the owner URL
info "[INFO] FETCHING THE OWNER URL FOR ${INTEGRATION_ADMIN_USRNAME}..."

dbg "curl -sk -X POST \"https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin/integration-keycloak/search\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d @user.json | jq -r '.results[].url'"

URL=$(curl -sk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin/integration-keycloak/search" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @user.json | jq -r .results[].url)
echo -e "\n"
info "[INFO] URL: ${URL}"
sep

info "[INFO] CREATING THE ORG USING JSON"
cat > orgs.json<<EOF
{
  "title": "$org_name",
  "name": "$org_title",
  "owner_url": "$URL"
}
EOF
cat orgs.json

#Create the org

info "[INFO] CREATING THE ORG ${org_name}..."

dbg "ORG= curl -sk -X POST \"https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/orgs\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d @orgs.json"

ORG=$(curl -sk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/orgs" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d @orgs.json)
echo -e "\n"
info "[INFO] ORG IS: $ORG"

sep

#Get ORG URL for Catalog creation
dbg "curl -sk -X GET \"https://${APIC_CLOUD_MANAGER_UI_EP}/api/orgs/${org_name}\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     | jq -r '.url'"

ORG_URL=$(curl -sk -X GET "https://${APIC_CLOUD_MANAGER_UI_EP}/api/orgs/$org_name" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" | jq -r .url)
echo -e "\n"
info "[INFO] ORG URL IS: $ORG_URL"

sep

info "[INFO] CREATING CATALOG USING JSON"

cat > catalog.json<<EOF
{
  "name": "$cat_name",
  "title": "$cat_title",
  "summary": "$cat_description"
}
EOF
cat catalog.json

sep
#Create catalog in the org created above
info "[INFO] CREATE CATALOG ${cat_name} IN THE ${PROVIDER_ORG}..."

dbg "curl -sk -X POST \"${ORG_URL}/catalogs\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d @catalog.json"

CAT_RESPONSE=$(curl -sk -X POST "${ORG_URL}/catalogs" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @catalog.json)
info "[INFO] CATALOG RESPONSE = $CAT_RESPONSE"

sep

APIC_MANAGER_ROUTE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*api-manager" | awk '{print $1}')
info "[INFO]  APIC_MANAGER_ROUTE_NAME : ${APIC_MANAGER_ROUTE_NAME}"

APIC_MANAGER_EP=$(oc get route -n $NAMESPACE $APIC_MANAGER_ROUTE_NAME -o jsonpath="{.spec.host}" )
info "[INFO]  APIC_MANAGER_EP : ${APIC_MANAGER_EP}"



info "[INFO] GETTING CONFIGURED CATALOG USER REGISTRY URL FOR ${PROVIDER_ORG}-CATALOG..."

dbg "curl -kLsS \"https://${APIC_MANAGER_EP}/api/catalogs/${PROVIDER_ORG}/${CATALOG}/configured-catalog-user-registries\" \
     -H \"Accept: application/json\" \
     -H \"Authorization: Bearer ${TOKEN}\""

RES=$(curl -kLsS https://$APIC_MANAGER_EP/api/catalogs/${PROVIDER_ORG}/$CATALOG/configured-catalog-user-registries \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}")

info "[INFO]  RES : ${RES}"

USER_REGISTRY_URL=$(echo "${RES}" | jq -r ".results[0].user_registry_url")
info "[INFO]  USER_REGISTRY_URL : ${USER_REGISTRY_URL}"

sep

info "[INFO] CREATING CONSUMER ORG OWNER: ${CORG_OWNER_USERNAME}..."

dbg "curl -kLsS -X POST \"${USER_REGISTRY_URL}/users\" \
     -H \"Accept: application/json\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d '{\"username\":\"${CORG_OWNER_USERNAME}\",\"email\":\"nigel@acme.org\",\"first_name\":\"Nigel\",\"last_name\":\"McNigelface\",\"password\":\"${CORG_OWNER_PASSWORD}\"}'"

RES=$(curl -kLsS -X POST $USER_REGISTRY_URL/users \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d "{
    \"username\": \"${CORG_OWNER_USERNAME}\",
    \"email\": \"nigel@example.com\",
    \"first_name\": \"Nigel\",
    \"last_name\": \"McNigelface\",
    \"password\": \"${CORG_OWNER_PASSWORD}\"
}")

info "[INFO]  RES : ${RES}"

OWNER_URL=$(echo "${RES}" | jq -r ".url")

info "[INFO] OWNER_URL: $OWNER_URL"

sep

info "[INFO] CREATING CONSUMER ORG: ${CONSUMER_ORG}... "

RES=$(curl -kLsS -X POST https://$APIC_MANAGER_EP/api/catalogs/${PROVIDER_ORG}/$CATALOG/consumer-orgs \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d "{
    \"title\": \"${CONSUMER_ORG}\",
    \"name\": \"${CONSUMER_ORG}\",
    \"owner_url\": \"${OWNER_URL}\"
}")

info "[INFO] RES: $RES"


sep


PLT_WEB_RESOURCE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*portal-web" | awk '{print $1}')
PTL_WEB_EP=$(oc get route -n $NAMESPACE ${PLT_WEB_RESOURCE_NAME} -o jsonpath='{.spec.host}')

info "[INFO] FETCHING CATALOG URL FOR ${CATALOG}..."
RES=`curl -X GET https://${API_EP}/api/catalogs/${PROVIDER_ORG}/${CATALOG} \
                -s -k -H "Content-Type: application/json" -H "Accept: application/json" \
                -H "Authorization: Bearer ${TOKEN}"`

dbg "[DEBUG] $(jq . <<<"${RES}")"
CATALOG_URL=`echo ${RES} | jq -r '.url'`
info "[INFO] CATALOG_URL: ${CATALOG_URL}"

sep

info "[INFO] ADDING PORTAL TO THE CATALOG: ${CATALOG}..."
response=`curl -X PUT ${CATALOG_URL}/settings \
                -s -k -H "Content-Type: application/json" -H "Accept: application/json" \
                -H "Authorization: Bearer ${TOKEN}" \
                -d "{
                      \"portal\": {
                        \"type\": \"drupal\",
                        \"endpoint\": \"https://${PTL_WEB_EP}/${PROVIDER_ORG}/${CATALOG}\",
                        \"portal_service_url\": \"https://${API_EP}/api/orgs/${PROVIDER_ORG}/portal-services/portal-service\"
                      }
                    }"`

dbg "$(jq . <<<"${response}")"

sep

info "[INFO]CREATING APIM CREDENTIALS IN ${NAMESPACE} USING API_KEY..."

APIC_MGMT_URL=$(oc get ManagementCluster ${RELEASE_NAME}-mgmt -o json -n "${NAMESPACE}" | jq -r '.status.endpoints[] | select(.name=="platformApi").uri')
info "[INFO] APIC_MGMT_URL: ${APIC_MGMT_URL}"
echo -e "\n"

APIC_PLATFORM_API_SECRET_NAME=$(oc get ManagementCluster ${RELEASE_NAME}-mgmt -o json -n "${NAMESPACE}" | jq -r '.status.endpoints[] | select(.name=="platformApi").secretName')
info "[INFO] APIC_PLATFORM_API_SECRET_NAME: $APIC_PLATFORM_API_SECRET_NAME"

PLATFORM_API_CERT=$(oc get secret "${APIC_PLATFORM_API_SECRET_NAME}" -o json -n "${NAMESPACE}" | jq -r '.data["ca.crt"]' | base64 --decode)
dbg "PLATFORM_API_CERT: ${PLATFORM_API_CERT}"

CERTIFICATE_NEWLINES_REPLACED=$(echo "${PLATFORM_API_CERT}" | awk '{printf "%s\\n", $0}')
echo -e "\n"
dbg "CERTIFICATE_NEWLINES_REPLACED: $CERTIFICATE_NEWLINES_REPLACED"

APIC_MANAGER_ROUTE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*api-manager" | awk '{print $1}')
dbg "APIC_MANAGER_ROUTE_NAME : ${APIC_MANAGER_ROUTE_NAME}"

APIC_MANAGER_EP=$(oc get route -n $NAMESPACE $APIC_MANAGER_ROUTE_NAME -o jsonpath="{.spec.host}" )
dbg " APIC_MANAGER_EP : ${APIC_MANAGER_EP}"

API_KEY_NAME=$(while [ ${#s} -lt 6 ]; do s+=$(tr -dc 'a-z' </dev/urandom | head -c6); done; echo "$s")
info "[INFO] API_KEY_NAME=${API_KEY_NAME}"

dbg "curl -kLsS -X POST \"https://${APIC_MANAGER_EP}/api/cloud/api-keys\" \
     -H \"Accept: application/json\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d '{\"name\":\"api-${API_KEY_NAME}\",\"title\":\"api-${API_KEY_NAME}\",\"description\":\"api-${API_KEY_NAME}\",\"client_type\":\"toolkit\"}'"

RES=$(curl -kLsS -X POST https://${APIC_MANAGER_EP}/api/cloud/api-keys \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d "{
    \"name\": \"api-${API_KEY_NAME}\",
    \"title\": \"api-${API_KEY_NAME}\",
    \"description\": \"api-${API_KEY_NAME}\",
    \"client_type\": \"toolkit\"
}")
dbg "RES: ${RES}"

API_KEY=$(echo ${RES} | jq -r '.api_key')


if [ -z ${API_KEY} ]; then
  err "[ERROR] FAILED TO GET THE API_KEY: ${API_KEY}"
  exit 1
fi

info "[INFO] API KEY: ${API_KEY}"

sep

info "CREATING THE apim-credentials Secret in ${NAMESPACE} namespace"

cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: apim-credentials
  namespace: "${NAMESPACE}"
type: Opaque
stringData:
  base_url: "${APIC_MGMT_URL}"
  api_key: "${API_KEY}"
  grant_type: api_key
  trusted_cert: "${CERTIFICATE_NEWLINES_REPLACED}"
EOF


sep

info "CONFIGURING API_KEY EXPIRY AND USAGE..."

dbg "curl -kLsS -X PUT \"https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/settings\" \
     -H \"Accept: application/json\" \
     -H \"Authorization: Bearer ${TOKEN}\" \
     -H \"Content-Type: application/json\" \
     -d '{\"api_key_expires_in\":\"110880000\",\"api_key_multiple_uses\":\"true\"}'"

RES=$(curl -kLsS -X PUT "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/settings" \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d "{\"api_key_expires_in\": \"110880000\", \"api_key_multiple_uses\": \"true\"}")

dbg "RES: ${RES}"