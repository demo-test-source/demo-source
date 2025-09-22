
#!/bin/bash
#******************************************************************************
# Licensed Materials - Property of IBM
# (c) Copyright IBM Corporation 2025. All Rights Reserved.
#
# Note to U.S. Government Users Restricted Rights:
# Use, duplication or disclosure restricted by GSA ADP Schedule
# Contract with IBM Corp.
#******************************************************************************

function usage() {
  echo "Usage: $0 -n <NAMESPACE> -r <RELEASE_NAME> -d <DEBUG>"
  divider
  exit 1
}

function spacing() {
  echo -e "\n"
  printf '%*s\n' "$(tput cols)" '' | tr ' ' '-'
  echo -e "\n"
}

DEBUG=false

while getopts "n:r:d:" opt; do
  case ${opt} in
  n)
    NAMESPACE="$OPTARG"
    ;;
  r)
    RELEASE_NAME="$OPTARG"
    ;;
  d)
    DEBUG="$OPTARG"
    ;;
  \?)
    usage
    ;;
  esac
done



API_RESOURCE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*platform-api" | awk '{print $1}')
echo "APIC INSTANCE NAME: ${API_RESOURCE_NAME}"
API_EP=$(oc get route -n $NAMESPACE ${API_RESOURCE_NAME} -o jsonpath='{.spec.host}')
echo "APIC ENDPOINT: ${API_EP}"
PROVIDER_ORG="main-demo"
CATALOG="main-demo-catalog"
CONSUMER_ORG=${PROVIDER_ORG}-corp
CORG_OWNER_USERNAME="${PROVIDER_ORG}-corg-admin"
CORG_OWNER_PASSWORD=engageibmAPI1

spacing



function authenticate() {
  realm=${1}
  username=${2}
  password=${3}

  echo "Authenticate as the ${username} user"

  [ "$DEBUG" = true ] &&  echo " curl -X POST https://${API_EP}/api/token -s -k -H \"Content-Type: application/json\" -H \"Accept: application/json\" -d '{ \"realm\": \"${realm}\", \"username\": \"${username}\", \"password\": \"${password}\", \"client_id\": \"599b7aef-8841-4ee2-88a0-84d49c4d6ff2\", \"client_secret\": \"0ea28423-e73b-47d4-b40e-ddb45c48bb0c\", \"grant_type\": \"password\" }'"

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
  RESULT=`echo ${response} | jq -r '.access_token'`
  return 0
}


function CONFIGURE_KEYCLOAK_CONFIG(){

  APIC_KEYCLOAK_CLIENT=$1

  ####################################################################################
  # IN THIS CODE BLOCK WE ARE ENABLING THE GRANT ACCESS FOR THE APIC KEYCLOAK CLIENT #
  ####################################################################################

  echo "FETCHING KEYCLOAK ROUTE..."
  KEYCLOAK_ROUTE_NAMESPACE=$(oc get route keycloak -n ibm-common-services -o jsonpath='{.metadata.namespace}')
  if [ -z "$KEYCLOAK_ROUTE_NAMESPACE" ]; then
    KEYCLOAK_ROUTE_NAMESPACE=$(oc get route keycloak -n ${NAMESPACE} -o jsonpath='{.metadata.namespace}')
  fi

  [ "$DEBUG" = true ] && echo "KEYCLOAK_ROUTE_NAMESPACE: ${KEYCLOAK_ROUTE_NAMESPACE}" && read -p "Press Enter to continue"

  KEYCLOAK_ROUTE=$(oc get route keycloak -n ${KEYCLOAK_ROUTE_NAMESPACE} -o jsonpath='{.spec.host}' )
  [ "$DEBUG" = true ] && echo " KEYCLOAK_ROUTE: ${KEYCLOAK_ROUTE}" && read -p "Press Enter to continue"

  echo "FETCHING KEYCLOAK ADMIN USR/PWD..."
  KEYCLOAK_ADMIN_SECRET_NAMESPACE=$(oc get secret cs-keycloak-initial-admin -n ${KEYCLOAK_ROUTE_NAMESPACE} -o jsonpath='{.metadata.namespace}')
  if [ -z "$KEYCLOAK_ADMIN_SECRET_NAMESPACE" ]; then
    echo "ERROR: CANNOT FIND THE cs-keycloak-initial-admin in ${KEYCLOAK_ROUTE_NAMESPACE} namespace"
    exit 1
  fi

  KEYCLOAK_ADMIN_USRNAME=$(oc get secret cs-keycloak-initial-admin -n ${KEYCLOAK_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')
  KEYCLOAK_ADMIN_PWD=$(oc get secret cs-keycloak-initial-admin -n ${KEYCLOAK_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')

  [ "$DEBUG" = true ] && echo " KEYCLOAK_ADMIN_SECRET_NAMESPACE: ${KEYCLOAK_ADMIN_SECRET_NAMESPACE}" && read -p "Press Enter to continue"


  echo "FETCH KEYCLOAK TOKEN..."
  KC_TOKEN=$(curl -X POST "https://${KEYCLOAK_ROUTE}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${KEYCLOAK_ADMIN_USRNAME}" -d "password=${KEYCLOAK_ADMIN_PWD}" -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

  [ "$DEBUG" = true ] && echo "KEYCLOAK TOKEN: ${KC_TOKEN}"

  KC_CLIENT=$(curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients?clientId=${APIC_KEYCLOAK_CLIENT}" \
  -H "Authorization: Bearer $KC_TOKEN")

  [ "$DEBUG" = true ] && echo "KEYCLOAK CLIENT: curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients?clientId=${APIC_KEYCLOAK_CLIENT}" \
  -H "Authorization: Bearer $KC_TOKEN""
  [ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
  echo "KEYCLOAK CLIENT: $KC_CLIENT"

  echo "GET UUID: "$KC_CLIENT" | jq -r '.[].id'"
  UUID=$(echo "$KC_CLIENT" | jq -r '.[].id')
  echo $UUID

  GRANT=$(echo "$KC_CLIENT" | jq -r '.[].directAccessGrantsEnabled')
  echo "CURRENT GRANT STATUS: $GRANT"
  [ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"

  if [ $GRANT == "true" ] ; then
    echo "Grant already enabled"
  else
    echo "ENABLING GRANT..."
    [ "$DEBUG" = true ] && echo "curl -X PUT "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/$UUID" -H "Content-Type: application/json" -H "Authorization: Bearer $KC_TOKEN" -d '{"directAccessGrantsEnabled": true}'"
    curl -X PUT "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/$UUID" \
    -H "Content-Type: application/json" -H "Authorization: Bearer $KC_TOKEN" -d '{"directAccessGrantsEnabled": true}'
    sleep 30
    KC_RESPONSE=$(curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients?clientId=${APIC_KEYCLOAK_CLIENT}" \
  -H "Authorization: Bearer $KC_TOKEN")
    GRANT=$(echo "$KC_RESPONSE" | jq -r '.[].directAccessGrantsEnabled')
    echo "GRANT STATUS: ${GRANT}"
  fi

  ####################################################################################
  # IN THE FOLLOWING CODE BLOCK WE ARE CONFIGURING GROUP MAPPER FOR THIS CLIENT      #
  ####################################################################################
  

  ####################################################################################
  # CREATING JSON FOR THE MAPPER                                                     #
  ####################################################################################
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

  [ "$DEBUG" = true ] && echo -e "\n"

  [ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"

  [ "$DEBUG" = true ] && echo "CURL COMMAND FOR SETTING UP: curl -X POST https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/$UUID/protocol-mappers/models -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" -d @aud.json"
  curl -X POST https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/clients/$UUID/protocol-mappers/models \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d @aud.json
  [ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"

  spacing

  # FETCH USERID FOR INTEGRATION-ADMIN USER
  [ "$DEBUG" = true ] && echo "curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users?username=integration-admin" -H "Authorization: Bearer $KC_TOKEN""
  INTEGRATION_ADMIN_ID=$(curl -X GET "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users?username=integration-admin" \
    -H "Authorization: Bearer $KC_TOKEN" | jq -r '.[0].id')
  [ "$DEBUG" = true ] && echo "INTEGRATION_ADMIN_ID: $INTEGRATION_ADMIN_ID"
 
  # ADD EMAIL ID FOR THE INTEGRATION_ADMIN USER
  [ "$DEBUG" = true ] && echo "curl -X PUT "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users/${INTEGRATION_ADMIN_ID}" -H "Authorization: Bearer $KC_TOKEN" -H "Content-Type: application/json" -d '{"email":"theprocrastinator@latermail.com","emailVerified":true}'"
  RES=$(curl -X PUT "https://${KEYCLOAK_ROUTE}/admin/realms/cloudpak/users/${INTEGRATION_ADMIN_ID}" \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "email": "theprocrastinator@example.com",
        "emailVerified": true
      }')
  [ "$DEBUG" = true ] && echo $RES


}

spacing

echo "LOGGING IN ${API_EP} ..."

admin_idp=admin/default-idp-1
admin_password=$(oc get secret -n $NAMESPACE ${RELEASE_NAME}-mgmt-admin-pass -o json | jq -r .data.password | base64 --decode)

[ "$DEBUG" = true ] && echo "REALM: ${admin_idp} USERNAME:admin PASSWORD:${admin_password}"
spacing

authenticate "${admin_idp}" "admin" "${admin_password}"
admin_token="${RESULT}"
[ "$DEBUG" = true ] && echo " ADMIN TOKEN: ${admin_token}"
spacing

## Get Keycloak URL for Cloudpak user registry
echo "GETTING CLOUDPAK USER REGISTRY..."
[ "$DEBUG" = true ] && echo " curl -X GET https://${API_EP}/api/orgs/admin/user-registries \
               -s -k -H "Accept: application/json" \
               -H "Authorization: Bearer ${admin_token}""

response=`curl -X GET https://${API_EP}/api/orgs/admin/user-registries \
               -s -k -H "Accept: application/json" \
               -H "Authorization: Bearer ${admin_token}"`
IK_TOKEN_ENDPOINT=$(echo "${response}" | jq -r '.results[] | select(.name == "integration-keycloak") .configuration.token_endpoint.endpoint')
spacing
echo "$IK_TOKEN_ENDPOINT"
[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"

APIC_CLOUD_MANAGER_RESOURCE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*admin" | awk '{print $1}')
echo "APIC_CLOUD_MANAGER_RESOURCE_NAME: $APIC_CLOUD_MANAGER_RESOURCE_NAME"
APIC_CLOUD_MANAGER_UI_EP=$(oc get route -n $NAMESPACE ${APIC_CLOUD_MANAGER_RESOURCE_NAME} -o jsonpath='{.spec.host}')
echo $APIC_CLOUD_MANAGER_UI_EP
spacing

[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"

echo "FINDING THE KEYCLOAK CLIENT FOR APIC RELEASE: ${RELEASE_NAME}...."
KEYCLOAK_CLIENT_ID=$(oc get secret keycloak-client-secret-${RELEASE_NAME}-keycloak-client -n ${NAMESPACE} -o jsonpath='{.data.CLIENT_ID}' | base64 --decode | tr -d '\r\n%')
KEYCLOAK_CLIENT_SECRET=$(oc get secret keycloak-client-secret-${RELEASE_NAME}-keycloak-client -n ${NAMESPACE} -o jsonpath='{.data.CLIENT_SECRET}' | base64 --decode | tr -d '\r\n%')
[ "$DEBUG" = true ] && echo "KEYCLOAK CLIENT ID: ${KEYCLOAK_CLIENT_ID}"
[ "$DEBUG" = true ] && echo "KEYCLOAK CLIENT ID: ${KEYCLOAK_CLIENT_SECRET}"
[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
spacing

CONFIGURE_KEYCLOAK_CONFIG $KEYCLOAK_CLIENT_ID

echo "FETCHING THE INTEGRATION_ADMIN LOGIN CREDENTIALS..."
INTEGRATION_ADMIN_SECRET_NAMESPACE=$(oc get secret integration-admin-initial-temporary-credentials -n ibm-common-services -o jsonpath='{.metadata.namespace}')

if [ -z "$INTEGRATION_ADMIN_SECRET_NAMESPACE" ]; then
    INTEGRATION_ADMIN_SECRET_NAMESPACE=$(oc get secret integration-admin-initial-temporary-credentials -n ${KEYCLOAK_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.metadata.namespace}')
fi

[ "$DEBUG" = true ] && echo "INTEGRATION_ADMIN_SECRET_NAMESPACE: ${INTEGRATION_ADMIN_SECRET_NAMESPACE}" && read -p "Press Enter to continue"

INTEGRATION_ADMIN_USRNAME=$(oc get secret integration-admin-initial-temporary-credentials -n ${INTEGRATION_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.data.username}' | base64 --decode | tr -d '\r\n%')
INTEGRATION_ADMIN_PWD=$(oc get secret integration-admin-initial-temporary-credentials -n ${INTEGRATION_ADMIN_SECRET_NAMESPACE} -o jsonpath='{.data.password}' | base64 --decode | tr -d '\r\n%')

[ "$DEBUG" = true ] && echo "INTEGRATION_ADMIN_USRNAME: ${INTEGRATION_ADMIN_USRNAME}"
[ "$DEBUG" = true ] && echo "INTEGRATION_ADMIN_PWD: ${INTEGRATION_ADMIN_PWD}"
[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
spacing


org_name="main-demo" #Org name that needs to be created
org_title="main-demo" #Org title 

cat_name="main-demo-catalog"  #catalog name that needs to be created
cat_title="main-demo-catalog"  #catalog title
cat_description="Test Catalog"  #catalog description



#Get the access token
echo "GET ACCESS TOKEN FOR INTEGRATION KEYCLOAK USER FOR ${$KEYCLOAK_CLIENT_ID}..."
echo "curl -sk -X POST "$IK_TOKEN_ENDPOINT" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=password" -d "client_id=$KEYCLOAK_CLIENT_ID" -d "client_secret=$KEYCLOAK_CLIENT_SECRET" -d "username=$INTEGRATION_ADMIN_USRNAME" -d "password=$INTEGRATION_ADMIN_PWD" | jq -r '.access_token'"
TOKEN=$(curl -sk -X POST "$IK_TOKEN_ENDPOINT" -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=password" -d "client_id=$KEYCLOAK_CLIENT_ID" -d "client_secret=$KEYCLOAK_CLIENT_SECRET" -d "username=$INTEGRATION_ADMIN_USRNAME" -d "password=$INTEGRATION_ADMIN_PWD" | jq -r '.access_token')
echo -e "\n"
echo "TOKEN: ${TOKEN}"
"$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
spacing

#create the user JSON for owner URL
cat > user.json<<EOF
{
  "username": "$INTEGRATION_ADMIN_USRNAME",
  "remote": false
}
EOF
cat user.json
echo -e "\n"
#Fetch the owner URL
echo "FETCHING THE OWNER URL FOR ${INTEGRATION_ADMIN_USRNAME}..."

[ "$DEBUG" = true ] && echo "curl -sk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin/integration-keycloak/search" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @user.json | jq -r .results[].url"
URL=$(curl -sk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/user-registries/admin/integration-keycloak/search" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @user.json | jq -r .results[].url)
echo -e "\n"
echo "URL: ${URL}"
[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
spacing

#Create the org json
cat > orgs.json<<EOF
{
  "title": "$org_name",
  "name": "$org_title",
  "owner_url": "$URL"
}
EOF
cat orgs.json

#Create the org

echo "CREATING THE ORG ${org_name}..."
[ "$DEBUG" = true ] && echo "ORG= curl -sk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/orgs" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @orgs.json"
ORG=$(curl -sk -X POST "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/orgs" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d @orgs.json)
echo -e "\n"
echo "ORG IS: $ORG"
[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
spacing

#Get ORG URL for Catalog creation
[ "$DEBUG" = true ] && echo "curl -sk -X GET "https://${APIC_CLOUD_MANAGER_UI_EP}/api/orgs/$org_name" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" | jq -r .url"
ORG_URL=$(curl -sk -X GET "https://${APIC_CLOUD_MANAGER_UI_EP}/api/orgs/$org_name" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" | jq -r .url)
echo -e "\n"
echo "ORG URL IS: $ORG_URL"
[ "$DEBUG" = true ] && read -p "PRESS ENTER TO CONTINUE"
spacing

#Create catalog json
cat > catalog.json<<EOF
{
  "name": "$cat_name",
  "title": "$cat_title",
  "summary": "$cat_description"
}
EOF
cat catalog.json

spacing
#Create catalog in the org created above
echo "CREATE CATALOG ${$cat_name} in the ${PROVIDER_ORG}..."
[ "$DEBUG" = true ] && echo "curl -sk -X POST "${ORG_URL}/catalogs" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @catalog.json"
CAT_RESPONSE=$(curl -sk -X POST "${ORG_URL}/catalogs" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @catalog.json)
echo $CAT_RESPONSE

spacing

APIC_MANAGER_ROUTE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*api-manager" | awk '{print $1}')
[ "$DEBUG" = true ] && echo " APIC_MANAGER_ROUTE_NAME : ${APIC_MANAGER_ROUTE_NAME}"
APIC_MANAGER_EP=$(oc get route -n $NAMESPACE $APIC_MANAGER_ROUTE_NAME -o jsonpath="{.spec.host}" )
[ "$DEBUG" = true ] && echo " APIC_MANAGER_EP : ${APIC_MANAGER_EP}"



echo "GETTING CONFIGURED CATALOG USER REGISTRY URL FOR ${PROVIDER_ORG}-CATALOG..."
[ "$DEBUG" = true ] && echo "curl -kLsS https://$APIC_MANAGER_EP/api/catalogs/${PROVIDER_ORG}/$CATALOG/configured-catalog-user-registries -H "accept: application/json" -H "authorization: Bearer ${TOKEN}""
RES=$(curl -kLsS https://$APIC_MANAGER_EP/api/catalogs/${PROVIDER_ORG}/$CATALOG/configured-catalog-user-registries \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}")
[ "$DEBUG" = true ] && echo " RES : ${RES}"

USER_REGISTRY_URL=$(echo "${RES}" | jq -r ".results[0].user_registry_url")
[ "$DEBUG" = true ] && echo " USER_REGISTRY_URL : ${USER_REGISTRY_URL}"

spacing

echo "CREATING CONSUMER ORG OWNER: ${CORG_OWNER_USERNAME}..."
[ "$DEBUG" = true ] && echo "curl -kLsS -X POST $USER_REGISTRY_URL/users -H "accept: application/json" -H "authorization: Bearer ${TOKEN}" -H "content-type: application/json" -d "{\"username\": \"${CORG_OWNER_USERNAME}\",\"email\": \"nigel@acme.org\",\"first_name\": \"Nigel\",\"last_name\": \"McNigelface\",\"password\": \"${CORG_OWNER_PASSWORD}\"}""
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
[ "$DEBUG" = true ] && echo " RES : ${RES}"
OWNER_URL=$(echo "${RES}" | jq -r ".url")
[ "$DEBUG" = true ] && echo "OWNER_URL: $OWNER_URL"

spacing

echo "CREATING CONSUMER ORG: ${CONSUMER_ORG}... "
RES=$(curl -kLsS -X POST https://$APIC_MANAGER_EP/api/catalogs/${PROVIDER_ORG}/$CATALOG/consumer-orgs \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d "{
    \"title\": \"${CONSUMER_ORG}\",
    \"name\": \"${CONSUMER_ORG}\",
    \"owner_url\": \"${OWNER_URL}\"
}")
[ "$DEBUG" = true ] && echo "RES: $RES"


spacing

PLT_WEB_RESOURCE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*portal-web" | awk '{print $1}')
PTL_WEB_EP=$(oc get route -n $NAMESPACE ${PLT_WEB_RESOURCE_NAME} -o jsonpath='{.spec.host}')

echo "FETCHING CATALOG URL FOR ${CATALOG}..."
RES=`curl -X GET https://${API_EP}/api/catalogs/${PROVIDER_ORG}/${CATALOG} \
                -s -k -H "Content-Type: application/json" -H "Accept: application/json" \
                -H "Authorization: Bearer ${TOKEN}"`
[ "$DEBUG" = true ] && echo "[DEBUG] $(echo ${RES} | jq .)"
CATALOG_URL=`echo ${RES} | jq -r '.url'`

spacing

echo "ADDING PORTAL TO THE CATALOG: ${CATALOG}..."
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
[ "$DEBUG" = true ] && echo "[DEBUG] $(echo ${response} | jq .)"

spacing

echo "CREATING APIM CREDENTIALS IN ${NAMESPACE} USING API_KEY..."
APIC_MGMT_URL=$(oc get ManagementCluster ${RELEASE_NAME}-mgmt -o json -n "${NAMESPACE}" | jq -r '.status.endpoints[] | select(.name=="platformApi").uri')
echo "APIC_MGMT_URL: ${APIC_MGMT_URL}"
echo -e "\n"
APIC_PLATFORM_API_SECRET_NAME=$(oc get ManagementCluster ${RELEASE_NAME}-mgmt -o json -n "${NAMESPACE}" | jq -r '.status.endpoints[] | select(.name=="platformApi").secretName')
echo "APIC_PLATFORM_API_SECRET_NAME: $APIC_PLATFORM_API_SECRET_NAME"
PLATFORM_API_CERT=$(oc get secret "${APIC_PLATFORM_API_SECRET_NAME}" -o json -n "${NAMESPACE}" | jq -r '.data["ca.crt"]' | base64 --decode)
CERTIFICATE_NEWLINES_REPLACED=$(echo "${PLATFORM_API_CERT}" | awk '{printf "%s\\n", $0}')
[ "$DEBUG" = true ] && echo -e "\n"
[ "$DEBUG" = true ] && echo "$CERTIFICATE_NEWLINES_REPLACED"
APIC_MANAGER_ROUTE_NAME=$(oc get routes -n $NAMESPACE | grep -m1 "${RELEASE_NAME:0:10}.*api-manager" | awk '{print $1}')
[ "$DEBUG" = true ] && echo " APIC_MANAGER_ROUTE_NAME : ${APIC_MANAGER_ROUTE_NAME}"
APIC_MANAGER_EP=$(oc get route -n $NAMESPACE $APIC_MANAGER_ROUTE_NAME -o jsonpath="{.spec.host}" )
[ "$DEBUG" = true ] && echo " APIC_MANAGER_EP : ${APIC_MANAGER_EP}"
API_KEY_NAME=$(while [ ${#s} -lt 6 ]; do s+=$(tr -dc 'a-z' </dev/urandom | head -c6); done; echo "$s")
[ "$DEBUG" = true ] && echo "curl -kLsS -X POST "https://${APIC_MANAGER_EP}/api/cloud/api-keys" -H "accept: application/json" -H "authorization: Bearer ${TOKEN}" -H "content-type: application/json" -d "{\"name\": \"api-${API_KEY_NAME}\", \"title\": \"api-${API_KEY_NAME}\", \"description\": \"api-${API_KEY_NAME}\", \"client_type\": \"toolkit\"}""
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
[ "$DEBUG" = true ] && echo "RES: ${RES}"

API_KEY=$(echo ${RES} | jq -r '.api_key')
echo "API KEY: ${API_KEY}"

if [ -z ${API_KEY} ]; then
  exit 1
fi

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


spacing

echo "CONFIGURING API_KEY EXPIRY AND USAGE..."
[ "$DEBUG" = true ] && echo "curl -kLsS -X PUT "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/settings" -H "accept: application/json" -H "authorization: Bearer ${TOKEN}" -H "content-type: application/json" -d "{\"api_key_expires_in\": \"110880000\", \"api_key_multiple_uses\": \"true\"}""
RES=$(curl -kLsS -X PUT "https://${APIC_CLOUD_MANAGER_UI_EP}/api/cloud/settings" \
  -H "accept: application/json" \
  -H "authorization: Bearer ${TOKEN}" \
  -H "content-type: application/json" \
  -d "{\"api_key_expires_in\": \"110880000\", \"api_key_multiple_uses\": \"true\"}")

[ "$DEBUG" = true ] && echo "RES: ${RES}"