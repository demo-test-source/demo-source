# setup-apic-script.sh

> ⚠️ **Not supported:** This script is provided “as is,” with **no support**. 

> ⚠️ **Only for Demo purposes:** This script is only for demo purposes, NOT to be used in production

This bashscript helps user setup IBM API Connect (APIC) resources needed to complete the simple-api demo. 


---

## Table of contents

* [Location](#location)
* [What it does](#what-it-does)
* [Prerequisites](#prerequisites)
* [Usage](#usage)
* [Arguments](#arguments)
* [Environment & constants](#environment--constants)
* [Troubleshooting](#troubleshooting)
* [Cleanup](#cleanup)
* [License](#license)

---

## Location

```
api-demo/setup-apic-script.sh
```

(Branch: `apic-script`) ([GitHub][1])

---

## What it does

At a high level, the script:

The script creates the following:
- An organization called `main-demo` in APIC Cloud Manager.
- Inside the organization, a catalog called `main-demo-catalog`
- A consumer org owner called `main-demo-corg-admin`
- A consumer org, called `main-demo-corp`
- A portal for the catalog, called `main-demo-catalog`
- A secret called `apim-credentials` in the namespace where APIC is installed.

> The exact sequence (curl calls, JSON payloads, etc.) is visible in the script comments and functions.

---

## Prerequisites

* **OpenShift CLI:** `oc`
* **Utilities:** `jq`, `curl`, `base64`, `awk`, `tr`  *(optional: `tput` for nicer separators)*
* **Access:** Admin OCP and APIC permission.
* **Installed components:** 

    -   IBM Cloud Pak® for Integration 16.1.0 or later is installed, including deployment of a Platform UI instance. For more information, see Installing.

    -   Within the Cloud Pak for Integration installation, deploy the following operators with their corresponding instances:

        -   IBM App Connect operator.
        -   IBM API Connect operator. Deploy an API Connect cluster instance.



---

## Usage

```bash
# from repo root
chmod +x api-demo/setup-apic-script.sh
./api-demo/setup-apic-script.sh -n <apic-namespace> -r <apic-release-name>

# enable step-by-step debug pauses
./api-demo/setup-apic-script.sh -n apic -r apic-rel -d
```

If your shell isn’t Bash:

```bash
bash ./api-demo/setup-apic-script.sh -n apic -r apic-rel
```

([GitHub - Script][1])

---

## Arguments

```
-n   OpenShift namespace (project) where APIC is installed   [required]
-r   APIC release name (used to locate the APIC resources) [required]
-d   Enable debug output and interactive pauses               [optional]
-h   Show help                                                [optional]
```

([GitHub - Script][1])

---

## Environment & constants

The script includes sensible demo defaults (edit the script if you need different values):

* `PROVIDER_ORG="main-demo"`
* `CATALOG="main-demo-catalog"`
* `CONSUMER_ORG="${PROVIDER_ORG}-corp"`
* `CORG_OWNER_USERNAME="${PROVIDER_ORG}-corg-admin"`
* `CORG_OWNER_PASSWORD="engageibmAPI1"`
* `APIC_CLIENT_ID="599b7aef-8841-4ee2-88a0-84d49c4d6ff2"`
* `APIC_CLIENT_SECRET="0ea28423-e73b-47d4-b40e-ddb45c48bb0c"`

Keycloak admin credentials are read from the `cs-keycloak-initial-admin` Secret in the detected Keycloak namespace. ([GitHub - Script][1])

---

## Troubleshooting

* **“Missing dependency: …”**
  Install the named tool (e.g., `jq`, `oc`).

* **“Could not find platform-api route”**
  Ensure `-n` and `-r` are correct, APIC is installed, and the `platform-api` Route exists in your namespace. The script matches on `${RELEASE_NAME:0:10}.*platform-api`. ([GitHub][1])

* **Keycloak route not found / admin secret missing**
  The script looks for the `keycloak` Route first in `ibm-common-services`, then in your APIC namespace, and reads the `cs-keycloak-initial-admin` Secret. Verify keycloak instance is installed and working. ([GitHub - Script][1])

* **401 during token request**
  Check that Direct Access Grants are enabled for the APIC client and that username/passwords are correct. Re-run with `-d` to see the constructed curl calls. ([GitHub - Script][1])

* **Hangs or unclear state**
  Re-run with `-d` (debug) to step through each phase.

To capture logs:

```bash
./api-demo/setup-apic-script.sh -n apic -r apic-rel | tee setup-apic-script.log
```

---

## Cleanup

There’s no separate destroy script. If you enabled/created resources, revert by:

* Deleting any demo orgs/users/catalogs you created via the APIC UI/CLI or API.

---
=

---

### Quick reference

* Path: `api-demo/setup-apic-script.sh`
* Required: `-n <namespace> -r <release-name>`
* Depends on: `oc`, `jq`, `curl`, `base64`, `awk`, `tr`
* Support: **None** (NOT FOR PRODUCTION USE)

[1]: https://github.com/demo-test-source/demo-source/raw/apic-script/api-demo/setup-apic-script.sh "raw.githubusercontent.com"
