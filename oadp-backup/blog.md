
# Using GitOps and OADP to Schedule Backups for Cloud Pak for Integration on RHOCP

## Introduction

In a previous blog, we showed how to **restore Cloud Pak for Integration (CP4I) workloads** using GitOps and the OpenShift APIs for Data Protection (OADP). That workflow used a Git-managed `Restore` CR to drive repeatable restores from an existing Velero backup. ([community.ibm.com][1])

This follow-on post explains how to use **OADP + GitOps** to **take *scheduled backups*** of a CP4I workload running in a specific OpenShift project on **Red Hat OpenShift Container Platform (RHOCP)**. Workload and environment definitions are assumed to exist already — particularly **OADP installed and configured** (including the `DataProtectionApplication` pointing to your object store) — so this post focuses on **backup scheduling and GitOps lifecycle management**.

---

## Why GitOps for Backups?

Manual backups via CLI or ad-hoc scripts create operational friction and risk:

* They are hard to audit.
* They can drift from documented intent.
* They are hard to repeat across environments.

Using **Git as source of truth** with a GitOps controller (such as Argo CD) ensures:

* Backups are **declarative**.
* Changes are **reviewable and versioned**.
* Backups are **auto-applied and self-healed**.

This mirrors the restore-via-Git pattern described in the earlier blog. ([community.ibm.com][1])

---

## Prerequisites

Before proceeding, you should have the following in place:

* OADP Operator installed in the `openshift-adp` namespace with a **ready** `DataProtectionApplication` CR configured against your object store (S3, ODF, etc.).
* Your CP4I instance installed in a **single namespace** (e.g., `cp4i-prod`).
* A Git repository where you will declare GitOps manifests.
* An OpenShift GitOps (Argo CD) installation to apply and sync those manifests.

---

## Repository Layout

A clean shell for your backup definitions might look like:

```text
gitops-repo/
└── oadp/
    └── backups/
        └── cp4i-prod/ <Namespacefolder>
            ├── schedule_backup-cp4i-prod.yaml
            ├── README.md
```

This isolates backup schedule definitions per workload or namespace (project).


---

## Defining a Scheduled Backup (Schedule CR)

OADP uses Velero’s `Schedule` CR for recurring backups. Here’s a recommended baseline:

```yaml
apiVersion: velero.io/v1
kind: Schedule
metadata:
  name: cp4i-prod-daily
  namespace: openshift-adp
spec:
  # Cron schedule: daily at 02:00 UTC
  schedule: "0 2 * * *"
  # Only include your CP4I project
  template:
    includedNamespaces:
      - nav-ns
    snapshotVolumes: true
    # Enable snapshotting of PVCs
    defaultVolumesToFsBackup: false
    ttl: 168h   # expire backups after 7 days
```

**Key fields explained:**

* `schedule`: Cron syntax for periodic backups.
* `includedNamespaces`: Limits scope to CP4I namespace.
* `snapshotVolumes`: Captures volume snapshots if CSI supports it.
* `ttl`: Time-to-live so old backups are automatically cleaned up.

Commit this YAML to your Git repository under the appropriate path.

---

## Applying with GitOps (Argo CD)

Create an Argo CD Application (or equivalent) pointing to the `cp4i-prod` backup directory:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: cp4i-backups
  namespace: openshift-gitops
spec:
  source:
    repoURL: https://github.com/demo-test-source/demo-source.git
    targetRevision: oadp-backup
    path: oadp-backup/gitops-repo/oadp/backups/cp4i-prod
  destination:
    server: https://kubernetes.default.svc
    namespace: openshift-adp
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

With `automated.syncPolicy`, Argo CD ensures that:

* The scheduled backup CR stays applied.
* Any out-of-sync drift is corrected automatically.

---

## Verification and Monitoring

After syncing the schedule with GitOps:

1. **Confirm the Schedule exists:**

   ```bash
   oc get schedules -n openshift-adp
   ```
2. **Monitor upcoming backups:**

   ```bash
   oc describe schedule cp4i-prod-daily -n openshift-adp
   ```
3. **List historical backups:**

   ```bash
   oc get backups -n openshift-adp
   ```

You should see backups generated on cadence, with objects and PVC snapshots stored in the configured object store.

---

## Best Practices

**Retention and TTL:** Adjust `ttl` for your operational window (e.g., 7d vs 30d vs 90d) based on RTO/RPO requirements.

**Labeling:** Ensure CP4I resources have proper backup labels if needed, allowing more granular control. ([IBM][2])

**Scope:** If you need cluster-wide backups, adjust `includedNamespaces` or include additional schedules per namespace.

**Testing and Restore:** Regularly validate restores to ensure backups are usable, using the restore patterns from your earlier blog. ([community.ibm.com][1])

---

## Summary

By defining backup schedules as declarative manifests and managing them with GitOps, you gain:

* **Repeatability**
* **Auditability**
* **Reduced operational drift**
* **Self-healing sync** via a GitOps controller

This approach fits naturally alongside your Git-driven restore workflows and strengthens your overall CP4I data protection posture in RHOCP.

---

If you’d like, I can generate **example backup manifest templates**, **Argo CD Application manifests** for multiple environments, or a **comparison of retention policies** based on S3 vs ODF backends.

[1]: https://community.ibm.com/community/user/blogs/hasan-rizvi/2025/10/21/using-gitops-oadp-for-restoring-cloudpak-for-integ "
	Restoring Cloud Pak for Integration workload using GitOps & OADP
"
[2]: https://www.ibm.com/docs/en/cloud-paks/cp-integration/16.1.1?topic=administering-backing-up-restoring-cloud-pak-integration&utm_source=chatgpt.com "Backing up and restoring IBM Cloud Pak for Integration"



- No talk about which operator to install, oadp and gitops
- For setting oadp we can point to the docs