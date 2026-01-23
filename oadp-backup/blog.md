
# Using GitOps and OpenShift APIs for Data Protection (OADP) to Schedule Backups for Cloud Pak for Integration on RHOCP

## Introduction

In a previous blog, we showed how to **restore Cloud Pak for Integration (CP4I) workloads** using Red Hat Openshift GitOps and the OADP Operators are already installed. That workflow used a Git-managed `Restore` CR to drive repeatable restores from an existing Velero backup. ([community.ibm.com][1])

This follow-on post explains how to use **OADP + GitOps** to **take *scheduled backups*** of a CP4I workload running in a specific OpenShift project on **Red Hat OpenShift Container Platform (RHOCP)**. 

The assumptions are that the workload (in this case CP4I workload) and environment definitions are assumed to exist already:
- Openshift Cluster with cluster-admin access
- Workload installed in a single namespace. In this case it is Cloud Pak for Integration (CP4I) workload installed in namespace called `oadp-ns`, in ‘single namespace` mode.
- OpenShift API for Data Protection (OADP) Operator installed in the openshift-adp namespace. (https://docs.redhat.com/en/documentation/openshift_container_platform/4.14/html/backup_and_restore/oadp-application-backup-and-restore#about-installing-oadp)

- RedHat Openshift Gitops operator is installed, this will install ArgoCD on the cluster
- DataProtectionApplication (DPA) configured to back up to an S3 bucket (endpoint, bucket, and credentials set). (Instruction)[https://www.ibm.com/docs/en/cloud-paks/cp-integration/16.1.0?topic=administering-backing-up-restoring-cloud-pak-integration#configuring-oadp__title__1] on setting up and configuring this step


Instructions for setting up the CP4I workload can be found in the Tutorial: Using the assembly canvas to create messaging workflows with Kubernetes resources in IBM docs.
 — particularly **Openshift  installed and configured** (including the `DataProtectionApplication` pointing to your object store) — so this post focuses on **backup scheduling and GitOps lifecycle management**.

---

## Why GitOps for Backups?

Manual backups performed through the CLI or ad-hoc scripts often introduce unnecessary operational friction and risk. Over time, these approaches become difficult to audit, as there is no reliable record of when or why changes were made. They are also prone to configuration drift, where the actual backup behaviour no longer matches the documented or intended state. Additionally, reproducing the same backup configuration consistently across multiple environments can be challenging, leading to inconsistency and potential gaps in protection.

By contrast, using Git as the single source of truth in combination with a GitOps controller such as Argo CD brings structure and reliability to the backup process. Backup configurations are defined declaratively, ensuring that the desired state is explicit and repeatable. All changes are versioned and reviewable through standard Git workflows, providing clear auditability. Once committed, these configurations are automatically applied and continuously reconciled, allowing the system to self-heal if any drift occurs. This approach aligns closely with the restore-via-Git pattern described in the earlier blog on the IBM Community site.

---

Argo CD’s job is not to “run” the backup. OADP/Velero runs the backup using the 'Schedule' resource. Argo CD’s job is to make sure the backup schedule definition exists in the cluster exactly as you declared it in Git, and stays that way over time.

In this flow there are three distinct responsibilities:

Argo CD: configuration delivery and drift control
Argo CD is responsible for delivering and maintaining the desired backup configuration in the cluster. It continuously reconciles Kubernetes manifests stored in Git with the live cluster state, including the Velero Schedule custom resource stored in the openshift-adp namespace. When the schedule is first introduced, Argo CD applies it to the cluster. From that point onward, it ensures the configuration remains consistent with Git: any manual changes made directly in the cluster are reverted, updates to parameters such as cron timing, included namespaces, retention (ttl), or snapshot settings are tracked and reviewed through Git commits, and accidental deletions are automatically corrected. If pruning is enabled, removing the schedule from Git will also remove it from the cluster. In this role, Argo CD acts as the “desired state enforcer” for backup policy and scheduling.

OADP / Velero: execution engine
Once the Schedule custom resource exists, OADP—through Velero—takes over the operational execution. Velero continuously watches for Schedule resources in the openshift-adp namespace and evaluates them based on the defined cron expression. At each scheduled interval, Velero creates a corresponding Backup object and executes the backup using the existing OADP configuration, including the configured BackupStorageLocation (BSL), VolumeSnapshotLocation (VSL), credentials, and plugins. It then writes backup metadata to object storage and performs volume snapshots or filesystem-level backups as configured. In short, Velero is responsible for running backups, while Argo CD is responsible for ensuring the schedule definition exists and remains correct.

The Schedule custom resource: the contract between GitOps and execution
The Velero Schedule custom resource serves as the contract between Argo CD and Velero. Argo CD manages this resource declaratively, synchronising it from Git into the cluster, while Velero consumes it operationally to generate and execute backups. For example, if you change the backup time from 0 2 * * * to 0 1 * * *, increase the retention from 168h to 720h, or adjust the includedNamespaces, those changes are made in Git. Argo CD applies and enforces them in the cluster, and Velero automatically begins using the updated configuration without any manual intervention. Argo CD does not trigger cron jobs, run backups, or move data to storage; its value lies in making backup scheduling governed, auditable, repeatable, and consistent across environments, enabling safe promotion of the same policy from development to production.


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
  # Minute hour day-of-month month day-of-week
  # Minute (0) – run at the start of the hour
  # Hour (2) – run at 02:00
  # Day of month (*) – every day of the month
  # Month (*) – every month
  # Day of week (*) – every day of the week
  schedule: "0 2 * * *"
  # Only include your CP4I project
  template:
    includedNamespaces:
      - nav-ns
    snapshotVolumes: true
    # Enable snapshotting of PVCs
    defaultVolumesToFsBackup: false
    ttl: 48h   # expire backups after 2 days
```

**Key fields explained:**

* `schedule`: Cron syntax for periodic backups.
* `includedNamespaces`: Limits scope to CP4I namespace.
* `snapshotVolumes`: Captures volume snapshots if CSI supports it.
* `ttl`: Time-to-live so old backups are automatically cleaned up.

This Yaml is already available in git  <PUT THE LINK AFTER MERGING IT TO MAIN>

---

Give Argo CD the right RBAC in openshift-adp namespace
To allow Argo CD to manage OADP and Velero resources, you need to grant it the right RBAC permissions in the openshift-adp namespace. The `Argo CD Application Controller` in the openshift-gitops namespace doesn’t have permission to act on resources in other namespaces, including openshift-adp where OADP runs. When you ask Argo CD to sync a Restore or DataProtectionApplication manifest, it tries to create or update those CRs inside openshift-adp.

This is done by creating a Role and RoleBinding that let the `Argo CD Application Controller` (openshift-gitops-argocd-application-controller) create and update OADP custom resources such as DataProtectionApplication, Backup, and Restore. Without these permissions, syncs will fail when Argo CD tries to apply the restore configuration. You can apply the provided rbac-premissions.yaml, which binds the controller to manage OADP/Velero CRs inside openshift-adp.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: argocd-manage-velero-schedules
  namespace: openshift-adp
rules:
- apiGroups: ["velero.io"]
  resources: ["schedules"]
  verbs: ["get","list","watch","create","update","patch","delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: argocd-manage-velero-schedules
  namespace: openshift-adp
subjects:
- kind: ServiceAccount
  name: openshift-gitops-argocd-application-controller
  namespace: openshift-gitops
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: argocd-manage-velero-schedules
```  
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
  project: default
  source:
    # Link to the GitRepo
    repoURL: https://github.com/demo-test-source/demo-source.git 
    # Branch Name
    targetRevision: oadp-backup
    # Directory Path, Where the file is
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

Log in with the admin account (username: admin) and retrieve the password from the <argo_cd_instance_name>-cluster Secret under admin.password in openshift-gitops namespace. 



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

**Testing and Restore:** Regularly validate restores to ensure backups are usable, using the restore patterns from the earlier blog. ([community.ibm.com][1])

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