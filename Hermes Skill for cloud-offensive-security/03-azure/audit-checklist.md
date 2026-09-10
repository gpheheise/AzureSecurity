# Azure Audit Checklist

CIS Microsoft Azure Foundations Benchmark v3.0.0 aligned where applicable, plus Entra ID checks not in CIS. Each item has the manual command, the expected finding pattern, and a finding ID mapping to [findings-mapping.md](findings-mapping.md).

Set context once:

```bash
az login --tenant $TENANT_ID
az account set --subscription $SUB_ID
export TENANT_ID=$(az account show --query tenantId -o tsv)
export SUB_ID=$(az account show --query id -o tsv)
```

For Entra parts, also:

```powershell
Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","AuditLog.Read.All","RoleManagement.Read.All"
```

---

## 1. Entra ID — Identity baseline

### 1.1 Global Administrator count

```powershell
$ga = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $ga.Id
```

**Finding pattern:** Microsoft recommends 2–4 GA accounts (one break-glass + 2-3 emergency admins). More than 5 active GAs is a finding. Service accounts as GA = finding.

**Maps to:** F-AZ-IAM-001 (Excessive Global Administrators).

### 1.2 Break-glass accounts properly configured

```powershell
# Find accounts that look like emergency accounts
Get-MgUser -Filter "startswith(userPrincipalName,'breakglass') or startswith(userPrincipalName,'emergency')" -All

# Check they are excluded from CA and have strong creds + monitored sign-ins
```

Requirements: two break-glass accounts, cloud-only (`*.onmicrosoft.com`), FIDO2 keys stored physically, excluded from all CA policies, sign-in events alerted in real time, password ≥ 24 chars, not synced from on-prem.

**Maps to:** F-AZ-IAM-002 (Missing or misconfigured break-glass accounts).

### 1.3 MFA enabled for all privileged users

```powershell
# Check MFA status (per-user, not CA-driven)
Get-MgUser -All | ForEach-Object {
  $methods = Get-MgUserAuthenticationMethod -UserId $_.Id
  [pscustomobject]@{UPN=$_.UserPrincipalName; Methods=($methods.AdditionalProperties.'@odata.type' -join ';')}
}

# More reliable: pull from sign-in logs — did they MFA?
Get-MgAuditLogSignIn -Top 1000 -Filter "userPrincipalName eq '$UPN'" | Select createdDateTime, authenticationDetails
```

**Maps to:** F-AZ-IAM-003 (MFA not enforced for privileged roles).

### 1.4 Conditional Access — baseline policies present

Required baseline policies (Microsoft's own recommendations + DORA / NIS2 expectations):

- Block legacy authentication.
- Require MFA for all admins.
- Require MFA for Azure Management.
- Require compliant device for Microsoft admin portals.
- Block sign-in from non-allowed locations / unmanaged devices for sensitive apps.
- High sign-in risk → block or step-up.
- High user risk → require password change.

```powershell
Get-MgIdentityConditionalAccessPolicy | Select displayName, state, @{n="GrantTypes";e={$_.GrantControls.BuiltInControls}}
```

**Maps to:** F-AZ-IAM-004 (Missing baseline Conditional Access policy: Legacy auth not blocked), F-AZ-IAM-005 (Missing CA: MFA not required for admins), F-AZ-IAM-006 (Missing CA: MFA not required for Azure Management).

### 1.5 Privileged Identity Management (PIM) used for role assignments

```powershell
# Are roles permanently assigned or eligible?
Get-MgRoleManagementDirectoryRoleAssignment -All | Select PrincipalId, RoleDefinitionId, DirectoryScopeId

Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All | Select PrincipalId, RoleDefinitionId
```

If most privileged roles are permanent (in `RoleAssignment`) rather than eligible (in `RoleEligibilitySchedule`), PIM is not being used. Without PIM, every privileged session is a standing risk.

**Maps to:** F-AZ-IAM-007 (PIM not used for privileged role assignments).

### 1.6 User consent restricted

```powershell
Get-MgPolicyAuthorizationPolicy | Select PermissionGrantPolicyIdsAssignedToDefaultUserRole
```

Expected: users can only consent to apps from verified publishers with low-impact permissions, or no consent at all. The default `ManagePermissionGrantsForSelf.microsoft-user-default-legacy` setting allows users to consent to any app with any user-impacting permission. Change to `ManagePermissionGrantsForSelf.microsoft-user-default-low`.

**Maps to:** F-AZ-IAM-008 (User consent not restricted — OAuth phishing risk).

### 1.7 Guest user defaults

```powershell
Get-MgPolicyAuthorizationPolicy | Select GuestUserRoleId, AllowInvitesFrom
```

Default `AllowInvitesFrom = everyone` is permissive. CIS expects `adminsAndGuestInviters`. `GuestUserRoleId` should be the restricted Guest role.

**Maps to:** F-AZ-IAM-009 (Guest invitation not restricted).

### 1.8 Device code flow not blocked for sensitive accounts

Device code is the dominant phish vector against admins. CA can block it explicitly.

```powershell
# Look for CA policy that blocks "Authentication flows" → "Device code flow"
# Pull all CA policies, search for the auth flow condition
Get-MgIdentityConditionalAccessPolicy | Where-Object {
  $_.Conditions.AuthenticationFlows.TransferMethods -match 'deviceCodeFlow'
}
```

**Maps to:** F-AZ-IAM-010 (Device code flow not blocked by Conditional Access).

### 1.9 Privileged accounts not synced from on-prem

```powershell
Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | ForEach-Object {
  Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id
} | ForEach-Object {
  Get-MgUser -UserId $_.Id -Property OnPremisesSyncEnabled, UserPrincipalName | Select UserPrincipalName, OnPremisesSyncEnabled
}
```

Any Global Admin synced from on-prem is a tier violation. On-prem compromise = cloud compromise.

**Maps to:** F-AZ-IAM-011 (On-prem-synced accounts hold Global Admin role).

### 1.10 Service principals review

```bash
# All apps with high-priv Graph permissions
az ad sp list --all -o json | jq -r '.[] | select(.appRoles | length > 0) | .displayName + " " + .id'

# Pull all consent grants and look for risky scopes
az rest --method GET --uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" | \
  jq '.value[] | select(.scope | contains("Mail.") or contains("Files.") or contains("Directory.") or contains("RoleManagement."))'
```

**Maps to:** F-AZ-IAM-012 (Service principals with excessive Graph permissions).

---

## 2. Subscription / RBAC

### 2.1 Subscription Owners count

```bash
az role assignment list --all --query "[?roleDefinitionName=='Owner']" -o table
```

Owners should be 2–3 per subscription; users (not service accounts), with PIM.

**Maps to:** F-AZ-RBAC-001 (Excessive Owner role assignments).

### 2.2 Custom roles audit

```bash
az role definition list --custom-role-only true -o json > custom-roles.json
jq '.[] | {name:.roleName, perms:[.permissions[].actions]}' custom-roles.json
```

Watch for `*` in `actions`, `Microsoft.Authorization/*/write`, `Microsoft.KeyVault/vaults/*`, anything that grants role assignment.

**Maps to:** F-AZ-RBAC-002 (Custom role with overly broad permissions).

### 2.3 Classic administrators

```bash
az role assignment list --include-classic-administrators --query "[?roleDefinitionName=='CoAdministrator' || roleDefinitionName=='ServiceAdministrator']" -o table
```

Classic admins shouldn't exist in modern subs. They predate RBAC and grant full sub access without being visible in normal role assignment views.

**Maps to:** F-AZ-RBAC-003 (Classic administrators present on subscription).

### 2.4 Role assignments to broad scopes

```bash
# Find assignments at subscription scope (vs. RG scope) for non-admins
az role assignment list --all -o json | \
  jq '.[] | select(.scope | test("^/subscriptions/[^/]+$")) | {p:.principalName, r:.roleDefinitionName, s:.scope}'
```

Contributor at subscription scope for a developer = excessive. RG scope is the floor for most workloads.

**Maps to:** F-AZ-RBAC-004 (Role assignment scope too broad).

---

## 3. Storage Accounts

### 3.1 Secure transfer required

```bash
az storage account list --query "[].{Name:name, HTTPSOnly:enableHttpsTrafficOnly}" -o table
```

Any `false` = finding.

**Maps to:** F-AZ-STO-001 (Storage account allows HTTP).

### 3.2 Minimum TLS version

```bash
az storage account list --query "[].{Name:name, MinTLS:minimumTlsVersion}" -o table
```

Expect `TLS1_2` or `TLS1_3`. Anything else = finding.

**Maps to:** F-AZ-STO-002 (Storage account minimum TLS version below 1.2).

### 3.3 Public network access

```bash
az storage account list --query "[].{Name:name, PubAccess:publicNetworkAccess, AllowBlobPub:allowBlobPublicAccess}" -o table
```

`publicNetworkAccess: Enabled` plus `allowBlobPublicAccess: true` = anyone on internet could potentially access blobs.

**Maps to:** F-AZ-STO-003 (Storage account public access enabled).

### 3.4 Anonymous container access

```bash
for sa in $(az storage account list --query "[].name" -o tsv); do
  rg=$(az storage account show --name $sa --query resourceGroup -o tsv)
  echo "=== $sa ==="
  az storage container list --account-name $sa --auth-mode login \
    --query "[?properties.publicAccess!='None'].{name:name, access:properties.publicAccess}" -o table 2>/dev/null
done
```

**Maps to:** F-AZ-STO-004 (Anonymous container access enabled).

### 3.5 Storage account key rotation

```bash
az storage account list --query "[].{Name:name, KeyPolicy:keyPolicy}" -o table
```

`keyPolicy.keyExpirationPeriodInDays` should be set. Missing = no rotation policy.

**Maps to:** F-AZ-STO-005 (Storage account keys not subject to rotation policy).

### 3.6 Soft delete / immutability

```bash
for sa in $(az storage account list --query "[].name" -o tsv); do
  az storage blob service-properties show --account-name $sa --auth-mode login \
    --query "{delete:deleteRetentionPolicy, containerDelete:containerDeleteRetentionPolicy}" 2>/dev/null
done
```

Soft delete disabled = ransomware can wipe blobs cleanly.

**Maps to:** F-AZ-STO-006 (Storage account soft delete disabled), F-AZ-STO-007 (No immutability policy on critical containers).

### 3.7 Defender for Storage enabled

```bash
az security pricing show --name StorageAccounts --query pricingTier
```

`Standard` = enabled. `Free` = not enabled.

**Maps to:** F-AZ-STO-008 (Defender for Storage not enabled).

---

## 4. Key Vault

### 4.1 Soft delete + purge protection

```bash
az keyvault list --query "[].{Name:name, SoftDelete:properties.enableSoftDelete, PurgeProtect:properties.enablePurgeProtection}" -o table
```

Both should be `true`. Without purge protection, anyone with `purge` can delete + immediately recreate keys, erasing audit chain.

**Maps to:** F-AZ-KV-001 (Key Vault purge protection disabled).

### 4.2 Network restrictions

```bash
az keyvault list --query "[].{Name:name, PubNet:properties.publicNetworkAccess, Bypass:properties.networkAcls.bypass, DefaultAction:properties.networkAcls.defaultAction}" -o table
```

Production Key Vaults should have `defaultAction: Deny` with explicit allowed networks or Private Endpoint.

**Maps to:** F-AZ-KV-002 (Key Vault publicly accessible).

### 4.3 RBAC vs access policies

```bash
az keyvault list --query "[].{Name:name, RBAC:properties.enableRbacAuthorization, AccessPolicies:properties.accessPolicies | length(@)}" -o table
```

Vaults still on access policies should be migrated to RBAC. Mixed mode is a confusion liability.

**Maps to:** F-AZ-KV-003 (Key Vault still using access policies — should migrate to RBAC).

### 4.4 Diagnostic logging

```bash
for kv in $(az keyvault list --query "[].name" -o tsv); do
  rg=$(az keyvault show --name $kv --query resourceGroup -o tsv)
  id=$(az keyvault show --name $kv --query id -o tsv)
  az monitor diagnostic-settings list --resource $id -o table
done
```

Missing diagnostic settings = secret reads not logged anywhere queryable.

**Maps to:** F-AZ-KV-004 (Key Vault diagnostic logs not configured).

### 4.5 Key + secret expiry

```bash
for kv in $(az keyvault list --query "[].name" -o tsv); do
  echo "=== $kv ==="
  az keyvault secret list --vault-name $kv --query "[?attributes.expires==null]" -o table
  az keyvault key list --vault-name $kv --query "[?attributes.expires==null]" -o table
done
```

Secrets/keys without expiry dates = no rotation enforcement.

**Maps to:** F-AZ-KV-005 (Key Vault secrets/keys without expiration).

---

## 5. Networking

### 5.1 NSGs allowing inbound from 0.0.0.0/0

```bash
az network nsg list --query "[].name" -o tsv | while read nsg; do
  rg=$(az network nsg list --query "[?name=='$nsg'].resourceGroup" -o tsv)
  echo "=== $nsg ==="
  az network nsg rule list --nsg-name $nsg --resource-group $rg \
    --query "[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet')].{Name:name, Port:destinationPortRange, Proto:protocol}" -o table
done
```

Flag any rule that allows inbound from `*`, `0.0.0.0/0`, or `Internet` on ports other than 80/443 (and even those need justification).

**Maps to:** F-AZ-NET-001 (NSG allows unrestricted inbound from internet).

### 5.2 RDP / SSH exposed

```bash
az network nsg list --query "[].name" -o tsv | while read nsg; do
  rg=$(az network nsg list --query "[?name=='$nsg'].resourceGroup" -o tsv)
  az network nsg rule list --nsg-name $nsg --resource-group $rg \
    --query "[?direction=='Inbound' && access=='Allow' && (destinationPortRange=='22' || destinationPortRange=='3389' || contains(destinationPortRange,'22-') || contains(destinationPortRange,'3389-'))]" -o table
done
```

Should be empty. Bastion or JIT VM access for everything else.

**Maps to:** F-AZ-NET-002 (RDP/SSH exposed to internet).

### 5.3 Network Watcher enabled per region

```bash
az network watcher list -o table
```

Should be present in every region with resources.

**Maps to:** F-AZ-NET-003 (Network Watcher not enabled in all regions).

### 5.4 NSG flow logs

```bash
az network watcher flow-log list --location $REGION -o table
```

Retention should be at least 90 days, target storage account properly secured.

**Maps to:** F-AZ-NET-004 (NSG flow logs not configured or short retention).

### 5.5 Application Gateway / WAF

```bash
az network application-gateway list --query "[].{Name:name, SKU:sku.name, WAF:webApplicationFirewallConfiguration.enabled}" -o table

# WAF policy mode
az network application-gateway waf-policy list --query "[].{Name:name, Mode:policySettings.mode, State:policySettings.state}" -o table
```

WAF in Detection mode is not protection. Should be Prevention. WAF disabled on internet-facing AppGW = finding.

**Maps to:** F-AZ-NET-005 (WAF disabled or in detection-only mode).

### 5.6 DDoS Protection

```bash
az network ddos-protection list -o table
```

If subscriptions hold critical internet-facing resources, missing Standard DDoS plan is worth flagging (note: it costs ~3k/mo per plan).

**Maps to:** F-AZ-NET-006 (DDoS Protection Standard not configured).

---

## 6. Compute (VMs, Scale Sets)

### 6.1 Disks encrypted

```bash
# Server-side encryption is default. Customer-managed key only when explicit.
az disk list --query "[].{Name:name, Encryption:encryption.type}" -o table

# Look for OS disks with encryption disabled
az vm list --query "[].{Name:name, OSEncryption:storageProfile.osDisk.encryptionSettings}" -o table
```

**Maps to:** F-AZ-VM-001 (VM disks not encrypted with CMK where policy requires).

### 6.2 Just-in-Time (JIT) VM access

```bash
az security jit-policy list -o table
```

For VMs that need RDP/SSH for ops, JIT vs always-open.

**Maps to:** F-AZ-VM-002 (JIT VM access not configured for management ports).

### 6.3 Managed identities

```bash
az vm list --query "[].{Name:name, Identity:identity.type, UserAssignedIds:identity.userAssignedIdentities}" -o table
```

Audit which VMs have which UAMIs. Cross-reference UAMI role assignments — over-privileged UAMIs that are attached to internet-facing VMs are a privesc primitive.

**Maps to:** F-AZ-VM-003 (Managed Identity over-privileged), F-AZ-VM-004 (UAMI attached to publicly accessible VM).

### 6.4 Update Management / patch state

```bash
az vm assess-patches --resource-group $RG --name $VM
```

Older OS images + no update management = baseline finding for KRITIS workloads.

**Maps to:** F-AZ-VM-005 (Patch management not configured).

### 6.5 Guest agent + Defender for Servers

```bash
az security pricing show --name VirtualMachines --query pricingTier
```

Defender for Servers tier (P1 or P2) provides EDR + vuln assessment + change tracking. Not enabled = finding for production subs.

**Maps to:** F-AZ-VM-006 (Defender for Servers not enabled).

### 6.6 Boot diagnostics

```bash
az vm list --query "[].{Name:name, BootDiag:diagnosticsProfile.bootDiagnostics.enabled}" -o table
```

Disabled = cannot serial-console troubleshoot or screenshot-capture during incident.

**Maps to:** F-AZ-VM-007 (Boot diagnostics disabled).

---

## 7. AKS

### 7.1 RBAC + AAD integration

```bash
az aks list --query "[].{Name:name, EnableRBAC:enableRbac, AADProfile:aadProfile}" -o table
```

If `aadProfile` is null and RBAC not integrated with Entra, cluster auth is local cert / kubeconfig. Not acceptable for production.

**Maps to:** F-AZ-AKS-001 (AKS cluster not integrated with Entra RBAC).

### 7.2 Private cluster

```bash
az aks list --query "[].{Name:name, PrivateCluster:apiServerAccessProfile.enablePrivateCluster, AuthorizedIPs:apiServerAccessProfile.authorizedIpRanges}" -o table
```

Public API server + no IP allowlist = exposed control plane.

**Maps to:** F-AZ-AKS-002 (AKS API server publicly accessible).

### 7.3 Node OS / version

```bash
az aks list --query "[].{Name:name, K8sVersion:kubernetesVersion, NodePoolImages:agentPoolProfiles[].nodeImageVersion}" -o table

# Available upgrades
az aks get-upgrades --name $CLUSTER --resource-group $RG -o table
```

Out of date K8s minor version = finding (Microsoft only supports current and N-2).

**Maps to:** F-AZ-AKS-003 (AKS cluster running unsupported Kubernetes version).

### 7.4 Network policy

```bash
az aks list --query "[].{Name:name, NetworkPolicy:networkProfile.networkPolicy, NetworkPlugin:networkProfile.networkPlugin}" -o table
```

No network policy = flat pod-to-pod traffic.

**Maps to:** F-AZ-AKS-004 (AKS network policy not enforced).

### 7.5 Pod Security Standards / Azure Policy add-on

```bash
az aks list --query "[].{Name:name, PolicyAddon:addonProfiles.azurepolicy.enabled}" -o table
```

Azure Policy for AKS = Gatekeeper-based admission control.

**Maps to:** F-AZ-AKS-005 (Azure Policy add-on for AKS disabled).

### 7.6 Defender for Containers

```bash
az security pricing show --name Containers --query pricingTier
```

**Maps to:** F-AZ-AKS-006 (Defender for Containers not enabled).

---

## 8. SQL / Databases

### 8.1 Public network access

```bash
az sql server list --query "[].{Name:name, PubNet:publicNetworkAccess}" -o table
az postgres flexible-server list --query "[].{Name:name, PubAccess:network.publicNetworkAccess}" -o table
az mysql flexible-server list --query "[].{Name:name, PubAccess:network.publicNetworkAccess}" -o table
```

**Maps to:** F-AZ-DB-001 (Database publicly accessible).

### 8.2 Auditing + Defender for SQL

```bash
for srv in $(az sql server list --query "[].name" -o tsv); do
  rg=$(az sql server list --query "[?name=='$srv'].resourceGroup" -o tsv)
  echo "=== $srv ==="
  az sql server audit-policy show --resource-group $rg --name $srv
  az sql server threat-policy show --resource-group $rg --name $srv 2>/dev/null
done
```

**Maps to:** F-AZ-DB-002 (SQL auditing not enabled), F-AZ-DB-003 (Defender for SQL not enabled).

### 8.3 TDE

```bash
for srv in $(az sql server list --query "[].name" -o tsv); do
  rg=$(az sql server list --query "[?name=='$srv'].resourceGroup" -o tsv)
  for db in $(az sql db list --server $srv --resource-group $rg --query "[?name!='master'].name" -o tsv); do
    az sql db tde show --server $srv --resource-group $rg --database $db --query "{db:'$db', state:state}" -o tsv
  done
done
```

TDE not enabled on any non-master DB = finding.

**Maps to:** F-AZ-DB-004 (Transparent Data Encryption disabled).

### 8.4 Entra-only authentication

```bash
for srv in $(az sql server list --query "[].name" -o tsv); do
  rg=$(az sql server list --query "[?name=='$srv'].resourceGroup" -o tsv)
  az sql server ad-only-auth show --resource-group $rg --name $srv
done
```

SQL admin password auth still enabled = preventable credential exposure.

**Maps to:** F-AZ-DB-005 (SQL Server Entra-only authentication not enforced).

---

## 9. Logging + monitoring

### 9.1 Activity log retention

```bash
az monitor log-profiles list -o table
# Legacy log profiles, but check
```

Modern: diagnostic settings on subscription level send activity logs to Log Analytics + Storage. Verify both targets exist.

```bash
az monitor diagnostic-settings subscription list -o table
```

**Maps to:** F-AZ-LOG-001 (Activity logs not exported to long-term storage).

### 9.2 Defender for Cloud enabled across plans

```bash
az security pricing list -o table
```

CIS expects: Servers, App Service, Databases, Storage, Containers, Key Vault, Resource Manager, DNS, APIs (if used), Open Source Relational DBs.

**Maps to:** F-AZ-LOG-002 (Defender for Cloud plans not enabled).

### 9.3 Microsoft Sentinel deployment

```bash
# Sentinel is a Log Analytics workspace solution
az monitor log-analytics workspace list --query "[].{Name:name, Sku:sku.name, Retention:retentionInDays}" -o table

# Solutions installed
az monitor log-analytics solution list --query "[].{Name:name, Workspace:workspaceResourceId}" -o table
```

**Maps to:** F-AZ-LOG-003 (No SIEM coverage for Azure / Sentinel not deployed).

### 9.4 Unified Audit Log (M365)

```powershell
# Requires Exchange Online PowerShell
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Select UnifiedAuditLogIngestionEnabled
```

Should be `True`. Default has been on since 2019 but legacy tenants sometimes still off. Without UAL, M365 forensics is impossible.

**Maps to:** F-AZ-LOG-004 (M365 Unified Audit Log not enabled or not retained ≥ 1 year).

### 9.5 Diagnostic settings on critical resources

```bash
# Spot check Key Vaults, SQL, Storage, AKS
for kv in $(az keyvault list --query "[].id" -o tsv); do
  az monitor diagnostic-settings list --resource $kv -o table
done
```

**Maps to:** F-AZ-LOG-005 (Resource diagnostic settings missing on critical resources).

### 9.6 Activity log alerts for key events

```bash
az monitor activity-log alert list -o table
```

Required alerts (CIS 5.x): NSG changes, security solution changes, policy assignment changes, SQL firewall changes, subscription admin updates.

**Maps to:** F-AZ-LOG-006 (No activity log alerts for critical configuration changes).

---

## 10. Automation — run it all at once

```bash
# Prowler v4 covers Azure too
prowler azure --tenant-id $TENANT_ID --output-formats json-asff html

# ScoutSuite
python3 scout.py azure --cli --report-dir ./scout-azure

# Maester (Entra ID baseline)
Install-Module Maester -Force
Invoke-Maester -OutputFolder ./maester

# Microsoft's own MCSB scan via Defender for Cloud
az security regulatory-compliance-standards list -o table
az security regulatory-compliance-controls list --standard-name "Azure-CIS-1.4.0" -o table
```

Use these to generate findings at scale, then manually triage the high/critical. Spot-check key findings to confirm they're real (automation has false positives) before they enter the report.

---

## Audit ↔ pentest crosswalk

| Audit finding (this checklist) | Pentest evidence (cookbook section) |
|--------------------------------|-------------------------------------|
| F-AZ-IAM-010 (device code not blocked) | Cookbook §2 — Device code phishing |
| F-AZ-IAM-012 (overprivileged SP) | Cookbook §4 — App registration abuse |
| F-AZ-STO-004 (anonymous container) | Cookbook §1 — Storage enum |
| F-AZ-VM-004 (UAMI overpriv + public VM) | Cookbook §4 — IMDS token grab |
| F-AZ-HYB-001 (Connect not hardened) | Cookbook §5 — AADConnect compromise |
| F-AZ-KV-002 (KV publicly accessible) | Cookbook §4 — KV secret dump |

A pentest report can cite "found via active testing" + "would be flagged by audit check F-AZ-XYZ" — strengthens both deliverables and gives the client a cross-check for future audits.
