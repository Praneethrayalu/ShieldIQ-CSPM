"""Microsoft Azure rules."""
from .engine import CheckResult, fixer, find, open_to_world, port_in, rule


def _set(coll, key, field, value):
    def fn(inv, rid):
        it = find(inv.get(coll), key, rid.split("/")[-1])
        if it is None:
            return False
        it[field] = value
        return True
    return fn


def _rid(inv, kind, name):
    return f"/subscriptions/{inv.get('subscription_id', 'sub')}/{kind}/{name}"


@rule("AZ-STG-001", "azure", "Storage", "Storage account allows public blob access", "critical",
      "allowBlobPublicAccess should be false.",
      ["public_data"],
      "The storage account permits containers to be configured for anonymous public read.",
      "Any container set to 'Blob' or 'Container' access can be read anonymously.",
      ["Set allowBlobPublicAccess=false on the account.", "Use SAS tokens or Private Endpoints for sharing."],
      terraform='''
resource "azurerm_storage_account" "{resource}" {
  # ...existing arguments...
  allow_nested_items_to_be_public = false
}''',
      cli="az storage account update --name {resource} --allow-blob-public-access false",
      refs=["CIS Azure 3.7"], asset="datastore")
def az_blob(inv):
    for s in inv.get("storage_accounts", []):
        yield CheckResult(_rid(inv, "storageAccounts", s["name"]), not s.get("allow_blob_public_access"),
                          "Public blob access allowed" if s.get("allow_blob_public_access") else "Disabled")


fixer("AZ-STG-001")(_set("storage_accounts", "name", "allow_blob_public_access", False))


@rule("AZ-STG-002", "azure", "Storage", "Storage account allows HTTP / TLS < 1.2", "medium",
      "Require secure transfer (HTTPS) and minimum TLS 1.2.",
      ["encryption_transit"],
      "supportsHttpsTrafficOnly is false or minimumTlsVersion is below TLS1_2.",
      "Data and SAS tokens can be intercepted in transit.",
      ["Enable 'Secure transfer required'.", "Set minimum TLS version to 1.2."],
      cli="az storage account update --name {resource} --https-only true --min-tls-version TLS1_2",
      refs=["CIS Azure 3.1", "CIS Azure 3.15"], asset="datastore")
def az_https(inv):
    for s in inv.get("storage_accounts", []):
        ok = s.get("https_only") and s.get("min_tls", "TLS1_0") >= "TLS1_2"
        yield CheckResult(_rid(inv, "storageAccounts", s["name"]), bool(ok),
                          f"https_only={s.get('https_only')}, min_tls={s.get('min_tls')}")


@fixer("AZ-STG-002")
def _fix_https(inv, rid):
    s = find(inv.get("storage_accounts"), "name", rid.split("/")[-1])
    if not s:
        return False
    s.update(https_only=True, min_tls="TLS1_2")
    return True


@rule("AZ-NET-001", "azure", "Network", "NSG allows SSH/RDP from the internet", "critical",
      "Network security groups must not allow 22/3389 from Internet / *.",
      ["network"],
      "An inbound Allow rule with source '*' or 'Internet' covers port 22 or 3389.",
      "VMs behind this NSG are exposed to brute force and remote exploits.",
      ["Remove the rule.", "Use Azure Bastion or Just-In-Time VM access."],
      cli="az network nsg rule delete --nsg-name {resource} --name <rule-name> --resource-group <rg>",
      refs=["CIS Azure 6.1", "CIS Azure 6.2"], asset="network")
def az_nsg(inv):
    for n in inv.get("nsgs", []):
        bad = _nsg_bad(n)
        yield CheckResult(_rid(inv, "networkSecurityGroups", n["name"]), not bad,
                          f"Ports {', '.join(bad)} open to Internet" if bad else "Restricted")


def _nsg_bad(n):
    bad = set()
    for r in n.get("rules", []):
        if r.get("direction", "Inbound") != "Inbound" or r.get("access", "Allow") != "Allow":
            continue
        if not open_to_world(r.get("source")):
            continue
        lo, _, hi = str(r.get("port", "0")).partition("-")
        if lo == "*":
            lo, hi = "0", "65535"
        for p in (22, 3389):
            if port_in(p, lo, hi or lo):
                bad.add(str(p))
    return sorted(bad)


@fixer("AZ-NET-001")
def _fix_nsg(inv, rid):
    n = find(inv.get("nsgs"), "name", rid.split("/")[-1])
    if not n:
        return False
    for r in n.get("rules", []):
        if open_to_world(r.get("source")):
            r["source"] = "VirtualNetwork"
    return True


@rule("AZ-SQL-001", "azure", "SQL", "Azure SQL firewall allows all IPs", "critical",
      "No SQL Server firewall rule should span 0.0.0.0 - 255.255.255.255.",
      ["network", "public_data"],
      "A firewall rule allows the entire IPv4 range.",
      "The SQL endpoint is reachable from anywhere; only the password protects your data.",
      ["Delete the allow-all rule.", "Use Private Endpoint or specific client IP rules."],
      cli="az sql server firewall-rule delete --server {resource} --name AllowAll --resource-group <rg>",
      refs=["CIS Azure 4.1.2"], asset="datastore")
def az_sql(inv):
    for s in inv.get("sql_servers", []):
        bad = any(r.get("start") == "0.0.0.0" and r.get("end") == "255.255.255.255" for r in s.get("firewall_rules", []))
        yield CheckResult(_rid(inv, "sqlServers", s["name"]), not bad, "Allow-all rule" if bad else "Restricted")


@fixer("AZ-SQL-001")
def _fix_azsql(inv, rid):
    s = find(inv.get("sql_servers"), "name", rid.split("/")[-1])
    if not s:
        return False
    s["firewall_rules"] = [r for r in s.get("firewall_rules", [])
                           if not (r.get("start") == "0.0.0.0" and r.get("end") == "255.255.255.255")]
    return True


@rule("AZ-SQL-002", "azure", "SQL", "Azure SQL auditing is disabled", "medium",
      "Server auditing should be enabled.",
      ["logging"],
      "Auditing is not configured on the logical SQL server.",
      "Database access and changes cannot be investigated.",
      ["Enable auditing to a Log Analytics workspace or storage account."],
      cli="az sql server audit-policy update --name {resource} --resource-group <rg> --state Enabled "
          "--lats Enabled --lawri <workspace-id>",
      refs=["CIS Azure 4.1.1"], asset="datastore")
def az_sql_audit(inv):
    for s in inv.get("sql_servers", []):
        yield CheckResult(_rid(inv, "sqlServers", s["name"]), bool(s.get("auditing")),
                          "Auditing on" if s.get("auditing") else "Auditing off")


fixer("AZ-SQL-002")(_set("sql_servers", "name", "auditing", True))


@rule("AZ-KV-001", "azure", "Key Vault", "Key Vault purge protection is disabled", "medium",
      "Enable soft delete and purge protection on Key Vaults.",
      ["backup"],
      "Purge protection is off, so deleted secrets/keys can be permanently purged immediately.",
      "A malicious insider or attacker can irreversibly destroy keys and the data they protect.",
      ["Enable purge protection (cannot be disabled afterwards)."],
      cli="az keyvault update --name {resource} --enable-purge-protection true",
      refs=["CIS Azure 8.5"])
def az_kv(inv):
    for k in inv.get("key_vaults", []):
        ok = k.get("soft_delete", True) and k.get("purge_protection")
        yield CheckResult(_rid(inv, "vaults", k["name"]), bool(ok),
                          "Protected" if ok else "Purge protection off")


fixer("AZ-KV-001")(_set("key_vaults", "name", "purge_protection", True))


@rule("AZ-VM-001", "azure", "Compute", "VM disk encryption is not enabled", "medium",
      "VM OS and data disks should be encrypted (ADE or encryption at host / CMK).",
      ["encryption_rest"],
      "The VM's managed disks are not encrypted with ADE/encryption-at-host.",
      "Disk snapshots and exports are readable without additional keys.",
      ["Enable encryption at host or Azure Disk Encryption."],
      cli="az vm encryption enable --name {resource} --resource-group <rg> --disk-encryption-keyvault <kv>",
      refs=["CIS Azure 7.3"], asset="compute")
def az_vm(inv):
    for v in inv.get("vms", []):
        yield CheckResult(_rid(inv, "virtualMachines", v["name"]), bool(v.get("disk_encrypted")),
                          "Encrypted" if v.get("disk_encrypted") else "Not encrypted")


fixer("AZ-VM-001")(_set("vms", "name", "disk_encrypted", True))


@rule("AZ-ID-001", "azure", "Entra ID", "Privileged Entra ID user without MFA", "critical",
      "Every user holding an admin role must use MFA (Conditional Access).",
      ["mfa"],
      "A Global/Privileged admin account is not registered for MFA.",
      "A phished admin password gives control of the tenant and every subscription.",
      ["Require MFA for admin roles with a Conditional Access policy.", "Use PIM for just-in-time elevation."],
      cli="# Entra admin center > Protection > Conditional Access > New policy: Directory roles = admins, Grant = Require MFA",
      refs=["CIS Azure 1.1.1"], asset="identity")
def az_mfa(inv):
    for u in inv.get("users", []):
        if u.get("admin"):
            yield CheckResult(f"entra/users/{u['upn']}", bool(u.get("mfa")), "MFA on" if u.get("mfa") else "No MFA")


@fixer("AZ-ID-001")
def _fix_azmfa(inv, rid):
    u = find(inv.get("users"), "upn", rid.split("/")[-1])
    if u:
        u["mfa"] = True
    return bool(u)


@rule("AZ-MON-001", "azure", "Defender", "Microsoft Defender for Cloud is not enabled", "low",
      "Enable Defender plans for servers, storage and SQL.",
      ["monitoring"],
      "Defender for Cloud enhanced security features are off.",
      "Threats such as crypto-mining or anomalous storage access are not detected.",
      ["Enable the Defender plans relevant to your workloads."],
      cli="az security pricing create --name VirtualMachines --tier standard")
def az_defender(inv):
    if "defender_enabled" in inv:
        yield CheckResult(f"/subscriptions/{inv.get('subscription_id', 'sub')}", bool(inv["defender_enabled"]),
                          "Enabled" if inv["defender_enabled"] else "Disabled")


@fixer("AZ-MON-001")
def _fix_def(inv, rid):
    inv["defender_enabled"] = True
    return True
