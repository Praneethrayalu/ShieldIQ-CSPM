"""GitHub (source code / supply chain) rules."""
from .engine import CheckResult, fixer, find, rule


def _repo(inv, name):
    return find(inv.get("repos"), "name", name.split("/")[-1])


def _rid(inv, r):
    return f"github.com/{inv.get('org', {}).get('name', 'org')}/{r['name']}"


@rule("GH-ORG-001", "github", "Organization", "Organization does not require two-factor authentication", "high",
      "Require 2FA for all organization members.",
      ["mfa"],
      "Two-factor requirement is disabled at the organization level.",
      "A member with a reused password can push malicious code or exfiltrate private repositories.",
      ["Enable 'Require two-factor authentication' in organization security settings."],
      cli="# GitHub > Organization settings > Authentication security > Require two-factor authentication",
      asset="identity")
def gh_2fa(inv):
    org = inv.get("org")
    # only evaluated when the setting is known (personal accounts / non-owners can't see it)
    if org and "two_factor_required" in org:
        yield CheckResult(f"github.com/{org.get('name', 'org')}", bool(org.get("two_factor_required")),
                          "2FA required" if org.get("two_factor_required") else "2FA optional")


@fixer("GH-ORG-001")
def _fix_2fa(inv, rid):
    inv.setdefault("org", {})["two_factor_required"] = True
    return True


@rule("GH-REPO-001", "github", "Repository", "Default branch is not protected", "high",
      "Protect the default branch: require pull requests and block force pushes.",
      ["code"],
      "No branch protection rule (or ruleset) applies to the default branch.",
      "Anyone with write access can push directly to production code or rewrite history.",
      ["Add a branch protection rule / ruleset for the default branch.", "Block force pushes and deletions."],
      terraform='''
resource "github_branch_protection" "{resource}" {
  repository_id  = "{resource}"
  pattern        = "main"
  enforce_admins = true
  required_pull_request_reviews {
    required_approving_review_count = 1
  }
}''',
      cli="gh api -X PUT repos/<owner>/{resource}/branches/main/protection --input protection.json")
def gh_protect(inv):
    for r in inv.get("repos", []):
        bp = r.get("branch_protection") or {}
        yield CheckResult(_rid(inv, r), bool(bp.get("enabled")),
                          f"'{r.get('default_branch', 'main')}' protected" if bp.get("enabled") else
                          f"'{r.get('default_branch', 'main')}' unprotected")


@fixer("GH-REPO-001")
def _fix_bp(inv, rid):
    r = _repo(inv, rid)
    if not r:
        return False
    r["branch_protection"] = {"enabled": True, "required_reviews": 1, "enforce_admins": True}
    return True


@rule("GH-REPO-002", "github", "Repository", "Pull requests can merge without review", "medium",
      "Require at least one approving review before merge.",
      ["code"],
      "Branch protection exists but required approving reviews is 0.",
      "A single compromised account can merge malicious changes.",
      ["Set required approving review count to at least 1 and dismiss stale approvals."],
      cli="gh api -X PATCH repos/<owner>/{resource}/branches/main/protection/required_pull_request_reviews "
          "-f required_approving_review_count=1")
def gh_reviews(inv):
    for r in inv.get("repos", []):
        bp = r.get("branch_protection") or {}
        if bp.get("enabled"):
            yield CheckResult(_rid(inv, r), bp.get("required_reviews", 0) >= 1,
                              f"Required reviews: {bp.get('required_reviews', 0)}")


@fixer("GH-REPO-002")
def _fix_rev(inv, rid):
    r = _repo(inv, rid)
    if not r:
        return False
    r.setdefault("branch_protection", {"enabled": True})["required_reviews"] = 1
    return True


@rule("GH-REPO-003", "github", "Repository", "Secret scanning is disabled", "high",
      "Enable secret scanning and push protection.",
      ["secrets"],
      "GitHub secret scanning / push protection is off for the repository.",
      "Committed API keys and tokens go unnoticed until they are abused.",
      ["Enable secret scanning and push protection (free for public repositories)."],
      cli="gh api -X PATCH repos/<owner>/{resource} -F security_and_analysis[secret_scanning][status]=enabled")
def gh_secret_scanning(inv):
    for r in inv.get("repos", []):
        if "secret_scanning" in r:
            yield CheckResult(_rid(inv, r), bool(r["secret_scanning"]),
                              "Enabled" if r["secret_scanning"] else "Disabled")


@fixer("GH-REPO-003")
def _fix_ss(inv, rid):
    r = _repo(inv, rid)
    if r:
        r["secret_scanning"] = True
    return bool(r)


@rule("GH-REPO-004", "github", "Repository", "Dependabot alerts / security updates are off", "medium",
      "Enable Dependabot alerts so vulnerable dependencies are flagged.",
      ["vuln"],
      "Dependabot is not configured (no alerts and no .github/dependabot.yml).",
      "Known-vulnerable libraries stay in production without anyone being told.",
      ["Enable Dependabot alerts and security updates.", "Add .github/dependabot.yml for version updates."],
      cli="gh api -X PUT repos/<owner>/{resource}/vulnerability-alerts")
def gh_dependabot(inv):
    for r in inv.get("repos", []):
        if "dependabot" in r:
            yield CheckResult(_rid(inv, r), bool(r["dependabot"]), "Enabled" if r["dependabot"] else "Disabled")


@fixer("GH-REPO-004")
def _fix_db(inv, rid):
    r = _repo(inv, rid)
    if r:
        r["dependabot"] = True
    return bool(r)


@rule("GH-REPO-005", "github", "Repository", "No SECURITY.md vulnerability disclosure policy", "low",
      "Publish a security policy so researchers know how to report issues.",
      ["code"],
      "No SECURITY.md in the root, docs/ or .github/.",
      "Vulnerability reports get lost or are disclosed publicly in issues.",
      ["Add SECURITY.md with a contact address and supported versions."],
      cli="printf '# Security Policy\\n\\nReport vulnerabilities to security@example.com\\n' > SECURITY.md && "
          "git add SECURITY.md && git commit -m 'Add security policy'")
def gh_secmd(inv):
    for r in inv.get("repos", []):
        if "has_security_policy" in r:
            yield CheckResult(_rid(inv, r), bool(r["has_security_policy"]),
                              "Present" if r["has_security_policy"] else "Missing")


@fixer("GH-REPO-005")
def _fix_sec(inv, rid):
    r = _repo(inv, rid)
    if r:
        r["has_security_policy"] = True
    return bool(r)


@rule("GH-REPO-006", "github", "Repository", "Hard-coded secret found in repository files", "critical",
      "Repository contents must not include credentials.",
      ["secrets"],
      "A file in the repository matches a credential pattern (cloud key, token or private key).",
      "Anyone who can read the repository (everyone, if it is public) can use the credential.",
      ["Revoke / rotate the credential immediately (assume it is compromised).",
       "Remove it from the code and load it from environment variables or a secret manager.",
       "Purge it from git history (git filter-repo) if the repo is public."],
      cli="git filter-repo --replace-text <(echo 'LEAKED_VALUE==>REMOVED')", asset="identity")
def gh_secret_found(inv):
    for r in inv.get("repos", []):
        if "secrets_found" in r:
            found = r.get("secrets_found") or []
            yield CheckResult(_rid(inv, r), not found,
                              f"{len(found)} secret(s): " + ", ".join(f"{s['type']} in {s['path']}:{s['line']}"
                                                                     for s in found[:3]) if found else "None found",
                              {"secrets": found})


@fixer("GH-REPO-006")
def _fix_sf(inv, rid):
    r = _repo(inv, rid)
    if r:
        r["secrets_found"] = []
    return bool(r)


@rule("GH-ACC-001", "github", "Access", "Outside collaborator has admin access", "medium",
      "Outside collaborators should not be repository admins.",
      ["access"],
      "A non-member collaborator holds the admin permission.",
      "External accounts outside your 2FA and offboarding controls can change settings and delete the repo.",
      ["Downgrade the collaborator to write/read, or make them an org member under your policies."],
      cli="gh api -X PUT repos/<owner>/<repo>/collaborators/{resource} -f permission=push")
def gh_outside(inv):
    for c in inv.get("outside_collaborators", []):
        yield CheckResult(f"github.com/users/{c['login']}", c.get("permission") != "admin",
                          f"Permission: {c.get('permission')}")


@fixer("GH-ACC-001")
def _fix_oc(inv, rid):
    c = find(inv.get("outside_collaborators"), "login", rid.split("/")[-1])
    if c:
        c["permission"] = "push"
    return bool(c)
