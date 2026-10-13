"""Live GitHub collector using the public REST API (works without a token for public repos;
a token in GITHUB_TOKEN or the integration form unlocks org/admin-only settings and higher rate limits)."""
import re

import requests

from . import CollectorError
from ..rules.code import scan_text

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
TEXT_EXT = re.compile(r"\.(py|js|ts|tsx|jsx|java|go|rb|php|cs|tf|tfvars|ya?ml|json|env|ini|cfg|conf|toml|properties|"
                      r"sh|ps1|xml|txt|md|ipynb)$|(^|/)(\.env[^/]*|Dockerfile|config)$", re.I)
SKIP_DIR = re.compile(r"(^|/)(node_modules|vendor|dist|build|\.git|venv|\.venv|__pycache__|site-packages)/")
NAME = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def _session(token=None):
    s = requests.Session()
    s.headers.update({"Accept": "application/vnd.github+json", "User-Agent": "ShieldIQ-scanner",
                      "X-GitHub-Api-Version": "2022-11-28"})
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _get(s, url, ok_missing=False, **kw):
    try:
        r = s.get(url, timeout=15, **kw)
    except requests.RequestException as exc:
        raise CollectorError(f"GitHub unreachable: {exc.__class__.__name__}")
    if r.status_code in (403, 429) and r.headers.get("X-RateLimit-Remaining") == "0":
        raise CollectorError("GitHub API rate limit reached (60/hour without a token). Add a token or retry later.")
    if r.status_code == 401:
        raise CollectorError("GitHub rejected the token (401). Check it or remove it to scan public repos.")
    if r.status_code in (403, 404) and ok_missing:
        return None
    if r.status_code == 404:
        raise CollectorError(f"Not found on GitHub: {url.replace(API, '')}")
    if r.status_code >= 400:
        raise CollectorError(f"GitHub API error {r.status_code}")
    return r


def collect(target: str, token: str = None, max_repos: int = 5, max_files: int = 60) -> dict:
    """target is 'owner' or 'owner/repo'."""
    target = (target or "").strip().strip("/").replace("https://github.com/", "")
    parts = target.split("/")
    if not 1 <= len(parts) <= 2 or not all(NAME.match(p) for p in parts):
        raise CollectorError("Enter a GitHub owner or owner/repo, e.g. 'octocat' or 'octocat/Hello-World'")
    s = _session(token)
    owner = parts[0]
    inv = {"org": {"name": owner}, "repos": [], "outside_collaborators": [], "_source": "github-live"}

    owner_info = _get(s, f"{API}/users/{owner}").json()
    if owner_info.get("type") == "Organization":
        org = _get(s, f"{API}/orgs/{owner}", ok_missing=True)
        tfa = org.json().get("two_factor_requirement_enabled") if org is not None else None
        if tfa is not None:  # only visible to org owners
            inv["org"]["two_factor_required"] = bool(tfa)

    if len(parts) == 2:
        repos = [_get(s, f"{API}/repos/{owner}/{parts[1]}").json()]
    else:
        kind = "orgs" if owner_info.get("type") == "Organization" else "users"
        repos = _get(s, f"{API}/{kind}/{owner}/repos", params={"per_page": 100, "sort": "pushed"}).json()
        repos = [r for r in repos if not r.get("fork") and not r.get("archived")][:max_repos]

    for repo in repos:
        name, branch = repo["name"], repo.get("default_branch", "main")
        item = {"name": name, "private": repo.get("private", False), "default_branch": branch,
                "html_url": repo.get("html_url")}
        br = _get(s, f"{API}/repos/{owner}/{name}/branches/{branch}", ok_missing=True)
        protected = bool(br and br.json().get("protected"))
        bp = {"enabled": protected}
        if protected and token:
            prot = _get(s, f"{API}/repos/{owner}/{name}/branches/{branch}/protection", ok_missing=True)
            if prot is not None:
                reviews = (prot.json().get("required_pull_request_reviews") or {})
                bp["required_reviews"] = reviews.get("required_approving_review_count", 0)
        item["branch_protection"] = bp
        sa = repo.get("security_and_analysis")  # present for admins only
        if sa:
            item["secret_scanning"] = (sa.get("secret_scanning") or {}).get("status") == "enabled"

        tree = _get(s, f"{API}/repos/{owner}/{name}/git/trees/{branch}", ok_missing=True,
                    params={"recursive": "1"})
        paths = [t["path"] for t in (tree.json().get("tree", []) if tree is not None else []) if t.get("type") == "blob"]
        lower = {p.lower() for p in paths}
        item["has_security_policy"] = bool({"security.md", ".github/security.md", "docs/security.md"} & lower)
        item["dependabot"] = bool({".github/dependabot.yml", ".github/dependabot.yaml"} & lower)
        sizes = {t["path"]: t.get("size", 0) for t in (tree.json().get("tree", []) if tree is not None else [])}
        candidates = [p for p in paths if TEXT_EXT.search(p) and not SKIP_DIR.search(p) and sizes.get(p, 0) < 200_000]
        candidates.sort(key=lambda p: (0 if re.search(r"(env|config|secret|settings|cred|key|\.tf)", p, re.I) else 1, p))
        found = []
        for path in candidates[:max_files]:
            try:
                r = s.get(f"{RAW}/{owner}/{name}/{branch}/{path}", timeout=10)
            except requests.RequestException:
                continue
            if r.status_code == 200:
                found.extend(scan_text(path, r.text))
        item["secrets_found"] = found
        item["files_scanned"] = min(len(candidates), max_files)
        inv["repos"].append(item)

    if token and len(parts) == 2:
        oc = _get(s, f"{API}/repos/{owner}/{parts[1]}/collaborators", ok_missing=True,
                  params={"affiliation": "outside"})
        if oc is not None:
            for c in oc.json():
                perm = "admin" if c.get("permissions", {}).get("admin") else "push" if c.get("permissions", {}).get("push") else "pull"
                inv["outside_collaborators"].append({"login": c["login"], "permission": perm})
    return inv
