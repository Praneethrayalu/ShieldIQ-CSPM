"""Secret detection rules for source code / config files (inventory: {"files": [{"path", "content"}]})."""
import math
import re

from .engine import CheckResult, fixer, rule

DETECTORS = [
    # (category, type, regex)
    ("cloud", "AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("cloud", "AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"=:\s]+([A-Za-z0-9/+]{40})\b")),
    ("cloud", "Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("cloud", "Azure Storage Key", re.compile(r"AccountKey=([A-Za-z0-9+/=]{60,100})")),
    ("private_key", "Private Key", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----)")),
    ("token", "GitHub Token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    ("token", "Slack Token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("token", "Slack Webhook", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})")),
    ("token", "Stripe Secret Key", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b")),
    ("token", "OpenAI API Key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b")),
    ("token", "Twilio Auth Token", re.compile(r"(?i)twilio.{0,20}?['\"=:\s]+([0-9a-f]{32})\b")),
    ("token", "JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("password", "Database URL with password",
     re.compile(r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/'\"]+:[^@\s'\"]{3,}@[^\s'\"]+)")),
    ("password", "Hard-coded password",
     re.compile(r"(?i)\b[\w-]*(?:password|passwd|pwd|secret|api_?key|token)\b\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]")),
]

PLACEHOLDERS = re.compile(r"(?i)(changeme|example|your[_-]?|xxxx|\*\*\*|<.*>|\$\{|placeholder|dummy|test123|"
                          r"os\.getenv|environ|process\.env)")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return v[:2] + "*" * (len(v) - 2)
    return v[:4] + "*" * min(len(v) - 8, 24) + v[-4:]


def scan_text(path: str, content: str):
    """Return a list of secret matches (values masked) found in one file."""
    found = []
    for lineno, line in enumerate(content.splitlines(), 1):
        if len(line) > 2000:
            line = line[:2000]
        for category, typ, rx in DETECTORS:
            for m in rx.finditer(line):
                val = m.group(1)
                if PLACEHOLDERS.search(val):
                    continue
                if category == "password" and typ == "Hard-coded password" and entropy(val) < 2.5:
                    continue
                found.append({"path": path, "line": lineno, "type": typ, "category": category,
                              "match": mask(val), "entropy": round(entropy(val), 2)})
    # de-duplicate (same line + same type); a specific detector beats the generic password one
    uniq = {(f["path"], f["line"], f["type"]): f for f in found}
    specific = {(f["path"], f["line"]) for f in uniq.values() if f["type"] != "Hard-coded password"}
    return [f for f in uniq.values() if f["type"] != "Hard-coded password" or (f["path"], f["line"]) not in specific]


def _matches(inv, category):
    for f in inv.get("files", []):
        hits = [h for h in scan_text(f["path"], f.get("content", "")) if h["category"] == category]
        yield f, hits


_STEPS = ["Treat the credential as compromised: revoke or rotate it at the provider now.",
          "Remove it from the file and load it from an environment variable or a secret manager.",
          "If the file was ever committed, purge it from git history (git filter-repo) and force-push.",
          "Add a pre-commit secret scanner (e.g. this ShieldIQ scanner in CI) to stop it happening again."]

for _cat, _id, _title, _sev in [
    ("cloud", "CODE-SEC-001", "Cloud provider credential committed in code", "critical"),
    ("private_key", "CODE-SEC-002", "Private key committed in code", "critical"),
    ("token", "CODE-SEC-003", "SaaS / API token committed in code", "high"),
    ("password", "CODE-SEC-004", "Hard-coded password or connection string", "high"),
]:
    def _make(cat):
        def check(inv):
            for f, hits in _matches(inv, cat):
                yield CheckResult(f"file://{f['path']}", not hits,
                                  "; ".join(f"{h['type']} on line {h['line']} ({h['match']})" for h in hits[:5])
                                  if hits else "Clean", {"matches": hits})
        return check

    rule(_id, "code", "Secrets", _title, _sev,
         "Credentials must never be stored in source code or config files.",
         ["secrets"],
         "A value matching a known credential format was found in the file.",
         "Anyone with access to the code, its git history, a build log or a leaked laptop can use the credential.",
         _STEPS,
         terraform='''
# Load secrets at runtime instead of hard-coding them
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]   # set in .env / secret manager, never committed''',
         cli="git rm --cached {resource} && echo '{resource}' >> .gitignore", asset="identity")(_make(_cat))

    def _mkfix(cat):
        def fx(inv, rid):
            path = rid.replace("file://", "")
            for f in inv.get("files", []):
                if f["path"] == path:
                    lines = f.get("content", "").splitlines()
                    bad = {h["line"] for h in scan_text(path, f.get("content", "")) if h["category"] == cat}
                    f["content"] = "\n".join("# [removed by ShieldIQ: secret moved to environment variable]"
                                             if i + 1 in bad else ln for i, ln in enumerate(lines))
                    return True
            return False
        return fx

    fixer(_id)(_mkfix(_cat))
