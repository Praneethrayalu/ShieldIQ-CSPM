"""Policy engine.

Collectors turn a cloud account / repo / cluster / file into a normalized
*inventory* (plain dict). Rules are small Python functions that look at the
inventory and yield one CheckResult per resource they evaluated. Because live
data, demo data, uploaded snapshots and Terraform files all become the same
inventory shape, every rule works on all of them.
"""
import shlex
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional

RULES: Dict[str, "Rule"] = {}


@dataclass
class CheckResult:
    resource_id: str
    passed: bool
    detail: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    provider: str
    service: str
    title: str
    severity: str
    description: str
    tags: List[str]
    root_cause: str
    impact: str
    steps: List[str]
    terraform: str
    cli: str
    refs: List[str]
    check: Callable[[dict], Iterable[CheckResult]]
    fix: Optional[Callable[[dict, str], bool]] = None
    asset: str = ""  # graph role hint: datastore / identity / compute / network
    iac_kind: str = "tf"  # language of the `terraform` snippet: tf | yaml | py

    IAC_LABELS = {"tf": "Terraform", "yaml": "Kubernetes YAML", "py": "Secure code"}

    @property
    def iac_quote(self):
        return "hcl" if self.iac_kind == "tf" else "line"

    @property
    def iac_label(self):
        return self.IAC_LABELS.get(self.iac_kind, "IaC")

    def render(self, text: str, resource_id: str, quote: Optional[str] = None) -> str:
        """Fill {resource} (short name) / {resource_id} (full id) into a fix snippet.

        quote="shell": values are shlex.quote()d - resource ids come from scanned/uploaded data and must never
        be able to inject shell syntax into a generated fix script. quote="hcl": values are escaped for a
        Terraform string literal. None: plain text (human-readable steps)."""
        short = short_name(resource_id)
        full = resource_id or ""
        if quote == "shell":
            short, full = shlex.quote(short), shlex.quote(full)
        elif quote == "hcl":
            short, full = hcl_escape(short), hcl_escape(full)
        elif quote == "line":  # YAML / code snippets: no line breaks or control characters can be injected
            short, full = comment_safe(short), comment_safe(full)
        return (text or "").replace("{resource}", short).replace("{resource_id}", full)


def short_name(resource_id: str) -> str:
    """Name a CLI expects: last path segment, and for path-less ARNs (S3 buckets: arn:aws:s3:::bucket) the part
    after the last ':' - so S3 commands get the bucket name, not the ARN."""
    short = (resource_id or "").split("/")[-1]
    if short.startswith("arn:"):
        short = short.split(":")[-1]
    return short


def hcl_escape(value: str) -> str:
    value = "".join(ch for ch in (value or "") if ch >= " " and ch != "\x7f")
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("${", "$${").replace("%{", "%%{")


def comment_safe(value: str) -> str:
    """One-line, control-character-free text for a '# ...' comment in a generated script."""
    return "".join(ch if ch >= " " and ch != "\x7f" else "?" for ch in str(value or ""))


def rule(id, provider, service, title, severity, description, tags, root_cause, impact, steps,
         terraform="", cli="", refs=(), asset=""):
    def deco(fn):
        RULES[id] = Rule(id=id, provider=provider, service=service, title=title, severity=severity,
                         description=description, tags=list(tags), root_cause=root_cause, impact=impact,
                         steps=list(steps), terraform=terraform.strip("\n"), cli=cli, refs=list(refs),
                         check=fn, asset=asset,
                         iac_kind={"kubernetes": "yaml", "code": "py"}.get(provider, "tf"))
        return fn
    return deco


def fixer(rule_id):
    """Register an auto-fix that mutates an inventory (used for demo/snapshot environments)."""
    def deco(fn):
        RULES[rule_id].fix = fn
        return fn
    return deco


def get_rule(rule_id) -> Optional[Rule]:
    return RULES.get(rule_id)


def rules_for(provider) -> List[Rule]:
    return [r for r in RULES.values() if r.provider == provider]


@dataclass
class Evaluation:
    rule: Rule
    results: List[CheckResult]
    error: Optional[str] = None  # set when the rule itself crashed: nothing was evaluated

    @property
    def failed(self):
        return [r for r in self.results if not r.passed]


def evaluate(provider: str, inventory: dict) -> List[Evaluation]:
    out = []
    for r in rules_for(provider):
        try:
            results, error = list(r.check(inventory or {})), None
        except Exception as exc:  # a broken rule must never kill a scan...
            # ...but it must not count as "passed" either: no results, and the error is reported so the
            # scan is marked partial and this rule's existing findings are left untouched (not resolved).
            results, error = [], f"{exc.__class__.__name__}: {str(exc)[:200]}"
        out.append(Evaluation(rule=r, results=results, error=error))
    return out


# --- helpers used by rule modules -------------------------------------------------

def find(items, key, value):
    for it in items or []:
        if it.get(key) == value:
            return it
    return None


def open_to_world(cidr):
    return cidr in ("0.0.0.0/0", "::/0", "*", "Internet", "any", "Any")


def port_in(port, start, end):
    try:
        return int(start) <= int(port) <= int(end)
    except (TypeError, ValueError):
        return False
