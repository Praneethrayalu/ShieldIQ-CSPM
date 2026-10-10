"""Policy engine.

Collectors turn a cloud account / repo / cluster / file into a normalized
*inventory* (plain dict). Rules are small Python functions that look at the
inventory and yield one CheckResult per resource they evaluated. Because live
data, demo data, uploaded snapshots and Terraform files all become the same
inventory shape, every rule works on all of them.
"""
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
    def iac_label(self):
        return self.IAC_LABELS.get(self.iac_kind, "IaC")

    def render(self, text: str, resource_id: str) -> str:
        short = resource_id.split("/")[-1]
        return (text or "").replace("{resource}", short).replace("{resource_id}", resource_id)


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

    @property
    def failed(self):
        return [r for r in self.results if not r.passed]


def evaluate(provider: str, inventory: dict) -> List[Evaluation]:
    out = []
    for r in rules_for(provider):
        try:
            results = list(r.check(inventory or {}))
        except Exception as exc:  # a broken rule must never kill a scan
            results = [CheckResult(resource_id="rule-error", passed=True, detail=f"rule error: {exc}")]
        out.append(Evaluation(rule=r, results=results))
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
