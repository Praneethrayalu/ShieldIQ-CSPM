"""Bridges the rule engine and the IAM effective-permission engine (shieldiq/iam).

- `analyzer_for(inv)`: one AuthzModel + Analyzer per inventory object (cached for the duration of a scan).
- `restriction(inv, principal_name, kind, actions)`: whether a permissions boundary, an SCP or an explicit Deny
  blocks an action *everywhere* (sound, action-level test used by AWS-IAM-005 to drop false positives), or whether
  those layers are unknown (the finding is then labelled unconfirmed, never dropped).
- AWS-IAM-007: evidence-based privilege-escalation paths (Secure / Finding / Unknown).
"""
from ..iam.analysis import Analyzer
from ..iam.model import build_model
from ..iam.policy import as_list, statements, stmt_matches_action

_CACHE = {}


def analyzer_for(inv):
    key = id(inv)
    hit = _CACHE.get(key)
    if hit is not None and hit[0] is inv:
        return hit[1]
    an = Analyzer(build_model(inv))
    _CACHE.clear()  # keep one: inventories are evaluated one at a time
    _CACHE[key] = (inv, an)
    return an


def _blocks(refs, action):
    """True if these layer documents certainly block `action` on every resource: no Allow statement covers the
    action at all, or an unconditional Deny on Resource "*" covers it. None if any document is unreadable."""
    allow, deny = False, False
    for r in refs:
        if r.document is None:
            return None
        for st in statements(r.document):
            if not stmt_matches_action(st, action):
                continue
            eff = str(st.get("Effect", "")).lower()
            if eff == "allow":
                allow = True
            elif eff == "deny" and not st.get("Condition") and "*" in as_list(st.get("Resource")) \
                    and "NotResource" not in st:
                deny = True
    return deny or not allow


def restriction(inv, kind, name, actions):
    """-> {"blocked": [(action, layer)], "unknown_layers": [...]}"""
    an = analyzer_for(inv)
    p = an.m.get(kind, name)
    out = {"blocked": [], "unknown_layers": [], "admin": None}
    if p is not None:
        adm, ds = an.admin(p)
        why = next((d.reason for d in ds if d.decision == "Denied"), None)
        out["admin"] = {"decision": adm, "reason": why}
    if p is None:
        out["unknown_layers"].append("principal not in the authorization model")
        return out
    if p.boundary_status == "unknown":
        out["unknown_layers"].append("permissions boundary")
    scp = an.m.scp or {}
    if not p.service_linked and scp.get("status") in ("unknown", "unavailable", None):
        out["unknown_layers"].append("SCPs")
    for a in actions:
        if p.boundary_status == "present" and p.boundary is not None:
            if _blocks([p.boundary], a) is True:
                out["blocked"].append((a, f"permissions boundary {p.boundary.name}"))
                continue
            if _blocks([p.boundary], a) is None and "permissions boundary document" not in out["unknown_layers"]:
                out["unknown_layers"].append("permissions boundary document")
        if scp.get("status") == "collected" and not p.service_linked:
            from ..iam.model import PolicyRef
            hit = None
            for lvl in scp.get("levels") or []:
                refs = [PolicyRef(x.get("name"), x.get("arn"), "scp", "scp", x.get("document")) for x in lvl.get("policies") or []]
                if refs and _blocks(refs, a) is True:
                    hit = f"SCP at {lvl.get('target')}"
                    break
            if hit:
                out["blocked"].append((a, hit))
    return out
