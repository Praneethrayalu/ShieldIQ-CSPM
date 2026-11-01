"""IAM policy-language primitives with three-valued (Kleene) logic.

Every predicate here answers True (matches), False (does not match) or None (UNKNOWN: ShieldIQ cannot decide
from the data it has - a policy variable with no value, a condition key absent from an incomplete request
context, an unsupported condition operator, NotPrincipal, ...). UNKNOWN is never silently folded into True or
False; the evaluator turns it into an *Indeterminate* decision.

Implemented (from the AWS IAM policy reference):
- Action / NotAction with `*` and `?` wildcards, case-insensitive (service prefixes and action names are not
  case-sensitive in AWS).
- Resource / NotResource ARN matching with `*` / `?` wildcards (case-sensitive) and policy variables
  (${aws:username}, ${aws:PrincipalTag/...}, ${*}, ${?}, ${$}; a variable with no known value -> UNKNOWN).
- Condition blocks: AND across operators and keys, OR across a key's values, negated operators, `...IfExists`,
  `ForAnyValue:` / `ForAllValues:` set operators, `Null`. Supported operator families: String*, Numeric*,
  Date*, Bool, IpAddress / NotIpAddress, Arn*. Anything else (e.g. BinaryEquals) -> UNKNOWN.
- Missing condition keys: when the request context is declared *complete*, AWS semantics apply (missing key ->
  the condition is false, except negated operators / IfExists / ForAllValues, which are true). When the context
  is *incomplete* (the default for a scan: ShieldIQ does not know the caller's IP, MFA state, tags, ...),
  a missing key is UNKNOWN.
"""
import ipaddress
import re
from datetime import datetime, timezone

UNKNOWN = None


# ------------------------------------------------------------------ three-valued logic
def t_and(*vals):
    if any(v is False for v in vals):
        return False
    if any(v is None for v in vals):
        return None
    return True


def t_or(*vals):
    if any(v is True for v in vals):
        return True
    if any(v is None for v in vals):
        return None
    return False


def t_not(v):
    return None if v is None else (not v)


def as_list(v):
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return list(v)
    return [v]


def statements(doc):
    st = (doc or {}).get("Statement", []) if isinstance(doc, dict) else []
    return [st] if isinstance(st, dict) else [s for s in st if isinstance(s, dict)]


# ------------------------------------------------------------------ wildcard matching
_RE_CACHE = {}


def _wild_re(pattern, ignore_case):
    key = (pattern, ignore_case)
    if key not in _RE_CACHE:
        out = []
        for ch in pattern:
            out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        _RE_CACHE[key] = re.compile("^" + "".join(out) + "$", re.S | (re.I if ignore_case else 0))
    return _RE_CACHE[key]


def wild_match(pattern, value, ignore_case=False):
    return bool(_wild_re(str(pattern), ignore_case).match(str(value)))


def action_matches(pattern, action):
    return wild_match(pattern, action, ignore_case=True)


def stmt_matches_action(stmt, action):
    """Definite (bool): does the statement's Action / NotAction cover `action`?"""
    if "Action" in stmt:
        return any(action_matches(p, action) for p in as_list(stmt["Action"]))
    if "NotAction" in stmt:
        return not any(action_matches(p, action) for p in as_list(stmt["NotAction"]))
    return False


# ------------------------------------------------------------------ policy variables
_VAR = re.compile(r"\$\{([^}]*)\}")
_LITERALS = {"*": "\x00STAR\x00", "?": "\x00QM\x00", "$": "$"}


def resolve_variables(pattern, ctx):
    """Substitute ${...} variables. Returns (text, missing_variable_names). Literal ${*} ${?} ${$} are kept as
    placeholders that wild_match treats as literal characters (handled by _literalize)."""
    missing = []

    def sub(m):
        name = m.group(1)
        if name in _LITERALS:
            return _LITERALS[name]
        v = ctx.get(name) if ctx is not None else None
        if v is None or isinstance(v, (list, tuple)):
            missing.append(name)
            return "\x00VAR\x00"
        return str(v)
    return _VAR.sub(sub, str(pattern)), missing


def _pattern_match(pattern, value, ctx, ignore_case=False):
    """Tri-state wildcard match of `value` against a policy pattern that may contain variables."""
    text, missing = resolve_variables(pattern, ctx)
    if missing:
        # unknown variable value: it could match (treat the variable as a wildcard) or not
        loose = text.replace("\x00VAR\x00", "*")
        loose = loose.replace(_LITERALS["*"], "*").replace(_LITERALS["?"], "?")
        return None if wild_match(loose, value, ignore_case) else False
    if _LITERALS["*"] in text or _LITERALS["?"] in text:
        # literal * / ? from ${*} ${?}: escape them by splitting
        parts = re.split("(\x00STAR\x00|\x00QM\x00)", text)
        rx = "".join(re.escape("*") if p == _LITERALS["*"] else re.escape("?") if p == _LITERALS["?"]
                     else _wild_re(p, ignore_case).pattern[1:-1] for p in parts)
        return bool(re.match("^" + rx + "$", str(value), re.S | (re.I if ignore_case else 0)))
    return wild_match(text, value, ignore_case)


def stmt_matches_resource(stmt, resource, ctx):
    """Tri-state: Resource / NotResource vs one resource ARN. A statement with neither applies to the resource
    the policy is attached to (resource-based / trust policies) -> True."""
    if "Resource" in stmt:
        return t_or(*[_pattern_match(p, resource, ctx) for p in as_list(stmt["Resource"])] or [False])
    if "NotResource" in stmt:
        return t_not(t_or(*[_pattern_match(p, resource, ctx) for p in as_list(stmt["NotResource"])] or [False]))
    return True


# ------------------------------------------------------------------ principals (resource-based / trust policies)
def principal_match(stmt, principal_arn, account_id, service=None):
    """For resource-based statements. Returns (tri, kind): kind 'direct' (the principal's own ARN or '*'),
    'account' (the account root: the account delegates, so the caller's identity policy must also allow),
    'service' (a service principal), or None."""
    if "NotPrincipal" in stmt:
        return None, "notprincipal-unsupported"
    p = stmt.get("Principal")
    if p is None:
        return False, None
    if p == "*":
        return True, "direct"
    if not isinstance(p, dict):
        return False, None
    if service is not None:
        return (True, "service") if service in as_list(p.get("Service")) else (False, None)
    for a in as_list(p.get("AWS")):
        a = str(a)
        if a == "*" or a == principal_arn:
            return True, "direct"
        if account_id and a in (account_id, f"arn:aws:iam::{account_id}:root"):
            return True, "account"
        if "*" in a and wild_match(a, principal_arn):  # wildcards are only valid with '*' alone, but be safe
            return None, "wildcard-principal"
    return False, None


# ------------------------------------------------------------------ request context + conditions
class RequestContext:
    """Condition-key values for an evaluation. complete=False (default): keys not given are UNKNOWN."""

    def __init__(self, values=None, complete=False):
        self.values = {}
        for k, v in (values or {}).items():
            self.values[k.lower()] = v
        self.complete = complete

    def get(self, key):
        return self.values.get(str(key).lower())

    def has(self, key):
        return str(key).lower() in self.values

    def to_dict(self):
        return {"values": self.values, "complete": self.complete}


_NEGATED = {"StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike", "NumericNotEquals", "DateNotEquals",
            "NotIpAddress", "ArnNotEquals", "ArnNotLike"}
_BASE_OPS = {"StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
             "StringLike", "StringNotLike", "NumericEquals", "NumericNotEquals", "NumericLessThan",
             "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals",
             "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals",
             "Bool", "IpAddress", "NotIpAddress", "ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike", "Null"}


def _parse_date(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    s = str(v)
    if re.fullmatch(r"\d+(\.\d+)?", s):
        return datetime.fromtimestamp(float(s), tz=timezone.utc)
    s = s.replace("Z", "+00:00")
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _cmp_one(base, req, pol, ctx):
    """Positive form of one comparison (negation is applied by the caller). Tri-state."""
    if base in ("StringEquals", "StringNotEquals"):
        text, miss = resolve_variables(pol, ctx)
        return None if miss else str(req) == text
    if base in ("StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase"):
        text, miss = resolve_variables(pol, ctx)
        return None if miss else str(req).lower() == text.lower()
    if base in ("StringLike", "StringNotLike"):
        return _pattern_match(pol, req, ctx)
    if base in ("ArnEquals", "ArnLike", "ArnNotEquals", "ArnNotLike"):
        return _pattern_match(pol, req, ctx)
    if base.startswith("Numeric"):
        a, b = float(req), float(pol)
        op = base.replace("NumericNot", "Numeric")
        return {"NumericEquals": a == b, "NumericLessThan": a < b, "NumericLessThanEquals": a <= b,
                "NumericGreaterThan": a > b, "NumericGreaterThanEquals": a >= b}[op]
    if base.startswith("Date"):
        a, b = _parse_date(req), _parse_date(pol)
        op = base.replace("DateNot", "Date")
        return {"DateEquals": a == b, "DateLessThan": a < b, "DateLessThanEquals": a <= b,
                "DateGreaterThan": a > b, "DateGreaterThanEquals": a >= b}[op]
    if base == "Bool":
        return str(req).lower() == str(pol).lower()
    if base in ("IpAddress", "NotIpAddress"):
        return ipaddress.ip_address(str(req)) in ipaddress.ip_network(str(pol), strict=False)
    raise ValueError(base)


def eval_condition_entry(op, key, policy_values, ctx):
    """Returns (tri, note-or-None) for one operator/key pair."""
    set_op = None
    if ":" in op:
        set_op, op = op.split(":", 1)
        if set_op not in ("ForAnyValue", "ForAllValues"):
            return None, f"unsupported set operator {set_op}"
    if_exists = op.endswith("IfExists") and op != "IfExists"
    base = op[:-8] if if_exists else op
    if base not in _BASE_OPS:
        return None, f"unsupported condition operator {op}"
    pvals = as_list(policy_values)
    present = ctx.has(key)
    if base == "Null":
        if not present:
            return (None, f"condition key {key} not in request context") if not ctx.complete else \
                (any(str(v).lower() == "true" for v in pvals), None)
        return any(str(v).lower() == "false" for v in pvals), None
    if not present:
        if not ctx.complete:
            return None, f"condition key {key} not in request context"
        if if_exists or set_op == "ForAllValues" or base in _NEGATED:
            return True, None
        return False, None
    rvals = as_list(ctx.get(key))
    negated = base in _NEGATED
    try:
        def match_req(rv):
            return t_or(*[_cmp_one(base, rv, pv, ctx) for pv in pvals] or [False])
        if set_op == "ForAllValues":
            res = t_and(*[match_req(rv) for rv in rvals]) if rvals else True
        else:  # ForAnyValue, or a single-valued operator (any request value)
            res = t_or(*[match_req(rv) for rv in rvals] or [False])
    except (ValueError, TypeError, KeyError) as exc:
        return None, f"cannot evaluate {op} on {key}: {exc.__class__.__name__}"
    return (t_not(res) if negated else res), None


def eval_conditions(cond, ctx):
    """AND across every operator/key in a Condition block. Returns (tri, [notes])."""
    if not cond:
        return True, []
    results, notes = [], []
    if not isinstance(cond, dict):
        return None, ["malformed Condition block"]
    for op, kv in cond.items():
        if not isinstance(kv, dict):
            results.append(None)
            notes.append(f"malformed condition {op}")
            continue
        for key, vals in kv.items():
            r, note = eval_condition_entry(op, key, vals, ctx)
            results.append(r)
            if note:
                notes.append(note)
    return t_and(*results), notes
