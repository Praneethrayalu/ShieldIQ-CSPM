"""Collectors turn real sources into normalized inventories for the policy engine."""
import copy
import json
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_data"
PROVIDERS = {
    "aws": {"label": "Amazon Web Services", "short": "AWS", "live": True},
    "gcp": {"label": "Google Cloud", "short": "GCP", "live": False},
    "azure": {"label": "Microsoft Azure", "short": "Azure", "live": False},
    "github": {"label": "GitHub", "short": "GitHub", "live": True},
    "slack": {"label": "Slack", "short": "Slack", "live": False},
    "kubernetes": {"label": "Kubernetes", "short": "K8s", "live": False},
    "code": {"label": "Source code", "short": "Code", "live": False},
}


class CollectorError(Exception):
    """A clean, user-facing collection error (bad credentials, missing library, API refusal)."""


def demo_inventory(provider: str) -> dict:
    path = SAMPLE_DIR / f"{provider}_demo.json"
    if not path.exists():
        raise CollectorError(f"No demo data for provider '{provider}'")
    return json.loads(path.read_text())


def validate_snapshot(provider: str, data) -> dict:
    """Validate an uploaded inventory snapshot (JSON) before storing it."""
    if not isinstance(data, dict):
        raise CollectorError("Snapshot must be a JSON object")
    expected = set(demo_inventory(provider).keys())
    known = set(data.keys()) & expected
    if not known:
        raise CollectorError(f"Snapshot has none of the expected {provider} keys: {', '.join(sorted(expected))}")
    for k, v in data.items():
        if k in expected and isinstance(demo_inventory(provider)[k], list) and not isinstance(v, list):
            raise CollectorError(f"Snapshot key '{k}' must be a list")
    return copy.deepcopy(data)
