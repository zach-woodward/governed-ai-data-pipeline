"""Deployment configuration: where things live, and what models exist.

Everything here is a fact about this installation. Everything a compliance
regime cares about lives in a policy pack instead.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

from .policy.schema import Target

ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = ROOT / "packs"
DATA_DIR = ROOT / "data"
LANDING_DIR = DATA_DIR / "landing"
SAMPLES_DIR = DATA_DIR / "samples"
DB_PATH = Path(os.environ.get("GOVPIPE_DB", ROOT / "var" / "govpipe.db"))
MODELS_FILE = ROOT / "config" / "models.yaml"

DEFAULT_PACK = "hipaa"


class ConfigError(ValueError):
    pass


def _models_doc() -> dict:
    return yaml.safe_load(MODELS_FILE.read_text(encoding="utf-8")) or {}


def load_targets() -> dict[str, Target]:
    doc = _models_doc()
    targets: dict[str, Target] = {}
    for key, spec in (doc.get("models") or {}).items():
        missing = [f for f in ("model_id", "provider") if f not in spec]
        if missing:
            raise ConfigError(f"config/models.yaml: '{key}' is missing {missing}")
        targets[key] = Target(
            key=key,
            model_id=spec["model_id"],
            provider=spec["provider"],
            display=spec.get("display", key),
            baa=bool(spec.get("baa", False)),
            zero_retention=bool(spec.get("zero_retention", False)),
            residency=list(spec.get("residency") or ["US"]),
            offline=bool(spec.get("offline", False)),
        )
    if not targets:
        raise ConfigError("config/models.yaml defines no models")
    return targets


def get_target(key: str | None = None) -> Target:
    targets = load_targets()
    if key is None:
        key = _models_doc().get("default_target") or next(iter(targets))
    if key not in targets:
        raise ConfigError(
            f"unknown model target '{key}'. Known: {', '.join(sorted(targets))}"
        )
    return targets[key]
