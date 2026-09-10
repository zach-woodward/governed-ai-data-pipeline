"""Load and validate a policy pack.

A pack is a directory of six YAML files, one per thing a compliance regime
changes, plus an optional detectors.py for detection logic that regex cannot
express. Validation is strict and happens at load: a pack that references an
unknown context field, action, obligation, or data type fails loudly here
rather than silently producing an allow the core cannot honor.
"""
from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .schema import (
    ACTIONS,
    MATCHABLE_FIELDS,
    OBLIGATION_TYPES,
    SENSITIVITIES,
    Obligation,
    Rule,
)

PACKS_DIR = Path(__file__).resolve().parent.parent.parent / "packs"

REQUIRED_FILES = (
    "pack.yaml", "detectors.yaml", "classification.yaml",
    "redaction.yaml", "routing.yaml", "rules.yaml",
)

SET_OPERATORS = frozenset({"any_of", "all_of", "none_of", "count"})


class PackError(ValueError):
    """A pack is malformed. Always raised at load time, never at decision time."""


@dataclass
class Identifier:
    id: str
    method: str            # regex | llm | python
    confidence: float
    pattern: str | None = None
    regex: re.Pattern | None = None
    hint: str = ""
    citation: str = ""
    group: int = 0         # capture group holding the value to redact
    token_entity: str = ""  # placeholder name, e.g. PATIENT -> [PATIENT_1]


@dataclass
class Pack:
    id: str
    name: str
    version: str
    root: Path
    authority: str = ""
    jurisdiction: str = "US"
    status: str = "complete"
    audit: dict[str, Any] = field(default_factory=dict)
    retention: dict[str, Any] = field(default_factory=dict)
    classifier: dict[str, Any] = field(default_factory=dict)
    data_types: dict[str, list[Identifier]] = field(default_factory=dict)
    data_type_meta: dict[str, dict[str, Any]] = field(default_factory=dict)
    levels: list[str] = field(default_factory=list)
    default_level: str = "internal"
    classification_rules: list[dict[str, Any]] = field(default_factory=list)
    redaction: dict[str, Any] = field(default_factory=dict)
    minimum_necessary: dict[str, Any] = field(default_factory=dict)
    routing: dict[str, Any] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)
    always: list[Obligation] = field(default_factory=list)
    default_decision: str = "deny"
    default_reason: str = "No rule matched; policy packs are deny-by-default."
    hooks: Any = None

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.version}"

    def identifiers_for(self, data_type: str) -> list[Identifier]:
        return self.data_types.get(data_type, [])

    def all_identifiers(self) -> list[tuple[str, Identifier]]:
        return [(dt, i) for dt, ids in self.data_types.items() for i in ids]

    def redaction_for(self, data_type: str, identifier: str) -> dict[str, Any]:
        """Most specific wins: 'PHI.ssn' overrides 'PHI'."""
        base = dict(self.redaction.get(data_type, {}))
        base.update(self.redaction.get(f"{data_type}.{identifier}", {}))
        return base


def _read(root: Path, name: str) -> dict[str, Any]:
    text = (root / name).read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise PackError(f"{root.name}/{name}: top level must be a mapping")
    return data


def _parse_obligations(raw: Any, where: str) -> list[Obligation]:
    """YAML `- redact: {…}` -> Obligation(type='redact', params={…})."""
    out: list[Obligation] = []
    for item in raw or []:
        if isinstance(item, str):
            type_, params = item, {}
        elif isinstance(item, dict) and len(item) == 1:
            type_, params = next(iter(item.items()))
            params = params or {}
            if not isinstance(params, dict):
                raise PackError(f"{where}: obligation '{type_}' params must be a mapping")
        else:
            raise PackError(f"{where}: each obligation must be a single-key mapping, got {item!r}")
        if type_ not in OBLIGATION_TYPES:
            raise PackError(
                f"{where}: unknown obligation '{type_}'. "
                f"Known: {', '.join(sorted(OBLIGATION_TYPES))}"
            )
        out.append(Obligation(type=type_, params=params))
    return out


def _validate_when(when: dict[str, Any], where: str) -> None:
    for fieldname, clause in (when or {}).items():
        if fieldname not in MATCHABLE_FIELDS:
            raise PackError(
                f"{where}: rule matches unknown field '{fieldname}'. "
                f"Known: {', '.join(sorted(MATCHABLE_FIELDS))}"
            )
        if isinstance(clause, dict):
            unknown = set(clause) - SET_OPERATORS
            if unknown:
                raise PackError(
                    f"{where}: unknown operator(s) {sorted(unknown)} on '{fieldname}'. "
                    f"Known: {', '.join(sorted(SET_OPERATORS))}"
                )
            count = clause.get("count")
            if count is not None and set(count) - {"gte", "lte"}:
                raise PackError(f"{where}: count supports only gte/lte on '{fieldname}'")
        if fieldname == "action":
            vals = clause if isinstance(clause, list) else [clause]
            bad = [v for v in vals if v not in ACTIONS]
            if bad:
                raise PackError(f"{where}: unknown action(s) {bad}. Known: {', '.join(ACTIONS)}")
        if fieldname == "sensitivity":
            vals = clause if isinstance(clause, list) else [clause]
            bad = [v for v in vals if v not in SENSITIVITIES]
            if bad:
                raise PackError(f"{where}: unknown sensitivity {bad}")


def load(pack_id: str, packs_dir: Path | None = None) -> Pack:
    root = (packs_dir or PACKS_DIR) / pack_id
    if not root.is_dir():
        raise PackError(f"no policy pack named '{pack_id}' in {packs_dir or PACKS_DIR}")
    missing = [f for f in REQUIRED_FILES if not (root / f).is_file()]
    if missing:
        raise PackError(f"pack '{pack_id}' is missing required file(s): {', '.join(missing)}")

    meta = _read(root, "pack.yaml")
    for key in ("id", "name", "version"):
        if not meta.get(key):
            raise PackError(f"{pack_id}/pack.yaml: missing '{key}'")
    if meta["id"] != pack_id:
        raise PackError(f"pack.yaml id '{meta['id']}' does not match directory '{pack_id}'")

    pack = Pack(
        id=meta["id"], name=meta["name"], version=str(meta["version"]), root=root,
        authority=meta.get("authority", ""), jurisdiction=meta.get("jurisdiction", "US"),
        status=meta.get("status", "complete"),
        audit=meta.get("audit", {}), retention=meta.get("retention", {}),
        classifier=meta.get("classifier", {}),
    )

    # ---- detectors.yaml -------------------------------------------------
    det = _read(root, "detectors.yaml")
    for dt, spec in (det.get("data_types") or {}).items():
        pack.data_type_meta[dt] = {k: v for k, v in spec.items() if k != "identifiers"}
        ids: list[Identifier] = []
        for raw in spec.get("identifiers") or []:
            ident = Identifier(
                id=raw["id"], method=raw.get("method", "regex"),
                confidence=float(raw.get("confidence", 0.5)),
                pattern=raw.get("pattern"), hint=raw.get("hint", ""),
                citation=raw.get("citation", ""), group=int(raw.get("group", 0)),
                token_entity=raw.get("token_entity", raw["id"].upper()),
            )
            if ident.method not in ("regex", "llm", "python"):
                raise PackError(f"{pack_id}/detectors.yaml: {dt}.{ident.id} has unknown method "
                                f"'{ident.method}' (regex | llm | python)")
            if ident.method == "regex":
                if not ident.pattern:
                    raise PackError(f"{pack_id}/detectors.yaml: {dt}.{ident.id} is method regex "
                                    "but has no pattern")
                try:
                    # No blanket IGNORECASE: several identifiers depend on case
                    # (a capitalized name, a two-letter state code, an uppercase
                    # VIN). Patterns opt into case-insensitivity per fragment
                    # with (?i:...) around the keyword they anchor on.
                    ident.regex = re.compile(ident.pattern, re.MULTILINE)
                except re.error as exc:
                    raise PackError(f"{pack_id}/detectors.yaml: {dt}.{ident.id} pattern "
                                    f"does not compile: {exc}") from exc
            ids.append(ident)
        pack.data_types[dt] = ids
    if not pack.data_types:
        raise PackError(f"{pack_id}/detectors.yaml: no data_types defined")

    # ---- classification.yaml -------------------------------------------
    cls = _read(root, "classification.yaml")
    pack.levels = cls.get("levels") or list(SENSITIVITIES)
    bad_levels = [l for l in pack.levels if l not in SENSITIVITIES]
    if bad_levels:
        raise PackError(f"{pack_id}/classification.yaml: unknown level(s) {bad_levels}")
    pack.default_level = cls.get("default", "internal")
    if pack.default_level not in pack.levels:
        raise PackError(f"{pack_id}/classification.yaml: default '{pack.default_level}' "
                        "is not in levels")
    pack.classification_rules = cls.get("rules") or []
    for i, r in enumerate(pack.classification_rules):
        where = f"{pack_id}/classification.yaml rule[{i}]"
        if r.get("level") not in pack.levels:
            raise PackError(f"{where}: level '{r.get('level')}' is not in levels")
        cond = r.get("if") or {}
        for key, clause in cond.items():
            if key not in ("data_types", "identifiers"):
                raise PackError(f"{where}: classification conditions may only match "
                                f"'data_types' or 'identifiers', got '{key}'")
            if isinstance(clause, dict):
                unknown = set(clause) - SET_OPERATORS
                if unknown:
                    raise PackError(f"{where}: unknown operator(s) {sorted(unknown)} "
                                    f"on '{key}'")
            names = (clause or {}).get("any_of", []) if isinstance(clause, dict) else []
            if key == "data_types":
                unknown = [n for n in names if n not in pack.data_types]
                if unknown:
                    raise PackError(f"{where}: unknown data type(s) {unknown}")

    # ---- redaction.yaml -------------------------------------------------
    red = _read(root, "redaction.yaml")
    pack.redaction = red.get("strategies") or {}
    pack.minimum_necessary = (red.get("minimum_necessary") or {}).get("profiles") or {}
    for key, spec in pack.redaction.items():
        strategy = spec.get("default")
        if strategy not in ("tokenize", "mask", "hash", "drop"):
            raise PackError(f"{pack_id}/redaction.yaml: '{key}' has unknown strategy "
                            f"'{strategy}' (tokenize | mask | hash | drop)")
        base = key.split(".")[0]
        if base not in pack.data_types:
            raise PackError(f"{pack_id}/redaction.yaml: '{key}' refers to unknown data type "
                            f"'{base}'")

    # ---- routing.yaml ---------------------------------------------------
    routing = _read(root, "routing.yaml")
    pack.routing = routing.get("requirements") or {}
    for level in pack.routing:
        if level not in SENSITIVITIES:
            raise PackError(f"{pack_id}/routing.yaml: unknown sensitivity '{level}'")

    # ---- rules.yaml -----------------------------------------------------
    rl = _read(root, "rules.yaml")
    pack.default_decision = rl.get("default", "deny")
    if pack.default_decision != "deny":
        raise PackError(f"{pack_id}/rules.yaml: default must be 'deny'. The core is "
                        "deny-by-default and packs cannot opt out.")
    pack.default_reason = rl.get("default_reason", pack.default_reason)
    pack.always = _parse_obligations(rl.get("always"), f"{pack_id}/rules.yaml always")

    seen: set[str] = set()
    for raw in rl.get("rules") or []:
        rid = raw.get("id")
        if not rid:
            raise PackError(f"{pack_id}/rules.yaml: every rule needs an id")
        if rid in seen:
            raise PackError(f"{pack_id}/rules.yaml: duplicate rule id '{rid}'")
        seen.add(rid)
        then = raw.get("then") or {}
        decision = then.get("decision")
        if decision not in ("allow", "deny"):
            raise PackError(f"{pack_id}/rules.yaml {rid}: decision must be allow or deny")
        where = f"{pack_id}/rules.yaml {rid}"
        _validate_when(raw.get("when") or {}, where)
        obligations = _parse_obligations(then.get("obligations"), where)
        if decision == "deny" and obligations:
            raise PackError(f"{where}: a deny rule cannot carry obligations")
        pack.rules.append(Rule(
            id=rid, decision=decision, description=raw.get("description", ""),
            citation=raw.get("citation", ""), when=raw.get("when") or {},
            obligations=obligations,
        ))
    if not pack.rules:
        raise PackError(f"{pack_id}/rules.yaml: no rules defined (everything would be denied)")

    # ---- optional detectors.py -----------------------------------------
    hook_path = root / "detectors.py"
    if hook_path.is_file():
        spec = importlib.util.spec_from_file_location(f"govpipe_pack_{pack_id}", hook_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pack.hooks = module

    return pack


def available(packs_dir: Path | None = None) -> list[str]:
    root = packs_dir or PACKS_DIR
    return sorted(p.name for p in root.iterdir() if p.is_dir() and (p / "pack.yaml").is_file())
