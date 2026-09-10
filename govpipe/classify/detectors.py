"""Pass one: pattern detection, driven entirely by the pack's detectors.yaml.

The core knows how to run a regex and how to resolve overlaps. It knows
nothing about what PHI or CUI is - that is the pack's job.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..policy.pack import Identifier, Pack


@dataclass
class Detection:
    data_type: str
    identifier: str
    method: str          # regex | llm | python
    confidence: float
    start: int
    end: int
    value: str
    token_entity: str = ""
    citation: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def value_hash(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()

    @property
    def length(self) -> int:
        return self.end - self.start

    def key(self) -> tuple[str, str]:
        return (self.data_type, self.identifier)


def _span(match, ident: Identifier) -> tuple[int, int, str]:
    """Honor the identifier's capture group so a label like 'MRN:' is not
    itself redacted - only the value is."""
    if ident.group and ident.group <= (match.re.groups or 0) and match.group(ident.group):
        return match.start(ident.group), match.end(ident.group), match.group(ident.group)
    return match.start(), match.end(), match.group(0)


def resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Two patterns can claim the same characters. Keep the more confident
    one, then the longer one, then the earlier one - deterministic, so the
    same document always classifies the same way."""
    ordered = sorted(detections, key=lambda d: (-d.confidence, -d.length, d.start))
    kept: list[Detection] = []
    for d in ordered:
        if any(d.start < k.end and k.start < d.end for k in kept):
            continue
        kept.append(d)
    return sorted(kept, key=lambda d: d.start)


def scan(pack: Pack, text: str) -> list[Detection]:
    """Run every regex identifier in the pack over the text."""
    found: list[Detection] = []
    for data_type, identifiers in pack.data_types.items():
        for ident in identifiers:
            if ident.method != "regex" or ident.regex is None:
                continue
            for match in ident.regex.finditer(text):
                start, end, value = _span(match, ident)
                if not value.strip():
                    continue
                found.append(Detection(
                    data_type=data_type, identifier=ident.id, method="regex",
                    confidence=ident.confidence, start=start, end=end,
                    value=value, token_entity=ident.token_entity,
                    citation=ident.citation,
                ))
    # Pack-supplied Python detectors for anything regex cannot express.
    if pack.hooks is not None and hasattr(pack.hooks, "detect"):
        for d in pack.hooks.detect(text) or []:
            found.append(d)
    return resolve_overlaps(found)


def summarize(detections: list[Detection]) -> dict[str, Any]:
    data_types = sorted({d.data_type for d in detections})
    identifiers = sorted({d.identifier for d in detections})
    methods: dict[str, str] = {}
    for d in detections:
        # If both passes found the same identifier, record that honestly.
        prior = methods.get(d.identifier)
        methods[d.identifier] = "regex+llm" if prior and prior != d.method else d.method
    return {
        "data_types": data_types,
        "identifiers": identifiers,
        "methods": methods,
        "count": len(detections),
    }
