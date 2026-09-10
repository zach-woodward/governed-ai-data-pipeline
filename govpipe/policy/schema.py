"""Types shared between the policy packs (YAML) and the engine.

These dataclasses are the contract between the regime-agnostic core and any
policy pack. A pack may add data; it may not change these shapes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Actions the pipeline knows how to perform. Packs constrain them; they do
# not invent new ones, because the core has to know how to carry each out.
ACTIONS = ("classify", "summarize", "extract", "release", "export")

SENSITIVITIES = ("public", "internal", "restricted", "prohibited")


@dataclass
class Subject:
    """Who is asking, and why. Purpose of use is a first-class input: the
    same person reading the same record for treatment vs. marketing is a
    different decision under most regimes."""
    id: str = "unknown"
    roles: list[str] = field(default_factory=list)
    purpose_of_use: str = "unspecified"


@dataclass
class Resource:
    doc_ids: list[str] = field(default_factory=list)
    sensitivity: str = "internal"
    data_types: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    jurisdiction: str = "US"


@dataclass
class Target:
    """The model a call would go to, plus the contractual facts about it that
    a regime cares about. Sourced from config/models.yaml, not from a pack."""
    key: str
    model_id: str
    provider: str = "anthropic"
    display: str = ""
    baa: bool = False
    zero_retention: bool = False
    residency: list[str] = field(default_factory=lambda: ["US"])
    offline: bool = False


@dataclass
class Context:
    action: str
    subject: Subject = field(default_factory=Subject)
    resource: Resource = field(default_factory=Resource)
    target: Target | None = None

    def flatten(self) -> dict[str, Any]:
        """The complete set of fields a rule may match on. Anything a pack
        references outside these keys fails pack validation at load time."""
        flat: dict[str, Any] = {
            "action": self.action,
            "subject.id": self.subject.id,
            "subject.roles": self.subject.roles,
            "subject.purpose_of_use": self.subject.purpose_of_use,
            "sensitivity": self.resource.sensitivity,
            "data_types": self.resource.data_types,
            "identifiers": self.resource.identifiers,
            "jurisdiction": self.resource.jurisdiction,
            "target.key": None,
            "target.model_id": None,
            "target.provider": None,
            "target.baa": None,
            "target.zero_retention": None,
            "target.residency": None,
        }
        if self.target is not None:
            flat.update({
                "target.key": self.target.key,
                "target.model_id": self.target.model_id,
                "target.provider": self.target.provider,
                "target.baa": self.target.baa,
                "target.zero_retention": self.target.zero_retention,
                "target.residency": self.target.residency,
            })
        return flat


MATCHABLE_FIELDS = frozenset(Context(action="classify").flatten().keys())
SET_FIELDS = frozenset({"subject.roles", "data_types", "identifiers", "target.residency"})


@dataclass
class Obligation:
    """A condition attached to an `allow`. The gateway must discharge every
    obligation or the call fails closed and is recorded as a deny."""
    type: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"type": self.type, **self.params}

    def __str__(self) -> str:
        if not self.params:
            return self.type
        inner = ", ".join(f"{k}={v}" for k, v in sorted(self.params.items()))
        return f"{self.type}({inner})"


@dataclass
class Rule:
    id: str
    decision: str                      # allow | deny
    description: str = ""
    citation: str = ""
    when: dict[str, Any] = field(default_factory=dict)
    obligations: list[Obligation] = field(default_factory=list)


@dataclass
class Decision:
    allowed: bool
    rule_id: str
    reason: str
    obligations: list[Obligation] = field(default_factory=list)
    citation: str = ""
    trace: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        return "allow" if self.allowed else "deny"

    def obligations_json(self) -> list[dict[str, Any]]:
        return [o.to_json() for o in self.obligations]

    def obligation(self, type_: str) -> Obligation | None:
        for o in self.obligations:
            if o.type == type_:
                return o
        return None


# Obligation types the gateway knows how to discharge. A pack that names an
# obligation outside this set fails validation at load time rather than
# producing an "allow" the core would silently ignore.
OBLIGATION_TYPES = frozenset({
    "redact",              # tokenize/mask/drop detected entities before the call
    "minimum_necessary",   # apply a named field-reduction profile
    "retain",              # set retention clocks on prompt/output
    "audit",               # audit detail level: full | summary
    "approve",             # route to a human review queue before release
    "residency",           # require inference in a named geography
    "worm",                # write-once retention for the output
    "supervise",           # copy to a supervisory review queue (post hoc)
})
