"""Obligation dischargers.

A policy decision is binary. Everything else a regime demands - redaction,
minimum necessary, retention, residency, human approval, WORM, supervisory
review - is an *obligation* attached to an allow. This module is the complete
list of obligations the pipeline knows how to carry out, and the order it
carries them out in.

If an obligation cannot be discharged, the discharger raises and the gateway
converts the allow into a deny. That is the property the design rests on, so
every function here is written to fail loudly rather than partially succeed.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from . import approvals, redact
from .policy import Obligation, Target

SECTION_RE = re.compile(r"^\s*([A-Z][A-Z0-9 /&_-]{2,}):\s*$", re.MULTILINE)


class ObligationError(RuntimeError):
    """An obligation could not be discharged. Converts the allow into a deny."""


# --------------------------------------------------------------------------
# Obligation dischargers. Each mutates `state` and may raise ObligationError.
# --------------------------------------------------------------------------

def _discharge_redact(state: dict, ob: Obligation, ctx: dict) -> None:
    types = ob.params.get("types")
    all_detections = [d for doc in ctx["docs"] for d in doc.detections]
    if not all_detections:
        state["redaction"] = {"applied": False, "reason": "nothing detected to redact"}
        return
    for doc in ctx["docs"]:
        # Detection spans are offsets into the document as classified. If an
        # earlier obligation has already rewritten the text, those offsets
        # point at the wrong characters and redaction would silently miss.
        # Fail closed rather than redact the wrong bytes.
        if state["doc_texts"][doc.doc_id] != doc.text:
            raise ObligationError(
                f"redaction must run before any obligation that rewrites text; "
                f"'{doc.doc_id}' was already modified, so detection offsets are stale"
            )
    texts, results = redact.apply_all(ctx["conn"], ctx["pack"], ctx["docs"],
                                      data_types=types)
    summaries = [r.summary() for r in results]
    state["doc_texts"] = texts
    combined: dict[str, Any] = {"applied": any(s["applied"] for s in summaries),
                                "strategies": {}, "by_identifier": {}, "tokens_issued": 0}
    for s in summaries:
        for k, v in s["strategies"].items():
            combined["strategies"][k] = combined["strategies"].get(k, 0) + v
        combined["by_identifier"].update(s["by_identifier"])
        combined["tokens_issued"] += s["tokens_issued"]
    state["redaction"] = combined


def _drop_sections(text: str, drop: list[str]) -> str:
    """Remove whole labelled sections. Sample documents use ALL-CAPS headers;
    a real deployment would key off structured fields instead."""
    if not drop:
        return text
    headers = [(m.start(), m.end(), m.group(1)) for m in SECTION_RE.finditer(text)]
    if not headers:
        return text
    keep_parts, cursor = [], 0
    for i, (start, end, name) in enumerate(headers):
        section_end = headers[i + 1][0] if i + 1 < len(headers) else len(text)
        lowered = name.lower()
        if any(term in lowered for term in drop):
            keep_parts.append(text[cursor:start])
            keep_parts.append(f"{name}: [WITHHELD - minimum necessary]\n\n")
            cursor = section_end
    keep_parts.append(text[cursor:])
    return "".join(keep_parts)


def _discharge_minimum_necessary(state: dict, ob: Obligation, ctx: dict) -> None:
    name = ob.params.get("profile")
    profile = ctx["pack"].minimum_necessary.get(name)
    if profile is None:
        raise ObligationError(
            f"policy requires minimum-necessary profile '{name}', which "
            f"{ctx['pack'].ref} does not define"
        )
    drop = [s.lower() for s in profile.get("drop_sections", [])]
    state["doc_texts"] = {
        doc_id: _drop_sections(text, drop)
        for doc_id, text in state["doc_texts"].items()
    }
    state["minimum_necessary"] = {"profile": name, "dropped": drop}


def _discharge_retain(state: dict, ob: Obligation, ctx: dict) -> None:
    state["retention"] = {
        "prompt_days": ob.params.get("prompt_days", ctx["pack"].retention.get("default_prompt_days")),
        "output_days": ob.params.get("output_days", ctx["pack"].retention.get("default_output_days")),
    }


def _discharge_audit(state: dict, ob: Obligation, ctx: dict) -> None:
    level = ob.params.get("level", "summary")
    if level not in ("full", "summary"):
        raise ObligationError(f"unknown audit level '{level}'")
    state["audit_level"] = level


def _discharge_residency(state: dict, ob: Obligation, ctx: dict) -> None:
    allowed = set(ob.params.get("allowed") or [])
    target: Target | None = ctx["target"]
    if target is None or not allowed:
        return
    excess = set(target.residency) - allowed
    if excess:
        raise ObligationError(
            f"policy requires inference within {sorted(allowed)}; target "
            f"'{target.key}' may process in {sorted(excess)}"
        )
    state["residency"] = sorted(allowed)


def _discharge_approve(state: dict, ob: Obligation, ctx: dict) -> None:
    """Blocking. Either an approved decision already exists, or one is created
    and the request stops here."""
    existing = ctx.get("approval_id")
    if existing:
        record = approvals.get(ctx["conn"], existing)
        if record is None:
            raise ObligationError(f"approval '{existing}' does not exist")
        if record["status"] != "approved":
            raise ObligationError(
                f"approval '{existing}' is {record['status']}, not approved"
            )
        state["approval_id"] = existing
        return
    state["needs_approval"] = {
        "queue": ob.params.get("queue", "default"),
        "roles": ob.params.get("roles", []),
    }


def _discharge_worm(state: dict, ob: Obligation, ctx: dict) -> None:
    state["worm"] = True


def _discharge_supervise(state: dict, ob: Obligation, ctx: dict) -> None:
    """Non-blocking: the item is queued for review after the fact."""
    state["supervise"] = {"queue": ob.params.get("queue", "supervision")}


# Obligations are discharged in this order, not in the order a pack happens to
# list them. The ordering carries real constraints:
#   - `approve` blocks early, before any work is done on data that may never
#     be released;
#   - `redact` must run before `minimum_necessary`, because detection spans
#     are offsets into the document as classified and section removal
#     invalidates them.
# An obligation type missing from this list is a programming error and is
# caught below rather than silently skipped.
DISCHARGE_ORDER = (
    "audit", "residency", "approve", "redact", "minimum_necessary",
    "retain", "worm", "supervise",
)

DISCHARGERS: dict[str, Callable[[dict, Obligation, dict], None]] = {
    "redact": _discharge_redact,
    "minimum_necessary": _discharge_minimum_necessary,
    "retain": _discharge_retain,
    "audit": _discharge_audit,
    "residency": _discharge_residency,
    "approve": _discharge_approve,
    "worm": _discharge_worm,
    "supervise": _discharge_supervise,
}


def discharge_all(state: dict, obligations: list[Obligation], ctx: dict) -> None:
    """Discharge every obligation in DISCHARGE_ORDER, mutating `state`.

    Raises ObligationError on the first one that cannot be met. The caller is
    responsible for turning that into a logged deny - this function never
    decides to proceed anyway.
    """
    ordered = sorted(
        obligations,
        key=lambda o: (DISCHARGE_ORDER.index(o.type) if o.type in DISCHARGE_ORDER
                       else len(DISCHARGE_ORDER)),
    )
    for ob in ordered:
        handler = DISCHARGERS.get(ob.type)
        if handler is None or ob.type not in DISCHARGE_ORDER:
            raise ObligationError(
                f"no discharge order defined for obligation '{ob.type}'; refusing to proceed"
            )
        try:
            handler(state, ob, ctx)
        except ObligationError:
            state["failed_obligation"] = ob.type
            raise
