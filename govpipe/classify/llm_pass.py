"""Pass two: LLM-assisted classification.

This pass is itself a governed model call. It goes through the same gateway
as everything else, on a pattern-redacted copy of the text, under whatever
rule the pack has written for `action: classify` - which in the HIPAA pack is
HIPAA-005. If the pattern pass already classified the document as prohibited,
the deny rules fire first and this pass never runs. That ordering is the
answer to the obvious objection: an LLM classifier is a data egress, so it
has to be governed like one.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from .. import gateway
from ..policy import Pack, Subject, Target
from .detectors import Detection

SYSTEM = (
    "You are a data classification assistant inside a compliance boundary. "
    "You identify categories of sensitive information in a document. Some "
    "values have already been replaced with tokens like [PATIENT_1] by a "
    "pattern-matching pass - treat a token as confirmation that an identifier "
    "of that kind is present. Report only what the document actually contains. "
    "Do not guess, do not infer identifiers from the document's general topic, "
    "and never invent evidence text."
)

SCHEMA = {
    "type": "object",
    "properties": {
        "detections": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "data_type": {"type": "string"},
                    "identifier": {"type": "string"},
                    "evidence": {
                        "type": "string",
                        "description": "Exact substring copied from the document.",
                    },
                    "confidence": {"type": "number"},
                    "rationale": {"type": "string"},
                },
                "required": ["data_type", "identifier", "evidence", "confidence", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["detections"],
    "additionalProperties": False,
}


def _catalogue(pack: Pack) -> tuple[str, dict[tuple[str, str], Any]]:
    """Only identifiers the pack marked `method: llm` are on offer. The model
    is not asked to re-do the regex pass' job."""
    lines, index = [], {}
    for data_type, identifiers in pack.data_types.items():
        for ident in identifiers:
            if ident.method != "llm":
                continue
            index[(data_type, ident.id)] = ident
            hint = " ".join((ident.hint or "").split())
            lines.append(f"- data_type={data_type} identifier={ident.id}: {hint}")
    return "\n".join(lines), index


def run(
    conn: sqlite3.Connection,
    pack: Pack,
    *,
    session_id: str,
    doc: gateway.Doc,
    subject: Subject,
    target: Target,
) -> tuple[list[Detection], dict[str, Any]]:
    """Returns (detections, status). Never raises: a classifier that cannot
    run must not stop ingestion, it must be recorded as not having run."""
    catalogue, index = _catalogue(pack)
    if not catalogue:
        return [], {"status": "skipped", "reason": "pack defines no llm identifiers"}
    if not pack.classifier.get("llm_pass", False):
        return [], {"status": "skipped", "reason": "pack disables the llm pass"}
    if target.offline:
        return [], {"status": "skipped",
                    "reason": f"target '{target.key}' is offline; no model available"}

    max_chars = int(pack.classifier.get("max_chars", 12000))
    truncated = len(doc.text) > max_chars
    excerpt = gateway.Doc(
        doc_id=doc.doc_id, text=doc.text[:max_chars], sensitivity=doc.sensitivity,
        data_types=doc.data_types, identifiers=doc.identifiers,
        detections=[d for d in doc.detections if d.end <= max_chars],
    )
    prompt = (
        "Identify which of the following categories appear in the document "
        "below. Return an empty list if none do.\n\n"
        f"Categories:\n{catalogue}\n\n"
        "For each finding, copy a short exact substring from the document as "
        "`evidence`."
    )

    result = gateway.call(
        conn, pack, session_id=session_id, action="classify", subject=subject,
        target=target, docs=[excerpt], prompt=prompt, system=SYSTEM,
        output_schema=SCHEMA, max_tokens=2048,
    )
    if not result.allowed:
        return [], {"status": "blocked", "reason": result.reason,
                    "rule_id": result.decision.rule_id, "audit_seq": result.audit_seq}

    try:
        payload = json.loads(result.text or "{}")
    except json.JSONDecodeError as exc:
        return [], {"status": "error", "reason": f"model returned non-JSON: {exc}",
                    "audit_seq": result.audit_seq}

    detections: list[Detection] = []
    unmatched = 0
    for item in payload.get("detections", []):
        key = (item.get("data_type"), item.get("identifier"))
        ident = index.get(key)
        if ident is None:
            # The model named a category the pack did not offer. Drop it: the
            # pack's vocabulary is the whole point.
            unmatched += 1
            continue
        evidence = (item.get("evidence") or "").strip()
        # The model saw redacted text, so locate evidence in the redacted copy
        # and map back only if it also appears verbatim in the original.
        start = doc.text.find(evidence) if evidence else -1
        end = start + len(evidence) if start >= 0 else -1
        detections.append(Detection(
            data_type=key[0], identifier=key[1], method="llm",
            confidence=float(item.get("confidence", ident.confidence)),
            start=start, end=end, value=evidence if start >= 0 else "",
            token_entity=ident.token_entity, citation=ident.citation,
            extra={"rationale": item.get("rationale", ""), "locatable": start >= 0},
        ))
    return detections, {
        "status": "ran", "model": target.key, "audit_seq": result.audit_seq,
        "tokens_in": result.tokens_in, "tokens_out": result.tokens_out,
        "found": len(detections), "dropped_unknown_category": unmatched,
        "truncated": truncated,
    }
