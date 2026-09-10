"""The governed LLM gateway.

Every model call in this system goes through `call()`. There is no other path
to a model, which is what makes the audit log complete rather than
best-effort.

The sequence is always the same:

    build context -> evaluate policy -> discharge every obligation
                  -> call the model -> write the audit entry

An allow whose obligations cannot all be discharged is converted to a deny
and logged as one. That is the property the whole design rests on.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from . import approvals, audit, redact, retention
from .classify.detectors import Detection
from .obligations import ObligationError, discharge_all
from .policy import Context, Decision, Pack, Resource, Subject, Target, evaluate


@dataclass
class Doc:
    """A classified document, ready to be reasoned over."""
    doc_id: str
    text: str
    sensitivity: str = "internal"
    data_types: list[str] = field(default_factory=list)
    identifiers: list[str] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)


@dataclass
class GatewayResult:
    status: str                      # completed | denied | pending_approval
    decision: Decision
    audit_seq: int
    text: str | None = None          # model output, tokens still in place
    reidentified: str | None = None  # output with vault values restored
    prompt_sent: str | None = None   # exactly what crossed the boundary
    approval_id: str | None = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    redaction: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.status == "completed"


# --------------------------------------------------------------------------
# Model invocation
# --------------------------------------------------------------------------

def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def _call_offline(target: Target, system: str, prompt: str) -> dict[str, Any]:
    """Deterministic stand-in so the entire pipeline, audit trail included,
    runs with no API key and no egress. Governance behavior is identical."""
    digest = hashlib.sha256((system + prompt).encode("utf-8")).hexdigest()[:8]
    tokens = re.findall(r"\[[A-Z]+_\d+\]", prompt)
    seen: list[str] = []
    for t in tokens:
        if t not in seen:
            seen.append(t)
    body = (
        f"[local-echo {digest}] Offline stub response. The prompt that reached "
        f"this endpoint was {len(prompt)} characters and referred to "
        f"{len(seen)} tokenized entities"
        + (f" ({', '.join(seen[:6])})" if seen else "")
        + ". No network call was made and no real model produced this text."
    )
    return {
        "text": body,
        "tokens_in": _estimate_tokens(system + prompt),
        "tokens_out": _estimate_tokens(body),
        "estimated": True,
        "stop_reason": "end_turn",
    }


def _call_anthropic(
    target: Target, system: str, prompt: str, output_schema: dict | None, max_tokens: int
) -> dict[str, Any]:
    import anthropic

    client = anthropic.Anthropic()
    kwargs: dict[str, Any] = {
        "model": target.model_id,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
        # Effort is a cost/quality dial, not a governance control.
        "output_config": {"effort": "low" if output_schema else "medium"},
    }
    if output_schema:
        kwargs["output_config"]["format"] = {"type": "json_schema", "schema": output_schema}
    # Note: server-side refusal fallbacks are deliberately NOT enabled. This
    # pipeline pins a specific model because policy said that model satisfies
    # the routing requirements; letting the server silently reroute to another
    # model would make the audit record's model_id a claim we cannot stand
    # behind. A refusal here surfaces as a refusal.
    response = client.messages.create(**kwargs)

    if response.stop_reason == "refusal":
        detail = getattr(response, "stop_details", None)
        category = getattr(detail, "category", None) if detail else None
        return {
            "text": None, "tokens_in": response.usage.input_tokens,
            "tokens_out": response.usage.output_tokens, "estimated": False,
            "stop_reason": "refusal", "refusal_category": category,
        }

    text = "".join(b.text for b in response.content if b.type == "text")
    return {
        "text": text,
        "tokens_in": response.usage.input_tokens,
        "tokens_out": response.usage.output_tokens,
        "estimated": False,
        "stop_reason": response.stop_reason,
    }


# --------------------------------------------------------------------------
# The choke point
# --------------------------------------------------------------------------

def call(
    conn: sqlite3.Connection,
    pack: Pack,
    *,
    session_id: str,
    action: str,
    subject: Subject,
    target: Target | None,
    docs: list[Doc],
    prompt: str,
    system: str = "",
    output_schema: dict | None = None,
    max_tokens: int = 4096,
    approval_id: str | None = None,
    jurisdiction: str = "US",
) -> GatewayResult:
    resource = Resource(
        doc_ids=[d.doc_id for d in docs],
        sensitivity=_highest(pack, [d.sensitivity for d in docs]),
        data_types=sorted({t for d in docs for t in d.data_types}),
        identifiers=sorted({i for d in docs for i in d.identifiers}),
        jurisdiction=jurisdiction,
    )
    ctx = Context(action=action, subject=subject, resource=resource, target=target)
    decision = evaluate(pack, ctx)

    common = dict(
        session_id=session_id, actor=subject.id, purpose=subject.purpose_of_use,
        pack=pack.ref, action=action, resource_ids=resource.doc_ids,
        sensitivity=resource.sensitivity, data_types=resource.data_types,
        decision=decision.verdict, rule_id=decision.rule_id,
        obligations=decision.obligations_json(),
        model_id=(target.key if target else None),
    )

    if not decision.allowed:
        entry = audit.append(
            conn, event="policy_deny", **common,
            detail={"reason": decision.reason, "citation": decision.citation,
                    "trace": decision.trace},
        )
        return GatewayResult(status="denied", decision=decision,
                             audit_seq=entry["seq"], reason=decision.reason)

    # ---- discharge obligations ------------------------------------------
    state: dict[str, Any] = {
        "doc_texts": {d.doc_id: d.text for d in docs},
        "redaction": {"applied": False},
        "audit_level": "summary",
    }
    dctx = {"conn": conn, "pack": pack, "docs": docs, "target": target,
            "approval_id": approval_id}
    try:
        discharge_all(state, decision.obligations, dctx)
    except ObligationError as exc:
        entry = audit.append(
            conn, event="obligation_failure", **{**common, "decision": "deny"},
            redaction=state.get("redaction", {}),
            detail={"reason": str(exc), "failed_obligation": state.get("failed_obligation"),
                    "original_rule": decision.rule_id, "citation": decision.citation},
        )
        failed = Decision(
            allowed=False, rule_id=decision.rule_id,
            reason=f"allow converted to deny: {exc}",
            citation=decision.citation,
            trace=decision.trace + [f"OBLIGATION {state.get('failed_obligation', '?')}: FAILED"],
        )
        return GatewayResult(status="denied", decision=failed,
                             audit_seq=entry["seq"], reason=failed.reason,
                             redaction=state.get("redaction", {}))

    # ---- blocking human approval ----------------------------------------
    if "needs_approval" in state:
        spec = state["needs_approval"]
        aid = approvals.create(
            conn, queue=spec["queue"], roles=spec["roles"], requester=subject.id,
            summary=f"{action} of {len(docs)} document(s) classified "
                    f"{resource.sensitivity}",
            context={"action": action, "doc_ids": resource.doc_ids,
                     "sensitivity": resource.sensitivity,
                     "data_types": resource.data_types,
                     "rule_id": decision.rule_id, "purpose": subject.purpose_of_use,
                     "target": target.key if target else None},
        )
        entry = audit.append(
            conn, event="approval_requested", **common, approval_id=aid,
            redaction=state["redaction"],
            detail={"queue": spec["queue"], "roles": spec["roles"],
                    "reason": decision.reason, "citation": decision.citation},
        )
        return GatewayResult(status="pending_approval", decision=decision,
                             audit_seq=entry["seq"], approval_id=aid,
                             redaction=state["redaction"],
                             reason=f"queued for {spec['queue']} review")

    # ---- build the prompt that will actually cross the boundary ---------
    body = "\n\n".join(
        f"--- document {doc_id} ---\n{state['doc_texts'][doc_id]}" for doc_id in resource.doc_ids
    )
    full_prompt = f"{prompt}\n\n{body}".strip() if body else prompt

    # ---- the call --------------------------------------------------------
    if target is None:
        result = {"text": None, "tokens_in": 0, "tokens_out": 0, "estimated": True,
                  "stop_reason": "no_model"}
    elif target.offline:
        result = _call_offline(target, system, full_prompt)
    else:
        try:
            result = _call_anthropic(target, system, full_prompt, output_schema, max_tokens)
        except Exception as exc:
            entry = audit.append(
                conn, event="model_error", **{**common, "decision": "deny"},
                redaction=state["redaction"],
                detail={"error": type(exc).__name__, "message": str(exc)[:500]},
            )
            failed = Decision(allowed=False, rule_id=decision.rule_id,
                              reason=f"model call failed: {type(exc).__name__}: {exc}",
                              citation=decision.citation, trace=decision.trace)
            return GatewayResult(status="denied", decision=failed,
                                 audit_seq=entry["seq"], reason=failed.reason)

    if result["stop_reason"] == "refusal":
        entry = audit.append(
            conn, event="model_refusal", **{**common, "decision": "deny"},
            tokens_in=result["tokens_in"], tokens_out=result["tokens_out"],
            redaction=state["redaction"],
            detail={"refusal_category": result.get("refusal_category")},
        )
        failed = Decision(allowed=False, rule_id=decision.rule_id,
                          reason="the model declined the request",
                          citation=decision.citation, trace=decision.trace)
        return GatewayResult(status="denied", decision=failed, audit_seq=entry["seq"],
                             reason=failed.reason)

    text = result["text"] or ""
    reidentified, restored = redact.reidentify(conn, resource.doc_ids, text)

    if "supervise" in state:
        approvals.create(
            conn, queue=state["supervise"]["queue"], roles=["supervisor"],
            requester=subject.id, status="pending",
            summary=f"post-hoc supervisory review of {action}",
            context={"doc_ids": resource.doc_ids, "rule_id": decision.rule_id},
        )

    detail: dict[str, Any] = {
        "reason": decision.reason,
        "citation": decision.citation,
        "prompt_sha256": hashlib.sha256(full_prompt.encode()).hexdigest(),
        "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "token_estimate": result["estimated"],
        "tokens_reidentified": restored,
        "minimum_necessary": state.get("minimum_necessary"),
        "retention": state.get("retention"),
        "residency": state.get("residency"),
    }
    if state["audit_level"] == "full":
        # What actually crossed the boundary, verbatim. Under 164.312(b) this
        # is the point of the log; it is retained for six years and is itself
        # PHI, which is why the database never leaves the boundary either.
        detail["prompt_sent"] = full_prompt
        detail["response"] = text

    try:
        _check_required_audit_fields(pack, common, result, model_involved=target is not None)
    except ObligationError as exc:
        entry = audit.append(
            conn, event="audit_contract_failure", **{**common, "decision": "deny"},
            redaction=state["redaction"], detail={"reason": str(exc)},
        )
        failed = Decision(allowed=False, rule_id=decision.rule_id, reason=str(exc),
                          citation=decision.citation, trace=decision.trace)
        return GatewayResult(status="denied", decision=failed, audit_seq=entry["seq"],
                             reason=str(exc))

    entry = audit.append(
        conn, event="llm_call" if target is not None else "action_completed",
        **common, approval_id=state.get("approval_id"),
        tokens_in=result["tokens_in"], tokens_out=result["tokens_out"],
        redaction=state["redaction"], detail=detail,
    )

    # ---- retention clocks ------------------------------------------------
    # Recorded after the audit entry so each clock names the thing it governs:
    # the vault rows for these documents, and this entry in the log.
    if "retention" in state:
        worm = state.get("worm", False)
        retention.record(conn, kind="audit", ref=f"seq:{entry['seq']}",
                         days=state["retention"]["prompt_days"], worm=worm)
        for doc_id in resource.doc_ids:
            retention.record(conn, kind="vault", ref=doc_id,
                             days=state["retention"]["output_days"], worm=worm)
    return GatewayResult(
        status="completed", decision=decision, audit_seq=entry["seq"], text=text,
        reidentified=reidentified, prompt_sent=full_prompt,
        approval_id=state.get("approval_id"),
        tokens_in=result["tokens_in"], tokens_out=result["tokens_out"],
        redaction=state["redaction"], reason=decision.reason,
    )


# Fields that only exist when a model was actually invoked. An action that
# does not call a model (a reviewed release, say) is not excused from the
# audit contract - it is simply not held to the model-specific half of it.
MODEL_ONLY_AUDIT_FIELDS = frozenset({"model_id", "tokens_in", "tokens_out"})


def _check_required_audit_fields(
    pack: Pack, common: dict, result: dict, *, model_involved: bool
) -> None:
    """The pack declares what its regime requires the log to capture. If the
    gateway cannot supply one of those fields, that is a governance failure,
    not a warning."""
    available = dict(common)
    available.update({"tokens_in": result["tokens_in"], "tokens_out": result["tokens_out"],
                      "redaction": True, "actor": common["actor"]})
    required = [
        f for f in pack.audit.get("required_fields", [])
        if model_involved or f not in MODEL_ONLY_AUDIT_FIELDS
    ]
    missing = [f for f in required if available.get(f) is None]
    if missing:
        raise ObligationError(
            f"{pack.ref} requires audit field(s) {missing} that this call cannot supply "
            f"({pack.audit.get('citation', '')})"
        )


def _highest(pack: Pack, levels: list[str]) -> str:
    """The classification of a set is the classification of its most
    sensitive member."""
    order = list(pack.levels) or ["public", "internal", "restricted", "prohibited"]
    ranked = [l for l in levels if l in order]
    if not ranked:
        return pack.default_level
    return max(ranked, key=order.index)
