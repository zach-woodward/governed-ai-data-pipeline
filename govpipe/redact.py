"""Redaction and re-identification.

Tokenized values are written to a local vault table. Re-identification is
possible only with that table, which never leaves the machine - which is what
makes it safe to send [PATIENT_1] to a model and still hand a readable answer
back to the clinician.
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from .audit import now
from .classify.detectors import Detection
from .policy.pack import Pack


@dataclass
class RedactionResult:
    text: str
    tokens: dict[str, str] = field(default_factory=dict)     # token -> original
    counts: dict[str, int] = field(default_factory=dict)     # strategy -> n
    by_identifier: dict[str, str] = field(default_factory=dict)  # identifier -> strategy

    @property
    def applied(self) -> bool:
        return bool(self.counts)

    def summary(self) -> dict[str, Any]:
        """Goes into the audit log. Records what was done, never the values."""
        return {
            "applied": self.applied,
            "strategies": dict(sorted(self.counts.items())),
            "by_identifier": dict(sorted(self.by_identifier.items())),
            "tokens_issued": len(self.tokens),
        }


def _mask(value: str, spec: dict[str, Any]) -> str:
    keep = int(spec.get("keep_last", 4))
    char = str(spec.get("mask_char", "x"))[:1] or "x"
    digits = [c for c in value if c.isalnum()]
    if len(digits) <= keep:
        return char * len(value)
    tail = "".join(digits[-keep:]) if keep else ""
    return char * (len(digits) - keep) + tail


def _hash(value: str) -> str:
    return "[SHA:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:10] + "]"


def apply(
    conn: sqlite3.Connection,
    pack: Pack,
    doc_id: str,
    text: str,
    detections: list[Detection],
    data_types: list[str] | None = None,
    persist: bool = True,
    shared: dict | None = None,
) -> RedactionResult:
    """Redact the detections whose data type is in `data_types` (all, if None).

    Replacements run right-to-left so earlier spans keep their offsets. The
    same value gets the same token, so a model can still tell that [PATIENT_1]
    on line 2 and line 40 are the same person - which is the whole reason to
    tokenize rather than blank out.

    How far that sameness reaches is the pack's call, via `scope` in
    redaction.yaml: `per_document` restarts numbering for each document,
    `per_corpus` carries it across every document in one call so the model can
    tell that two records are about the same person. `shared` is the state
    that makes per_corpus work and is supplied by `apply_all`.
    """
    wanted = set(data_types) if data_types else None
    # An LLM detection whose evidence could not be located in the source has
    # no span, so there is nothing to replace. It still counts for
    # classification; it just cannot be redacted.
    targets = [d for d in detections
               if (wanted is None or d.data_type in wanted) and d.start >= 0]
    result = RedactionResult(text=text)
    if not targets:
        return result

    # Per-document state. `shared` holds the equivalent for per_corpus scope.
    doc_state = {"counters": {}, "tokens": {}}
    shared = shared if shared is not None else {"counters": {}, "tokens": {}}
    rows: list[tuple] = []
    edits: list[tuple[int, int, str]] = []

    for d in sorted(targets, key=lambda d: d.start):
        spec = pack.redaction_for(d.data_type, d.identifier)
        strategy = spec.get("default", "tokenize")
        entity = d.token_entity or d.identifier.upper()

        if strategy == "tokenize":
            scope = spec.get("scope", "per_document")
            state = shared if scope == "per_corpus" else doc_state
            cache_key = (entity, d.value)
            token = state["tokens"].get(cache_key)
            if token is None:
                state["counters"][entity] = state["counters"].get(entity, 0) + 1
                fmt = spec.get("token_format", "[{ENTITY}_{N}]")
                token = fmt.replace("{ENTITY}", entity).replace(
                    "{N}", str(state["counters"][entity]))
                state["tokens"][cache_key] = token
            if token not in result.tokens:
                result.tokens[token] = d.value
                # A vault row per (doc, token): re-identification is always
                # scoped to the documents the caller actually holds, even when
                # the token itself is shared across a corpus.
                rows.append((token, doc_id, d.data_type, d.identifier, d.value, now()))
            replacement = token
        elif strategy == "mask":
            replacement = _mask(d.value, spec)
        elif strategy == "hash":
            replacement = _hash(d.value)
        elif strategy == "drop":
            replacement = f"[REDACTED:{entity}]"
        else:  # unreachable: pack validation rejects unknown strategies
            raise ValueError(f"unknown redaction strategy '{strategy}'")

        edits.append((d.start, d.end, replacement))
        result.counts[strategy] = result.counts.get(strategy, 0) + 1
        result.by_identifier[f"{d.data_type}.{d.identifier}"] = strategy

    out = text
    for start, end, replacement in sorted(edits, reverse=True):
        out = out[:start] + replacement + out[end:]
    result.text = out

    if persist and rows:
        conn.executemany(
            "INSERT OR REPLACE INTO vault "
            "(token, doc_id, entity_type, identifier, value, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
    return result


def apply_all(
    conn: sqlite3.Connection,
    pack: Pack,
    docs: list,
    data_types: list[str] | None = None,
) -> tuple[dict[str, str], list[RedactionResult]]:
    """Redact a whole call's worth of documents, honoring per_corpus scope."""
    shared: dict = {"counters": {}, "tokens": {}}
    texts, results = {}, []
    for doc in docs:
        res = apply(conn, pack, doc.doc_id, doc.text, doc.detections,
                    data_types=data_types, shared=shared)
        texts[doc.doc_id] = res.text
        results.append(res)
    return texts, results


def reidentify(conn: sqlite3.Connection, doc_ids: list[str], text: str) -> tuple[str, int]:
    """Put the real values back. Only ever called inside the boundary, on
    output that is about to be shown to an authorized human."""
    if not doc_ids:
        return text, 0
    marks = ",".join("?" * len(doc_ids))
    rows = conn.execute(
        f"SELECT token, value FROM vault WHERE doc_id IN ({marks})", doc_ids
    ).fetchall()
    # Longest token first, so [PATIENT_10] is not eaten by [PATIENT_1].
    n = 0
    for row in sorted(rows, key=lambda r: -len(r["token"])):
        if row["token"] in text:
            text = text.replace(row["token"], row["value"])
            n += 1
    return text, n
