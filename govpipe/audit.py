"""Append-only, hash-chained audit log.

Each entry's hash covers the entry's own canonical JSON *and* the previous
entry's hash, so altering or removing any entry breaks every hash after it.
`verify()` reports the first sequence number where the chain fails.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

GENESIS_PREV = "0" * 64

# The exact column set that is hashed, in a fixed order. Adding a column here
# is a schema change: old entries would no longer verify.
HASHED_FIELDS = (
    "seq", "ts", "session_id", "actor", "purpose", "event", "action",
    "resource_ids", "sensitivity", "data_types", "decision", "rule_id",
    "obligations", "pack", "model_id", "tokens_in", "tokens_out",
    "redaction", "approval_id", "detail", "prev_hash",
)

JSON_FIELDS = ("resource_ids", "data_types", "obligations", "redaction", "detail")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical(entry: dict[str, Any]) -> str:
    """Deterministic serialization. Sorted keys, no whitespace, no NaN."""
    return json.dumps(
        {k: entry.get(k) for k in HASHED_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def compute_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(canonical(entry).encode("utf-8")).hexdigest()


def _head(conn: sqlite3.Connection) -> tuple[int, str]:
    row = conn.execute(
        "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return -1, GENESIS_PREV
    return row["seq"], row["entry_hash"]


def append(
    conn: sqlite3.Connection,
    *,
    event: str,
    session_id: str,
    actor: str = "system",
    purpose: str = "operations",
    pack: str = "none",
    action: str | None = None,
    resource_ids: list[str] | None = None,
    sensitivity: str | None = None,
    data_types: list[str] | None = None,
    decision: str | None = None,
    rule_id: str | None = None,
    obligations: list[Any] | None = None,
    model_id: str | None = None,
    tokens_in: int | None = None,
    tokens_out: int | None = None,
    redaction: dict[str, Any] | None = None,
    approval_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one entry and return it (including seq and entry_hash)."""
    # BEGIN IMMEDIATE takes the write lock before we read the head, so two
    # concurrent appends cannot chain off the same predecessor.
    conn.execute("BEGIN IMMEDIATE")
    try:
        last_seq, prev_hash = _head(conn)
        entry = {
            "seq": last_seq + 1,
            "ts": now(),
            "session_id": session_id,
            "actor": actor,
            "purpose": purpose,
            "event": event,
            "action": action,
            "resource_ids": json.dumps(resource_ids or [], sort_keys=True),
            "sensitivity": sensitivity,
            "data_types": json.dumps(sorted(data_types or []), sort_keys=True),
            "decision": decision,
            "rule_id": rule_id,
            "obligations": json.dumps(obligations or [], sort_keys=True),
            "pack": pack,
            "model_id": model_id,
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "redaction": json.dumps(redaction or {}, sort_keys=True),
            "approval_id": approval_id,
            "detail": json.dumps(detail or {}, sort_keys=True, default=str),
            "prev_hash": prev_hash,
        }
        entry["entry_hash"] = compute_hash(entry)
        cols = ", ".join(HASHED_FIELDS + ("entry_hash",))
        marks = ", ".join("?" * (len(HASHED_FIELDS) + 1))
        conn.execute(
            f"INSERT INTO audit_log ({cols}) VALUES ({marks})",
            [entry[k] for k in HASHED_FIELDS] + [entry["entry_hash"]],
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return entry


def verify(conn: sqlite3.Connection) -> tuple[bool, int | None, str]:
    """Walk the chain. Returns (ok, first_bad_seq, message)."""
    expected_prev = GENESIS_PREV
    expected_seq = 0
    count = 0
    for row in conn.execute("SELECT * FROM audit_log ORDER BY seq ASC"):
        entry = dict(row)
        if entry["seq"] != expected_seq:
            return False, entry["seq"], (
                f"sequence gap: expected seq {expected_seq}, found {entry['seq']} "
                "(an entry was deleted)"
            )
        if entry["prev_hash"] != expected_prev:
            return False, entry["seq"], (
                f"broken link at seq {entry['seq']}: prev_hash does not match "
                "the previous entry's hash"
            )
        recomputed = compute_hash(entry)
        if recomputed != entry["entry_hash"]:
            return False, entry["seq"], (
                f"content altered at seq {entry['seq']}: stored hash "
                f"{entry['entry_hash'][:12]}… != recomputed {recomputed[:12]}…"
            )
        expected_prev = entry["entry_hash"]
        expected_seq += 1
        count += 1
    return True, None, f"chain intact across {count} entries"


def _parse_since(since: str) -> str:
    """'7d', '24h', '30m', or an ISO timestamp."""
    unit = since[-1:].lower()
    if unit in "dhm" and since[:-1].isdigit():
        n = int(since[:-1])
        delta = {"d": timedelta(days=n), "h": timedelta(hours=n), "m": timedelta(minutes=n)}[unit]
        return (datetime.now(timezone.utc) - delta).isoformat(timespec="microseconds")
    return since


def query(
    conn: sqlite3.Connection,
    *,
    since: str | None = None,
    until: str | None = None,
    sensitivity: str | None = None,
    data_type: str | None = None,
    event: str | None = None,
    decision: str | None = None,
    actor: str | None = None,
    model_id: str | None = None,
    session_id: str | None = None,
    limit: int = 200,
    newest: bool = False,
) -> list[dict[str, Any]]:
    """Filtered slice of the chain. `newest` takes the most recent `limit`
    entries rather than the earliest, but still returns them oldest-first so a
    trail always reads top to bottom."""
    where, params = [], []
    if since:
        where.append("ts >= ?"); params.append(_parse_since(since))
    if until:
        where.append("ts <= ?"); params.append(_parse_since(until))
    if sensitivity:
        where.append("sensitivity = ?"); params.append(sensitivity)
    if event:
        where.append("event = ?"); params.append(event)
    if decision:
        where.append("decision = ?"); params.append(decision)
    if actor:
        where.append("actor = ?"); params.append(actor)
    if model_id:
        where.append("model_id = ?"); params.append(model_id)
    if session_id:
        where.append("session_id = ?"); params.append(session_id)
    if data_type:
        # data_types is a JSON list; match the quoted element.
        where.append("data_types LIKE ?"); params.append(f'%"{data_type}"%')
    sql = "SELECT * FROM audit_log"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY seq {'DESC' if newest else 'ASC'} LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(sql, params)]
    if newest:
        rows.reverse()
    for r in rows:
        for f in JSON_FIELDS:
            try:
                r[f] = json.loads(r[f])
            except (json.JSONDecodeError, TypeError):
                pass
    return rows


def new_session_id() -> str:
    return "s-" + uuid.uuid4().hex[:10]
