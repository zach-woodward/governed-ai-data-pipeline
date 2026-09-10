"""Human-in-the-loop approval queue.

Policy decides *that* a human must sign off and *who* may do it; this module
is only the queue. Both the request and the decision are audited, so the
accounting of disclosures can be reconstructed from the log alone.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from typing import Any

from . import audit


def create(
    conn: sqlite3.Connection, *, queue: str, roles: list[str], requester: str,
    summary: str, context: dict[str, Any], status: str = "pending",
) -> str:
    approval_id = "a-" + uuid.uuid4().hex[:8]
    conn.execute(
        "INSERT INTO approvals (approval_id, created_at, status, queue, roles, "
        "requester, summary, context) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (approval_id, audit.now(), status, queue, json.dumps(sorted(roles)),
         requester, summary, json.dumps(context, sort_keys=True, default=str)),
    )
    return approval_id


def get(conn: sqlite3.Connection, approval_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)
    ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["roles"] = json.loads(record["roles"])
    record["context"] = json.loads(record["context"])
    return record


def pending(conn: sqlite3.Connection, queue: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT approval_id FROM approvals WHERE status = 'pending'"
    params: list[Any] = []
    if queue:
        sql += " AND queue = ?"
        params.append(queue)
    sql += " ORDER BY created_at ASC"
    return [get(conn, r["approval_id"]) for r in conn.execute(sql, params)]


def all_items(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT approval_id FROM approvals ORDER BY created_at DESC LIMIT ?", (limit,)
    )
    return [get(conn, r["approval_id"]) for r in rows]


class ApprovalError(RuntimeError):
    pass


def decide(
    conn: sqlite3.Connection, approval_id: str, *, decision: str, decided_by: str,
    roles: list[str], session_id: str, pack_ref: str, note: str = "",
) -> dict[str, Any]:
    """Approve or deny a queued item.

    The role check is enforced here rather than in the UI: policy named the
    roles that may decide, so a decision by anyone else is refused and the
    refusal is itself audited.
    """
    if decision not in ("approved", "denied"):
        raise ApprovalError("decision must be 'approved' or 'denied'")
    record = get(conn, approval_id)
    if record is None:
        raise ApprovalError(f"no approval with id '{approval_id}'")
    if record["status"] != "pending":
        raise ApprovalError(
            f"approval '{approval_id}' was already {record['status']}"
        )

    required = set(record["roles"])
    if required and not (required & set(roles)):
        audit.append(
            conn, event="approval_refused", session_id=session_id, actor=decided_by,
            pack=pack_ref, approval_id=approval_id, decision="deny",
            rule_id="APPROVAL-ROLE",
            resource_ids=record["context"].get("doc_ids", []),
            sensitivity=record["context"].get("sensitivity"),
            data_types=record["context"].get("data_types", []),
            action=record["context"].get("action"),
            detail={"reason": f"{decided_by} holds {sorted(roles)}; this queue "
                              f"requires one of {sorted(required)}",
                    "queue": record["queue"], "summary": record["summary"]},
        )
        raise ApprovalError(
            f"{decided_by} holds roles {sorted(roles)} but queue '{record['queue']}' "
            f"requires one of {sorted(required)}"
        )

    conn.execute(
        "UPDATE approvals SET status = ?, decided_at = ?, decided_by = ?, note = ? "
        "WHERE approval_id = ?",
        (decision, audit.now(), decided_by, note, approval_id),
    )
    audit.append(
        conn, event="approval_decision", session_id=session_id, actor=decided_by,
        purpose=record["context"].get("purpose", "review"), pack=pack_ref,
        action=record["context"].get("action"), approval_id=approval_id,
        resource_ids=record["context"].get("doc_ids", []),
        sensitivity=record["context"].get("sensitivity"),
        data_types=record["context"].get("data_types", []),
        decision="allow" if decision == "approved" else "deny",
        rule_id=record["context"].get("rule_id"),
        detail={"queue": record["queue"], "note": note, "roles_held": sorted(roles),
                "summary": record["summary"]},
    )
    return get(conn, approval_id)
