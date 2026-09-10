"""Retention clocks.

Two kinds of artifact expire on different terms, and the difference is the
interesting part:

  vault  - the re-identification table. When its clock runs out the rows are
           destroyed, and every token that pointed at them becomes permanently
           unresolvable. That is de-identification by key destruction, and it
           is the only thing here that actually deletes data.

  audit  - the log itself. It is hash-chained and append-only, so it *cannot*
           be purged without breaking the chain, and under 45 CFR 164.316(b)
           or SEA 17a-4 it must not be. Its clock is a floor, not a deadline:
           the sweep reports these as held and never touches them.

A regime that wanted the log erasable would be asking for a different design,
and it is worth saying so out loud rather than pretending the sweep handles it.
Nothing is deleted as a side effect of a model call; the sweep is explicit and
defaults to a dry run.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from . import audit

PURGEABLE_KINDS = frozenset({"vault"})


def record(
    conn: sqlite3.Connection, *, kind: str, ref: str, days: int | None,
    worm: bool = False,
) -> None:
    """Start a clock. `ref` must name something a sweep could actually act on:
    a doc_id for `vault`, an audit sequence number for `audit`."""
    if days is None:
        return
    created = datetime.now(timezone.utc)
    conn.execute(
        "INSERT INTO retention (kind, ref, created_at, expires_at, worm) "
        "VALUES (?, ?, ?, ?, ?)",
        (kind, ref, created.isoformat(timespec="microseconds"),
         (created + timedelta(days=int(days))).isoformat(timespec="microseconds"),
         1 if worm else 0),
    )


def due(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    nowts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return [dict(r) for r in conn.execute(
        "SELECT * FROM retention WHERE purged_at IS NULL AND expires_at <= ? "
        "ORDER BY expires_at ASC", (nowts,)
    )]


def listing(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM retention ORDER BY expires_at ASC LIMIT ?", (limit,)
    )]


def sweep(
    conn: sqlite3.Connection, *, session_id: str, pack_ref: str, actor: str = "system",
    dry_run: bool = True,
) -> dict[str, Any]:
    items = due(conn)
    purgeable = [i for i in items if i["kind"] in PURGEABLE_KINDS and not i["worm"]]
    worm_held = [i for i in items if i["worm"]]
    immutable_held = [i for i in items
                      if i["kind"] not in PURGEABLE_KINDS and not i["worm"]]

    tokens_destroyed = 0
    if not dry_run and purgeable:
        for item in purgeable:
            cur = conn.execute("DELETE FROM vault WHERE doc_id = ?", (item["ref"],))
            tokens_destroyed += cur.rowcount or 0
        nowts = audit.now()
        conn.executemany(
            "UPDATE retention SET purged_at = ? WHERE id = ?",
            [(nowts, i["id"]) for i in purgeable],
        )

    audit.append(
        conn, event="retention_sweep", session_id=session_id, actor=actor,
        pack=pack_ref, purpose="operations",
        detail={"dry_run": dry_run,
                "eligible": len(purgeable),
                "tokens_destroyed": tokens_destroyed,
                "worm_held": len(worm_held),
                "immutable_held": len(immutable_held),
                "refs": sorted({i["ref"] for i in purgeable})[:50]},
    )
    return {"purged": 0 if dry_run else len(purgeable), "eligible": len(purgeable),
            "tokens_destroyed": tokens_destroyed, "worm_held": len(worm_held),
            "immutable_held": len(immutable_held)}
