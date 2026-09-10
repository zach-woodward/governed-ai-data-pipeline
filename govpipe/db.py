"""SQLite storage for the governed pipeline.

One database file holds everything. The audit_log table is the system of
record; every other table is operational state that can be rebuilt.
"""
from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "var" / "govpipe.db"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ---------------------------------------------------------------- documents
CREATE TABLE IF NOT EXISTS documents (
    doc_id       TEXT PRIMARY KEY,
    source_path  TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    media_type   TEXT NOT NULL,
    byte_len     INTEGER NOT NULL,
    text_len     INTEGER NOT NULL,
    ingested_at  TEXT NOT NULL
);

-- Classification result. One row per document per classifier run.
CREATE TABLE IF NOT EXISTS manifests (
    doc_id             TEXT PRIMARY KEY REFERENCES documents(doc_id),
    sensitivity        TEXT NOT NULL,
    classification_rule TEXT NOT NULL DEFAULT '',
    data_types         TEXT NOT NULL,   -- json list
    identifiers        TEXT NOT NULL,   -- json list
    methods            TEXT NOT NULL,   -- json map identifier -> regex|llm
    pack_id            TEXT NOT NULL,
    pack_version       TEXT NOT NULL,
    classifier_version TEXT NOT NULL,
    classified_at      TEXT NOT NULL,
    manifest_hash      TEXT NOT NULL
);

-- Individual detections. Never stores the matched value in the clear; the
-- value lives in the vault only when redaction actually tokenized it.
CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    doc_id      TEXT NOT NULL REFERENCES documents(doc_id),
    data_type   TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    method      TEXT NOT NULL,          -- regex | llm
    confidence  REAL NOT NULL,
    span_start  INTEGER,
    span_end    INTEGER,
    value_hash  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_detections_doc ON detections(doc_id);

-- ------------------------------------------------------------------- vault
-- Reversible tokenization. Re-identification is only possible with this
-- table, which never leaves the boundary.
CREATE TABLE IF NOT EXISTS vault (
    token       TEXT NOT NULL,
    doc_id      TEXT NOT NULL REFERENCES documents(doc_id),
    entity_type TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    value       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (doc_id, token)
);

-- --------------------------------------------------------------- approvals
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL,          -- pending | approved | denied
    queue       TEXT NOT NULL,
    roles       TEXT NOT NULL,          -- json list of roles that may decide
    requester   TEXT NOT NULL,
    summary     TEXT NOT NULL,
    context     TEXT NOT NULL,          -- json request context
    decided_at  TEXT,
    decided_by  TEXT,
    note        TEXT
);

-- --------------------------------------------------------------- retention
CREATE TABLE IF NOT EXISTS retention (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,          -- prompt | output | document
    ref         TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    worm        INTEGER NOT NULL DEFAULT 0,
    purged_at   TEXT
);

-- --------------------------------------------------------------- audit log
-- Append-only, hash chained. seq 0 is the genesis entry.
CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    actor        TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    event        TEXT NOT NULL,
    action       TEXT,
    resource_ids TEXT NOT NULL,         -- json list
    sensitivity  TEXT,
    data_types   TEXT NOT NULL,         -- json list
    decision     TEXT,                  -- allow | deny
    rule_id      TEXT,
    obligations  TEXT NOT NULL,         -- json list
    pack         TEXT NOT NULL,         -- "hipaa@1.0.0"
    model_id     TEXT,
    tokens_in    INTEGER,
    tokens_out   INTEGER,
    redaction    TEXT NOT NULL,         -- json summary
    approval_id  TEXT,
    detail       TEXT NOT NULL,         -- json
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audit_ts    ON audit_log(ts);
CREATE INDEX IF NOT EXISTS ix_audit_sens  ON audit_log(sensitivity);
CREATE INDEX IF NOT EXISTS ix_audit_event ON audit_log(event);

-- Append-only enforcement at the storage layer. These are a speed bump, not
-- the control: the hash chain in audit.py is what actually detects tampering
-- by anyone who can drop a trigger.
CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- -------------------------------------------------------------------- meta
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# Columns added to existing tables after the first release. `CREATE TABLE IF
# NOT EXISTS` is idempotent for creation but never alters a table that already
# exists, so a database made before a schema change would fail at query time
# with "no such column". Each entry is applied only if the column is absent.
#
# Deliberately additive: nothing here drops or rewrites a column, because the
# audit log's hash chain covers a fixed field set and a destructive migration
# would invalidate every existing entry.
COLUMN_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
    ("manifests", "classification_rule", "TEXT NOT NULL DEFAULT ''"),
)


def migrate(conn: sqlite3.Connection) -> list[str]:
    """Bring an existing database up to the current schema. Returns what it did."""
    applied = []
    for table, column, ddl in COLUMN_MIGRATIONS:
        existing = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue                      # table not created yet; SCHEMA handles it
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
            applied.append(f"{table}.{column}")
    return applied


def connect(path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(path) if path else DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    migrate(conn)
    return conn


def get_meta(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def detection_key(conn: sqlite3.Connection) -> bytes:
    """A random per-database key for hashing detected values.

    A bare SHA-256 of a detected value is not a one-way function in practice:
    the search space for a social security number is 10^9, which is a few
    seconds of work. Keying the digest means the detections table records that
    two documents contain the same value without recording what it is.
    """
    existing = get_meta(conn, "detection_key")
    if existing is None:
        existing = secrets.token_hex(32)
        set_meta(conn, "detection_key", existing)
    return bytes.fromhex(existing)


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
