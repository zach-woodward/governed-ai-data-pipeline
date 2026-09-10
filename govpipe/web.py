"""A minimal web view over the governed pipeline.

Every route here calls the same core the CLI does. There is no second
implementation of any control: the web UI cannot allow a call the CLI would
deny, because both go through `gateway.call`.

Standard library only, matching zw-panel's zero-dependency posture. Bound to
0.0.0.0 so the LAN can reach it; there is no authentication, so it belongs on
a trusted network or behind Tailscale, not on the public internet.
"""
from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import approvals, audit, retention
from .classify.manifest import IngestError, SUPPORTED, ingest, load_doc
from .config import DB_PATH, SAMPLES_DIR, ConfigError, get_target, load_targets
from .db import connect, get_meta, set_meta
from .gateway import call
from .policy import PackError, Subject, available, load

STATIC = Path(__file__).resolve().parent / "static"

# Live model targets cost money and send data off the machine. The web UI
# defaults to the offline stub and only uses a real one when the request says
# so explicitly, so a visitor clicking around cannot run up a bill.
DEFAULT_WEB_TARGET = "local-echo"


class Ctx:
    """Per-process state. The database handle is per-request: SQLite objects
    are not safe to share across threads."""

    def __init__(self, db: str):
        self.db = db
        self.lock = threading.Lock()

    def conn(self) -> sqlite3.Connection:
        return connect(self.db)

    def pack(self, conn, override: str | None = None):
        return load(override or get_meta(conn, "active_pack", "hipaa"))


def _json(obj) -> bytes:
    return json.dumps(obj, default=str).encode("utf-8")


def _subject(body: dict) -> Subject:
    return Subject(
        id=body.get("actor") or "web.visitor",
        roles=[r for r in (body.get("roles") or "").split(",") if r.strip()],
        purpose_of_use=body.get("purpose") or "operations",
    )


# ---------------------------------------------------------------- read side
def state(ctx: Ctx, conn) -> dict:
    pack = ctx.pack(conn)
    packs = []
    for pid in available():
        p = load(pid)
        packs.append({"id": p.id, "name": p.name, "version": p.version,
                      "status": p.status, "rules": len(p.rules),
                      "authority": p.authority,
                      "data_types": {k: len(v) for k, v in p.data_types.items()}})
    ok, bad, msg = audit.verify(conn)
    return {
        "active_pack": pack.id,
        "packs": packs,
        "targets": [{"key": t.key, "display": t.display, "baa": t.baa,
                     "zero_retention": t.zero_retention, "residency": t.residency,
                     "offline": t.offline}
                    for t in load_targets().values()],
        "docs": docs(conn),
        "approvals": approvals.all_items(conn, limit=50),
        "chain": {"ok": ok, "broken_at": bad, "message": msg},
        "counts": {
            "audit": conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"],
            "denials": conn.execute(
                "SELECT COUNT(*) c FROM audit_log WHERE decision='deny'").fetchone()["c"],
            "vault": conn.execute("SELECT COUNT(*) c FROM vault").fetchone()["c"],
            "retention": len(retention.listing(conn, limit=500)),
        },
    }


def docs(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT d.doc_id, d.source_path, d.sha256, d.media_type, d.ingested_at, "
        "m.sensitivity, m.classification_rule, m.data_types, m.identifiers, m.methods, m.pack_id, "
        "m.pack_version, m.manifest_hash, m.classifier_version "
        "FROM documents d LEFT JOIN manifests m USING(doc_id) ORDER BY d.source_path")
    out = []
    for r in rows:
        d = dict(r)
        d["file"] = Path(d["source_path"]).name
        for f in ("data_types", "identifiers", "methods"):
            try:
                d[f] = json.loads(d[f] or ("{}" if f == "methods" else "[]"))
            except (TypeError, json.JSONDecodeError):
                d[f] = {} if f == "methods" else []
        d["detections"] = conn.execute(
            "SELECT data_type, identifier, method, confidence, COUNT(*) n FROM detections "
            "WHERE doc_id = ? GROUP BY data_type, identifier, method "
            "ORDER BY data_type, identifier", (d["doc_id"],)).fetchall()
        d["detections"] = [dict(x) for x in d["detections"]]
        out.append(d)
    return out


def pack_detail(pack_id: str) -> dict:
    p = load(pack_id)
    return {
        "id": p.id, "name": p.name, "version": p.version, "status": p.status,
        "authority": p.authority, "audit": p.audit, "retention": p.retention,
        "classifier": p.classifier, "routing": p.routing,
        "classification": p.classification_rules,
        "levels": p.levels, "default_level": p.default_level,
        "always": [str(o) for o in p.always],
        "redaction": p.redaction,
        "minimum_necessary": list(p.minimum_necessary),
        "data_types": {
            dt: [{"id": i.id, "method": i.method, "confidence": i.confidence,
                  "citation": i.citation, "token_entity": i.token_entity}
                 for i in ids]
            for dt, ids in p.data_types.items()},
        "rules": [{"id": r.id, "decision": r.decision, "description": r.description,
                   "citation": r.citation, "when": r.when,
                   "obligations": [str(o) for o in r.obligations]}
                  for r in p.rules],
        "files": sorted(f.name for f in p.root.glob("*.yaml")),
    }


# --------------------------------------------------------------- write side
def do_ingest(ctx: Ctx, conn, body: dict) -> dict:
    pack = ctx.pack(conn, body.get("pack"))
    subject = _subject(body)
    session = body.get("session") or audit.new_session_id()
    target = get_target(body.get("classifier_target") or DEFAULT_WEB_TARGET)
    results, errors = [], []
    for path in sorted(SAMPLES_DIR.iterdir()):
        if path.suffix.lower() not in SUPPORTED:
            continue
        try:
            results.append(ingest(conn, pack, path, session_id=session,
                                  subject=subject, classifier_target=target))
        except IngestError as exc:
            errors.append({"file": path.name, "error": str(exc)})
    return {"session": session, "ingested": results, "errors": errors,
            "pack": pack.ref}


def do_ask(ctx: Ctx, conn, body: dict) -> dict:
    pack = ctx.pack(conn, body.get("pack"))
    session = body.get("session") or audit.new_session_id()
    target_key = body.get("target") or DEFAULT_WEB_TARGET
    target = None if target_key == "none" else get_target(target_key)
    docs_in = [load_doc(conn, pack, d) for d in (body.get("doc_ids") or [])]
    result = call(
        conn, pack, session_id=session, action=body.get("action") or "summarize",
        subject=_subject(body), target=target, docs=docs_in,
        prompt=body.get("prompt") or "Summarize.",
        approval_id=body.get("approval_id") or None,
    )
    return {
        "session": session,
        "status": result.status,
        "rule_id": result.decision.rule_id,
        "reason": result.reason,
        "citation": result.decision.citation,
        "trace": result.decision.trace,
        "obligations": [str(o) for o in result.decision.obligations],
        "audit_seq": result.audit_seq,
        "approval_id": result.approval_id,
        "prompt_sent": result.prompt_sent,
        "text": result.text,
        "reidentified": result.reidentified,
        "redaction": result.redaction,
        "tokens_in": result.tokens_in, "tokens_out": result.tokens_out,
    }


def do_decide(ctx: Ctx, conn, body: dict) -> dict:
    pack = ctx.pack(conn)
    item = approvals.decide(
        conn, body["approval_id"], decision=body["decision"],
        decided_by=body.get("actor") or "web.visitor",
        roles=[r for r in (body.get("roles") or "").split(",") if r.strip()],
        session_id=body.get("session") or audit.new_session_id(),
        pack_ref=pack.ref, note=body.get("note") or "",
    )
    return {"approval": item}


def do_tamper(conn) -> dict:
    """Break the chain, show the break, and put it back - all in one call, so
    the demo never leaves the database in a broken state."""
    # A denial is the entry someone would actually want to rewrite, so prefer
    # one. Whatever we pick, the new value must genuinely differ from the old:
    # writing a row's existing value back is a no-op, the hash still matches,
    # and the demo would claim the chain survived tampering that never happened.
    # Two constraints on which entry to rewrite.
    #
    # It must actually change value: writing a row's existing value back is a
    # no-op, the hash still matches, and the demo would claim the chain
    # survived tampering that never happened.
    #
    # And it must have a successor. A hash chain protects an entry by way of
    # every entry that commits to it, so the *last* entry can be rewritten and
    # rehashed undetectably. That is a real property of the construction, not
    # a bug here - it is why a production deployment anchors the head
    # somewhere it does not control. Rewriting the tail would tell the
    # opposite of the intended story, so pick an entry with entries after it.
    head = conn.execute("SELECT MAX(seq) m FROM audit_log").fetchone()["m"]
    if head is None:
        return {"error": "the log is empty"}
    row = conn.execute(
        "SELECT seq, decision FROM audit_log WHERE decision = 'deny' AND seq < ? "
        "ORDER BY seq LIMIT 1", (head,)
    ).fetchone() or conn.execute(
        "SELECT seq, decision FROM audit_log WHERE decision IS NOT NULL AND seq < ? "
        "ORDER BY seq LIMIT 1", (head,)
    ).fetchone()
    if row is None:
        return {"error": "no decided entry has a successor yet - run another call, "
                         "then try again (the last entry in a chain has nothing "
                         "committing to it)"}
    seq = row["seq"]
    forged = "allow" if row["decision"] == "deny" else "deny"
    original = dict(conn.execute(
        "SELECT decision, entry_hash FROM audit_log WHERE seq = ?", (seq,)).fetchone())
    steps = []

    try:
        conn.execute("UPDATE audit_log SET decision=? WHERE seq = ?", (forged, seq))
        steps.append({"step": "edit the row in place", "blocked": False,
                      "detail": "unexpected: the append-only trigger did not fire"})
    except sqlite3.IntegrityError as exc:
        steps.append({"step": "edit the row in place", "blocked": True,
                      "detail": f"blocked by the storage trigger: {exc}"})

    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit_log SET decision=? WHERE seq = ?", (forged, seq))
    ok, bad, msg = audit.verify(conn)
    steps.append({"step": f"drop the trigger, then rewrite seq {seq} "
                          f"from '{original['decision']}' to '{forged}'",
                  "blocked": False, "chain_ok": ok, "broken_at": bad, "detail": msg})

    edited = dict(conn.execute("SELECT * FROM audit_log WHERE seq = ?", (seq,)).fetchone())
    conn.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = ?",
                 (audit.compute_hash(edited), seq))
    ok2, bad2, msg2 = audit.verify(conn)
    steps.append({"step": "recompute that entry's own hash too",
                  "blocked": False, "chain_ok": ok2, "broken_at": bad2, "detail": msg2})

    conn.execute("UPDATE audit_log SET decision=?, entry_hash=? WHERE seq=?",
                 (original["decision"], original["entry_hash"], seq))
    conn.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log "
                 "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END")
    ok3, _, msg3 = audit.verify(conn)
    steps.append({"step": "restore", "blocked": False, "chain_ok": ok3, "detail": msg3})
    return {"target_seq": seq, "head_seq": head, "steps": steps,
            "note": "The chain protects an entry through every entry that commits "
                    "to it, so the newest entry is the one it cannot protect. A "
                    "deployment closes that gap by anchoring the head hash "
                    "somewhere the operator does not control."}


# ------------------------------------------------------------------ routing
class Handler(BaseHTTPRequestHandler):
    ctx: Ctx = None
    server_version = "govpipe"

    def log_message(self, fmt, *args):
        pass                       # the audit log is the log that matters

    def _send(self, code: int, payload: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        try:
            if url.path in ("/", "/index.html"):
                return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
            conn = self.ctx.conn()
            if url.path == "/api/state":
                return self._send(200, _json(state(self.ctx, conn)))
            if url.path.startswith("/api/pack/"):
                return self._send(200, _json(pack_detail(url.path.rsplit("/", 1)[-1])))
            if url.path == "/api/audit":
                entries = audit.query(
                    conn,
                    since=(q.get("since") or [None])[0],
                    sensitivity=(q.get("sensitivity") or [None])[0],
                    data_type=(q.get("data_type") or [None])[0],
                    event=(q.get("event") or [None])[0],
                    decision=(q.get("decision") or [None])[0],
                    session_id=(q.get("session") or [None])[0],
                    limit=int((q.get("limit") or [200])[0]),
                    newest=True,
                )
                return self._send(200, _json({"entries": entries}))
            if url.path.startswith("/api/audit/"):
                seq = int(url.path.rsplit("/", 1)[-1])
                row = conn.execute("SELECT * FROM audit_log WHERE seq = ?", (seq,)).fetchone()
                if row is None:
                    return self._send(404, _json({"error": f"no entry {seq}"}))
                entry = dict(row)
                for f in audit.JSON_FIELDS:
                    entry[f] = json.loads(entry[f])
                return self._send(200, _json(entry))
            if url.path == "/api/retention":
                return self._send(200, _json({"items": retention.listing(conn)}))
            return self._send(404, _json({"error": "not found"}))
        except Exception as exc:
            return self._send(500, _json({"error": f"{type(exc).__name__}: {exc}",
                                          "trace": traceback.format_exc()[-800:]}))

    def do_POST(self):
        url = urlparse(self.path)
        try:
            body = self._body()
            conn = self.ctx.conn()
            if url.path == "/api/ingest":
                return self._send(200, _json(do_ingest(self.ctx, conn, body)))
            if url.path == "/api/ask":
                return self._send(200, _json(do_ask(self.ctx, conn, body)))
            if url.path == "/api/approvals":
                return self._send(200, _json(do_decide(self.ctx, conn, body)))
            if url.path == "/api/pack/use":
                load(body["pack"])
                previous = get_meta(conn, "active_pack", "hipaa")
                set_meta(conn, "active_pack", body["pack"])
                audit.append(conn, event="pack_switch", session_id=audit.new_session_id(),
                             actor=body.get("actor") or "web.visitor",
                             pack=load(body["pack"]).ref,
                             detail={"previous": previous, "new": body["pack"],
                                     "via": "web"})
                return self._send(200, _json({"active_pack": body["pack"]}))
            if url.path == "/api/verify":
                ok, bad, msg = audit.verify(conn)
                return self._send(200, _json({"ok": ok, "broken_at": bad, "message": msg}))
            if url.path == "/api/tamper":
                with self.ctx.lock:
                    return self._send(200, _json(do_tamper(conn)))
            return self._send(404, _json({"error": "not found"}))
        except (PackError, ConfigError, IngestError, approvals.ApprovalError) as exc:
            return self._send(400, _json({"error": str(exc)}))
        except Exception as exc:
            return self._send(500, _json({"error": f"{type(exc).__name__}: {exc}",
                                          "trace": traceback.format_exc()[-800:]}))


def lan_ip() -> str:
    """The address this host would use to reach the outside world.

    TEST-NET-1 (RFC 5737) is reserved for documentation and routes nowhere; a
    UDP connect sends no packets, so this is a pure routing-table lookup that
    works on any subnet rather than assuming a 192.168.0.x network.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def serve(host: str = "0.0.0.0", port: int = 9010, db: str | None = None) -> int:
    Handler.ctx = Ctx(str(db or DB_PATH))
    httpd = ThreadingHTTPServer((host, port), Handler)
    where = lan_ip() if host == "0.0.0.0" else host
    print(f"govpipe web  http://{where}:{port}   (db: {Handler.ctx.db})")
    if host == "0.0.0.0":
        print(f"             also http://127.0.0.1:{port}")
        print("             no authentication - keep this on a trusted network")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="govpipe-web")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9010)
    p.add_argument("--db", default=None)
    a = p.parse_args(argv)
    return serve(a.host, a.port, a.db)


if __name__ == "__main__":
    raise SystemExit(main())
