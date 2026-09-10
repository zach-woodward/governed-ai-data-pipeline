"""`gov` - the command line over the governed pipeline.

Every command that touches data goes through the same core the demo does.
There is no privileged path here.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import approvals, audit, retention
from .classify.manifest import IngestError, SUPPORTED, ingest, load_doc
from .config import DEFAULT_PACK, DB_PATH, SAMPLES_DIR, ConfigError, get_target
from .db import connect, get_meta, set_meta
from .gateway import call
from .policy import PackError, Subject, available, load

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    ("\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m")
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR") else ("",) * 7
)


def table(rows: list[list[str]], headers: list[str]) -> str:
    if not rows:
        return f"{DIM}(none){RESET}"
    widths = [max(len(str(r[i])) for r in [headers] + rows) for i in range(len(headers))]
    out = ["  ".join(f"{BOLD}{h:<{w}}{RESET}" for h, w in zip(headers, widths))]
    out += ["  ".join(f"{str(c):<{w}}" for c, w in zip(row, widths)) for row in rows]
    return "\n".join(out)


def active_pack_id(conn) -> str:
    return get_meta(conn, "active_pack", DEFAULT_PACK)


def subject_from(args) -> Subject:
    return Subject(
        id=args.actor,
        roles=[r.strip() for r in (args.roles or "").split(",") if r.strip()],
        purpose_of_use=args.purpose,
    )


# ------------------------------------------------------------------- packs
def cmd_pack(args, conn):
    if args.pack_cmd == "list":
        current = active_pack_id(conn)
        rows = []
        for pid in available():
            try:
                p = load(pid)
                rows.append([("* " if pid == current else "  ") + pid, p.version,
                             p.status, str(len(p.rules)), str(len(p.data_types)), p.name])
            except PackError as exc:
                rows.append([("* " if pid == current else "  ") + pid, "-", "INVALID",
                             "-", "-", str(exc)[:60]])
        print(table(rows, ["pack", "version", "status", "rules", "types", "name"]))
        return 0
    if args.pack_cmd == "use":
        new_pack = load(args.id)            # fail loudly before switching
        previous = active_pack_id(conn)
        set_meta(conn, "active_pack", args.id)
        audit.append(conn, event="pack_switch", session_id=args.session,
                     actor=args.actor, pack=new_pack.ref,
                     detail={"previous": previous, "new": args.id})
        print(f"{GREEN}active policy pack -> {args.id}{RESET}")
        return 0

    pack = load(args.id or active_pack_id(conn))
    print(f"{BOLD}{pack.name}{RESET}  ({pack.ref}, status: {pack.status})")
    print(f"{DIM}{pack.authority}{RESET}\n")
    print(f"{BOLD}data types{RESET}")
    for dt, ids in pack.data_types.items():
        methods = {}
        for i in ids:
            methods[i.method] = methods.get(i.method, 0) + 1
        breakdown = ", ".join(f"{n} {m}" for m, n in sorted(methods.items()))
        print(f"  {dt:6} {len(ids):3} identifiers ({breakdown})")
    print(f"\n{BOLD}classification{RESET}")
    for r in pack.classification_rules:
        print(f"  {r.get('id','?'):16} -> {r['level']}")
    print(f"\n{BOLD}routing requirements{RESET}")
    for level, req in pack.routing.items():
        print(f"  {level:12} {req or '(none)'}")
    print(f"\n{BOLD}rules{RESET}  (deny-by-default: {pack.default_decision})")
    for r in pack.rules:
        colour = RED if r.decision == "deny" else GREEN
        obs = ", ".join(str(o) for o in r.obligations) or "-"
        print(f"  {colour}{r.decision.upper():5}{RESET} {r.id:11} {r.citation}")
        print(f"        {DIM}{' '.join(r.description.split())[:96]}{RESET}")
        if r.decision == "allow":
            print(f"        obligations: {obs}")
    print(f"\n{BOLD}always{RESET}: {', '.join(str(o) for o in pack.always) or '-'}")
    return 0


# ------------------------------------------------------------------ ingest
def cmd_ingest(args, conn):
    pack = load(args.pack or active_pack_id(conn))
    subject = subject_from(args)
    target = get_target(args.classifier_target or pack.classifier.get("target"))
    paths: list[Path] = []
    for raw in args.paths or [str(SAMPLES_DIR)]:
        p = Path(raw)
        if p.is_dir():
            paths += sorted(f for f in p.iterdir() if f.suffix.lower() in SUPPORTED)
        else:
            paths.append(p)
    rows = []
    for p in paths:
        try:
            r = ingest(conn, pack, p, session_id=args.session, subject=subject,
                       classifier_target=target)
        except IngestError as exc:
            print(f"{RED}skipped{RESET} {p.name}: {exc}")
            continue
        colour = {"prohibited": RED, "restricted": YELLOW}.get(r["sensitivity"], "")
        methods = r["methods"]
        mix = "+".join(sorted({m for m in methods.values()})) or "-"
        rows.append([r["doc_id"], p.name, f"{colour}{r['sensitivity']}{RESET}",
                     r["classification_rule"], ",".join(r["data_types"]) or "-",
                     str(r["detections"]), mix, r["llm_status"]["status"]])
    print(table(rows, ["doc_id", "file", "sensitivity", "rule", "types",
                       "hits", "method", "llm pass"]))
    return 0


def cmd_docs(args, conn):
    if args.doc_id:
        row = conn.execute(
            "SELECT d.*, m.* FROM documents d LEFT JOIN manifests m USING(doc_id) "
            "WHERE d.doc_id = ?", (args.doc_id,)).fetchone()
        if row is None:
            print(f"{RED}no document '{args.doc_id}'{RESET}"); return 1
        r = dict(row)
        print(f"{BOLD}{r['doc_id']}{RESET}  {r['source_path']}")
        print(f"  sha256          {r['sha256']}")
        print(f"  media/size      {r['media_type']}, {r['byte_len']} bytes, {r['text_len']} chars")
        print(f"  ingested        {r['ingested_at']}")
        print(f"  sensitivity     {r.get('sensitivity')} (rule {r.get('classification_rule')})")
        print(f"  data types      {', '.join(json.loads(r.get('data_types') or '[]')) or '-'}")
        print(f"  identifiers     {', '.join(json.loads(r.get('identifiers') or '[]')) or '-'}")
        print(f"  classifier      {r.get('classifier_version')} under {r.get('pack_id')}@{r.get('pack_version')}")
        print(f"  manifest hash   {r.get('manifest_hash')}")
        det = conn.execute(
            "SELECT data_type, identifier, method, confidence, COUNT(*) n FROM detections "
            "WHERE doc_id = ? GROUP BY data_type, identifier, method ORDER BY data_type, identifier",
            (args.doc_id,)).fetchall()
        print(f"\n{BOLD}detections{RESET}")
        print(table([[d["data_type"], d["identifier"], d["method"],
                      f"{d['confidence']:.2f}", str(d["n"])] for d in det],
                    ["type", "identifier", "method", "conf", "n"]))
        return 0
    rows = [[r["doc_id"], Path(r["source_path"]).name, r["sensitivity"] or "-",
             ",".join(json.loads(r["data_types"] or "[]")) or "-", r["ingested_at"][:19]]
            for r in conn.execute(
                "SELECT d.doc_id, d.source_path, d.ingested_at, m.sensitivity, m.data_types "
                "FROM documents d LEFT JOIN manifests m USING(doc_id) ORDER BY d.ingested_at")]
    print(table(rows, ["doc_id", "file", "sensitivity", "types", "ingested"]))
    return 0


# --------------------------------------------------------------------- ask
def cmd_ask(args, conn):
    pack = load(args.pack or active_pack_id(conn))
    docs = [load_doc(conn, pack, d) for d in args.doc]
    target = None if args.target == "none" else get_target(args.target)
    result = call(
        conn, pack, session_id=args.session, action=args.action,
        subject=subject_from(args), target=target,
        docs=docs, prompt=args.prompt, approval_id=args.approval,
    )
    colour = {"completed": GREEN, "denied": RED, "pending_approval": YELLOW}[result.status]
    print(f"{colour}{result.status.upper()}{RESET}  rule {BOLD}{result.decision.rule_id}{RESET}"
          f"  audit seq {result.audit_seq}")
    print(f"  {result.reason}")
    if result.decision.citation:
        print(f"  {DIM}{result.decision.citation}{RESET}")
    if args.explain:
        print(f"\n{BOLD}decision trace{RESET}")
        for line in result.decision.trace:
            print(f"  {line}")
    if result.status == "pending_approval":
        print(f"\nqueued as {BOLD}{result.approval_id}{RESET} - "
              f"`gov approvals approve {result.approval_id} --actor <who> --roles <role>`")
        return 2
    if result.status == "denied":
        return 1
    if result.redaction.get("applied"):
        print(f"\n{BOLD}redaction{RESET} {result.redaction['strategies']}, "
              f"{result.redaction['tokens_issued']} tokens issued")
    if args.show_prompt:
        print(f"\n{BOLD}prompt as sent{RESET}\n{DIM}{result.prompt_sent}{RESET}")
    print(f"\n{BOLD}response (as returned, tokens in place){RESET}\n{result.text}")
    if result.reidentified != result.text:
        print(f"\n{BOLD}response (re-identified inside the boundary){RESET}\n{result.reidentified}")
    print(f"\n{DIM}tokens in/out: {result.tokens_in}/{result.tokens_out}{RESET}")
    return 0


# --------------------------------------------------------------- approvals
def cmd_approvals(args, conn):
    pack = load(args.pack or active_pack_id(conn))
    if args.approvals_cmd == "list":
        items = approvals.all_items(conn) if args.all else approvals.pending(conn, args.queue)
        rows = [[i["approval_id"], i["status"], i["queue"], ",".join(i["roles"]),
                 i["requester"], i["created_at"][:19], i["summary"][:44]] for i in items]
        print(table(rows, ["id", "status", "queue", "roles", "requester", "created", "summary"]))
        return 0
    if args.approvals_cmd == "show":
        item = approvals.get(conn, args.id)
        if item is None:
            print(f"{RED}no approval '{args.id}'{RESET}"); return 1
        print(json.dumps(item, indent=2, sort_keys=True))
        return 0
    decision = "approved" if args.approvals_cmd == "approve" else "denied"
    try:
        item = approvals.decide(
            conn, args.id, decision=decision, decided_by=args.actor,
            roles=[r.strip() for r in (args.roles or "").split(",") if r.strip()],
            session_id=args.session, pack_ref=pack.ref, note=args.note or "",
        )
    except approvals.ApprovalError as exc:
        print(f"{RED}refused{RESET}: {exc}")
        return 1
    print(f"{GREEN}{item['approval_id']} {item['status']}{RESET} by {item['decided_by']}")
    return 0


# ------------------------------------------------------------------- audit
def cmd_audit(args, conn):
    if args.audit_cmd == "verify":
        ok, bad, msg = audit.verify(conn)
        if ok:
            print(f"{GREEN}CHAIN INTACT{RESET}  {msg}")
            return 0
        print(f"{RED}CHAIN BROKEN{RESET} at seq {bad}\n  {msg}")
        return 1
    if args.audit_cmd == "show":
        row = conn.execute("SELECT * FROM audit_log WHERE seq = ?", (args.seq,)).fetchone()
        if row is None:
            print(f"{RED}no audit entry {args.seq}{RESET}"); return 1
        entry = dict(row)
        for f in audit.JSON_FIELDS:
            entry[f] = json.loads(entry[f])
        print(json.dumps(entry, indent=2, sort_keys=True))
        return 0

    entries = audit.query(
        conn, since=args.since, sensitivity=args.sensitivity, data_type=args.data_type,
        event=args.event, decision=args.decision, actor=args.actor_filter,
        model_id=args.model, session_id=args.session_filter, limit=args.limit,
        newest=getattr(args, "newest", False),
    )
    if args.json:
        print(json.dumps(entries, indent=2, sort_keys=True))
        return 0
    rows = []
    for e in entries:
        colour = RED if e["decision"] == "deny" else (GREEN if e["decision"] == "allow" else "")
        rows.append([
            str(e["seq"]), e["ts"][11:19], e["event"], e["actor"],
            ",".join(e["resource_ids"])[:22] or "-", e["sensitivity"] or "-",
            f"{colour}{e['decision'] or '-'}{RESET}", e["rule_id"] or "-",
            e["model_id"] or "-",
            f"{e['tokens_in'] or 0}/{e['tokens_out'] or 0}",
            "yes" if e["redaction"].get("applied") else "no",
        ])
    print(table(rows, ["seq", "time", "event", "actor", "resources", "sens",
                       "decision", "rule", "model", "tok i/o", "redact"]))
    print(f"\n{DIM}{len(entries)} entr{'y' if len(entries)==1 else 'ies'}{RESET}")
    return 0


def cmd_retention(args, conn):
    pack = load(args.pack or active_pack_id(conn))
    if args.retention_cmd == "sweep":
        r = retention.sweep(conn, session_id=args.session, pack_ref=pack.ref,
                            actor=args.actor, dry_run=not args.apply)
        verb = "purged" if args.apply else "eligible (dry run)"
        print(f"{r['eligible']} vault clock(s) {verb}"
              + (f", {r['tokens_destroyed']} re-identification token(s) destroyed"
                 if args.apply else "")
              + f"\n{r['worm_held']} held under WORM retention, "
              f"{r['immutable_held']} audit entries held (the log is never purged)")
        return 0
    rows = [[str(i["id"]), i["kind"], i["ref"][:32], i["expires_at"][:19],
             "yes" if i["worm"] else "no", i["purged_at"][:19] if i["purged_at"] else "-"]
            for i in retention.listing(conn)]
    print(table(rows, ["id", "kind", "ref", "expires", "worm", "purged"]))
    return 0


# --------------------------------------------------------------------- cli
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gov", description="Governed AI data pipeline")
    p.add_argument("--db", default=str(DB_PATH))
    p.add_argument("--pack", help="override the active policy pack for this command")
    p.add_argument("--session", default=None, help="session id to tag audit entries with")
    p.add_argument("--actor", default=os.environ.get("USER", "operator"))
    p.add_argument("--roles", default="operator")
    p.add_argument("--purpose", default="operations", help="purpose of use")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("pack", help="inspect and switch policy packs")
    pks = pk.add_subparsers(dest="pack_cmd", required=True)
    pks.add_parser("list")
    s = pks.add_parser("show"); s.add_argument("id", nargs="?")
    s = pks.add_parser("use"); s.add_argument("id")

    ing = sub.add_parser("ingest", help="classify documents into the pipeline")
    ing.add_argument("paths", nargs="*")
    ing.add_argument("--classifier-target", help="model target for the LLM pass")

    d = sub.add_parser("docs", help="list or show ingested documents")
    d.add_argument("doc_id", nargs="?")

    a = sub.add_parser("ask", help="make a governed model call")
    a.add_argument("--doc", action="append", required=True)
    a.add_argument("--action", default="summarize",
                   choices=["summarize", "extract", "classify", "release", "export"])
    a.add_argument("--prompt", required=True)
    a.add_argument("--target", default=None,
                   help="model target key, or 'none' for an action that calls no model")
    a.add_argument("--approval", default=None, help="an approval id already granted")
    a.add_argument("--show-prompt", action="store_true")
    a.add_argument("--explain", action="store_true", help="print the decision trace")

    ap = sub.add_parser("approvals", help="human review queue")
    aps = ap.add_subparsers(dest="approvals_cmd", required=True)
    l = aps.add_parser("list"); l.add_argument("--queue"); l.add_argument("--all", action="store_true")
    sh = aps.add_parser("show"); sh.add_argument("id")
    for verb in ("approve", "deny"):
        v = aps.add_parser(verb); v.add_argument("id"); v.add_argument("--note")

    au = sub.add_parser("audit", help="query and verify the audit log")
    aus = au.add_subparsers(dest="audit_cmd", required=True)
    aus.add_parser("verify")
    sh = aus.add_parser("show"); sh.add_argument("seq", type=int)
    q = aus.add_parser("query")
    q.add_argument("--since", help="7d, 24h, 30m, or an ISO timestamp")
    q.add_argument("--sensitivity"); q.add_argument("--data-type"); q.add_argument("--event")
    q.add_argument("--decision", choices=["allow", "deny"]); q.add_argument("--model")
    q.add_argument("--actor-filter", dest="actor_filter")
    q.add_argument("--session-filter", dest="session_filter")
    q.add_argument("--limit", type=int, default=200); q.add_argument("--json", action="store_true")
    t = aus.add_parser("tail", help="the most recent entries")
    t.set_defaults(audit_cmd="query", since=None, sensitivity=None, data_type=None,
                   event=None, decision=None, model=None, actor_filter=None,
                   session_filter=None, json=False, newest=True)
    t.add_argument("--limit", type=int, default=25)

    r = sub.add_parser("retention", help="retention clocks")
    rs = r.add_subparsers(dest="retention_cmd", required=True)
    rs.add_parser("list")
    sw = rs.add_parser("sweep"); sw.add_argument("--apply", action="store_true")

    sub.add_parser("demo", help="run the scripted end-to-end demonstration")

    w = sub.add_parser("serve", help="minimal web view over the same core")
    w.add_argument("--host", default="0.0.0.0",
                   help="0.0.0.0 makes it reachable from the LAN; there is no auth")
    w.add_argument("--port", type=int, default=9010)
    return p


HANDLERS = {"pack": cmd_pack, "ingest": cmd_ingest, "docs": cmd_docs, "ask": cmd_ask,
            "approvals": cmd_approvals, "audit": cmd_audit, "retention": cmd_retention}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.session is None:
        args.session = audit.new_session_id()
    if args.cmd == "demo":
        import importlib.util
        from .config import ROOT
        spec = importlib.util.spec_from_file_location("govpipe_demo", ROOT / "demo" / "demo.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.run_demo(db_path=None if args.db == str(DB_PATH) else args.db)
    if args.cmd == "serve":
        from .web import serve
        return serve(args.host, args.port, args.db)
    conn = connect(args.db)
    try:
        return HANDLERS[args.cmd](args, conn)
    except (PackError, ConfigError, IngestError) as exc:
        print(f"{RED}error{RESET}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
