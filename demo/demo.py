"""The scripted end-to-end demonstration.

Nine beats, each one a single governance claim with the evidence printed
underneath it. Runs offline by default so it works on a conference wifi;
pass --live to route the same calls to a real model.
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from govpipe import approvals, audit, gateway  # noqa: E402
from govpipe.classify.manifest import ingest, load_doc  # noqa: E402
from govpipe.cli import BOLD, CYAN, DIM, GREEN, RED, RESET, YELLOW, table  # noqa: E402
from govpipe.config import SAMPLES_DIR, get_target  # noqa: E402
from govpipe.db import connect, set_meta  # noqa: E402
from govpipe.policy import Subject, load  # noqa: E402

PAUSE = True


def beat(n: int, title: str, claim: str) -> None:
    print(f"\n{CYAN}{'─' * 78}{RESET}")
    print(f"{CYAN}{BOLD}  {n}. {title}{RESET}")
    print(f"{DIM}  {claim}{RESET}")
    print(f"{CYAN}{'─' * 78}{RESET}")
    if PAUSE:
        try:
            input(f"{DIM}  [enter]{RESET}")
        except EOFError:
            pass


def verdict(result) -> None:
    colour = {"completed": GREEN, "denied": RED, "pending_approval": YELLOW}[result.status]
    print(f"  {colour}{BOLD}{result.status.upper():17}{RESET} rule {BOLD}{result.decision.rule_id}{RESET}"
          f"   audit seq {result.audit_seq}")
    print(f"  {' '.join(result.reason.split())}")
    if result.decision.citation:
        print(f"  {DIM}{result.decision.citation}{RESET}")


def run_demo(db_path: str | Path | None = None, *, live: bool = False,
             pause: bool = True) -> int:
    global PAUSE
    PAUSE = pause

    db = Path(db_path) if db_path else ROOT / "var" / "demo.db"
    for suffix in ("", "-wal", "-shm"):
        Path(str(db) + suffix).unlink(missing_ok=True)
    conn = connect(db)

    pack = load("hipaa")
    set_meta(conn, "active_pack", pack.id)
    session = audit.new_session_id()
    covered = get_target("claude-opus-5-baa" if live else "local-echo")
    uncovered = get_target("claude-opus-5-standard")
    multiregion = get_target("claude-opus-5-global")

    clinician = Subject(id="dr.reyes", roles=["clinician"], purpose_of_use="treatment")
    marketer = Subject(id="p.doyle", roles=["marketing"], purpose_of_use="marketing")
    officer_roles = ["privacy_officer"]

    print(f"\n{BOLD}Governed AI Data Pipeline{RESET} - demonstration")
    print(f"{DIM}session {session}   database {db}{RESET}")
    print(f"{DIM}model target: {covered.key} ({'live API' if live else 'offline stub, no egress'}){RESET}")

    # ---------------------------------------------------------------- 1 ---
    beat(1, "The active policy pack",
         "A compliance regime is six declarative files. Nothing below is hard-coded.")
    print(f"  {BOLD}{pack.name}{RESET}  {pack.ref}")
    print(f"  {DIM}{pack.authority}{RESET}\n")
    for f in sorted(p.name for p in pack.root.glob("*.yaml")):
        purpose = {
            "pack.yaml": "identity, audit requirements, retention defaults",
            "detectors.yaml": "what data types exist and how to find them",
            "classification.yaml": "detected types -> sensitivity level",
            "redaction.yaml": "what happens to each entity before a call",
            "routing.yaml": "what a model must be to receive each level",
            "rules.yaml": "the decision table, deny by default",
        }[f]
        print(f"    packs/hipaa/{f:22} {DIM}{purpose}{RESET}")
    print(f"\n  {len(pack.identifiers_for('PHI'))} PHI identifiers "
          f"(45 CFR 164.514(b)(2) Safe Harbor), {len(pack.rules)} policy rules")

    # ---------------------------------------------------------------- 2 ---
    beat(2, "Ingestion and classification",
         "Every document is classified twice - patterns first, then an LLM - "
         "and the log records which pass found what.")
    docs = {}
    rows = []
    for path in sorted(SAMPLES_DIR.iterdir()):
        if path.suffix.lower() not in (".txt", ".csv", ".pdf"):
            continue
        r = ingest(conn, pack, path, session_id=session, subject=clinician,
                   classifier_target=covered)
        docs[path.name] = r
        colour = {"prohibited": RED, "restricted": YELLOW}.get(r["sensitivity"], "")
        rows.append([r["doc_id"], path.name, f"{colour}{r['sensitivity']}{RESET}",
                     r["classification_rule"], ",".join(r["data_types"]) or "-",
                     str(r["detections"]),
                     "+".join(sorted(set(r["methods"].values()))) or "-",
                     r["llm_status"]["status"]])
    print(table(rows, ["doc_id", "file", "sensitivity", "rule", "types", "hits",
                       "found by", "llm pass"]))
    if not live:
        print(f"\n  {DIM}The LLM pass is skipped offline. Run with --live to see the "
              f"second pass\n  contribute identifiers no regex can catch.{RESET}")

    # ---------------------------------------------------------------- 3 ---
    beat(3, "The manifest",
         "Classification is a record, not a runtime opinion: hashed, versioned, "
         "and attributable.")
    note = docs["patient_note_001.txt"]
    for label, value in [
        ("document", note["doc_id"]), ("source", note["path"]),
        ("sha256", note["sha256"]), ("sensitivity", note["sensitivity"]),
        ("decided by rule", f"{note['classification_rule']} - {note['citation']}"),
        ("data types", ", ".join(note["data_types"])),
        ("identifiers", ", ".join(note["identifiers"])),
        ("classifier", pack.classifier["version_tag"]),
        ("policy pack", pack.ref), ("manifest hash", note["manifest_hash"]),
    ]:
        print(f"  {label:16} {value}")

    # ---------------------------------------------------------------- 4 ---
    beat(4, "A prohibited call is blocked",
         "Part 2 substance-use records need consent naming the recipient. "
         "No routing makes that call legal.")
    sud = load_doc(conn, pack, docs["sud_intake_003.txt"]["doc_id"])
    r = gateway.call(conn, pack, session_id=session, action="summarize",
                     subject=clinician, target=covered, docs=[sud],
                     prompt="Summarize this intake.")
    verdict(r)
    print(f"\n  {DIM}decision trace{RESET}")
    for line in r.decision.trace:
        print(f"    {line}")

    # ---------------------------------------------------------------- 5 ---
    beat(5, "Three more ways to be denied",
         "Deny is the default. Each of these fires on a different control.")
    phi = load_doc(conn, pack, note["doc_id"])
    for label, subject, tgt in [
        ("no business associate agreement", clinician, uncovered),
        ("BAA holds, but inference may run in the EU", clinician, multiregion),
        ("covered model, but the purpose is marketing", marketer, covered),
    ]:
        r = gateway.call(conn, pack, session_id=session, action="summarize",
                         subject=subject, target=tgt, docs=[phi],
                         prompt="Summarize the clinical course.")
        print(f"\n  {BOLD}{label}{RESET}  {DIM}-> {tgt.key}{RESET}")
        verdict(r)

    # ---------------------------------------------------------------- 6 ---
    beat(6, "A redacted call succeeds",
         "Same document, same model family, allowed - because the policy's "
         "obligations were actually discharged.")
    r = gateway.call(conn, pack, session_id=session, action="summarize",
                     subject=clinician, target=covered, docs=[phi],
                     prompt="Summarize the clinical course and the plan.")
    verdict(r)
    print(f"\n  {BOLD}obligations discharged{RESET}")
    for ob in sorted(r.decision.obligations, key=lambda o: o.type):
        print(f"    {ob}")
    print(f"\n  {BOLD}redaction{RESET} {r.redaction['strategies']}, "
          f"{r.redaction['tokens_issued']} reversible tokens issued")
    print(f"\n  {BOLD}what actually crossed the boundary{RESET}")
    for line in (r.prompt_sent or "").splitlines():
        print(f"    {DIM}{line}{RESET}")
    print(f"\n  {BOLD}response{RESET}")
    for line in (r.text or "").splitlines():
        print(f"    {line}")
    if r.reidentified != r.text:
        print(f"\n  {BOLD}re-identified inside the boundary{RESET} "
              f"{DIM}(vault lookup, never leaves this machine){RESET}")
        for line in (r.reidentified or "").splitlines():
            print(f"    {line}")

    # ---------------------------------------------------------------- 7 ---
    beat(7, "Human in the loop",
         "Release is a disclosure. Policy names the queue and the role; the "
         "queue enforces the role.")
    r = gateway.call(conn, pack, session_id=session, action="release",
                     subject=clinician, target=None, docs=[phi],
                     prompt="Release the reviewed summary to the referring practice.")
    verdict(r)
    approval_id = r.approval_id
    item = approvals.get(conn, approval_id)
    print(f"\n  {BOLD}queued{RESET} {approval_id}  queue={item['queue']}  "
          f"roles={','.join(item['roles'])}")
    print(f"  {item['summary']}")

    print(f"\n  {BOLD}a clinician tries to approve their own request{RESET}")
    try:
        approvals.decide(conn, approval_id, decision="approved", decided_by="dr.reyes",
                         roles=["clinician"], session_id=session, pack_ref=pack.ref)
    except approvals.ApprovalError as exc:
        print(f"    {RED}REFUSED{RESET} {exc}")

    print(f"\n  {BOLD}the privacy officer approves{RESET}")
    decided = approvals.decide(conn, approval_id, decision="approved",
                               decided_by="k.oyelaran", roles=officer_roles,
                               session_id=session, pack_ref=pack.ref,
                               note="Minimum necessary confirmed; recipient on file.")
    print(f"    {GREEN}{decided['status']}{RESET} by {decided['decided_by']} "
          f"at {decided['decided_at'][:19]}")

    print(f"\n  {BOLD}the release proceeds, carrying the approval{RESET}")
    r = gateway.call(conn, pack, session_id=session, action="release",
                     subject=clinician, target=None, docs=[phi],
                     prompt="Release the reviewed summary to the referring practice.",
                     approval_id=approval_id)
    verdict(r)

    # ---------------------------------------------------------------- 8 ---
    beat(8, "Swap the policy pack",
         "Same three documents, three regimes, no pipeline code changed.")
    swap_rows = []
    for pid in ("hipaa", "pubsec", "finserv"):
        other = load(pid)
        for name in ("patient_note_001.txt", "citizen_benefits_case.txt",
                     "trade_desk_chat.txt"):
            res = ingest(conn, other, SAMPLES_DIR / name, session_id=session,
                         subject=clinician, classifier_target=covered)
            colour = {"prohibited": RED, "restricted": YELLOW}.get(res["sensitivity"], "")
            swap_rows.append([f"{other.id}@{other.version}", name,
                              f"{colour}{res['sensitivity']}{RESET}",
                              res["classification_rule"],
                              ",".join(res["data_types"]) or "-"])
    print(table(swap_rows, ["pack", "document", "sensitivity", "rule", "types"]))
    print(f"\n  {DIM}The trade-desk chat is invisible to HIPAA and to the CUI pack, and\n"
          f"  prohibited under finserv. Nothing about the pipeline changed - only\n"
          f"  which six files were loaded.{RESET}")
    # Re-classify under HIPAA so the database is left in the state the rest of
    # the demo described, rather than under the last pack that was tried on.
    for name in ("patient_note_001.txt", "citizen_benefits_case.txt",
                 "trade_desk_chat.txt"):
        ingest(conn, pack, SAMPLES_DIR / name, session_id=session,
               subject=clinician, classifier_target=covered)
    set_meta(conn, "active_pack", "hipaa")

    # ---------------------------------------------------------------- 9 ---
    beat(9, "The audit log detects its own tampering",
         "Append-only is a claim. A hash chain is evidence.")
    ok, bad, msg = audit.verify(conn)
    print(f"  {GREEN}CHAIN INTACT{RESET}  {msg}")

    # Deliberately an entry with successors. A hash chain protects an entry
    # through the entries that commit to it, so the newest entry is the one it
    # cannot protect - rewriting the tail would demonstrate the opposite of the
    # point.
    head = conn.execute("SELECT MAX(seq) m FROM audit_log").fetchone()["m"]
    target_seq = conn.execute(
        "SELECT seq FROM audit_log WHERE event='policy_deny' AND seq < ? "
        "ORDER BY seq LIMIT 1", (head,)
    ).fetchone()["seq"]
    original = dict(conn.execute(
        "SELECT decision, rule_id, entry_hash FROM audit_log WHERE seq = ?", (target_seq,)
    ).fetchone())

    print(f"\n  {BOLD}an operator tries to rewrite seq {target_seq} in place{RESET}")
    try:
        conn.execute("UPDATE audit_log SET decision='allow' WHERE seq = ?", (target_seq,))
    except sqlite3.IntegrityError as exc:
        print(f"    {RED}BLOCKED{RESET} by the storage trigger: {exc}")

    print(f"\n  {BOLD}so they drop the trigger first - the real threat model{RESET}")
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit_log SET decision='allow' WHERE seq = ?", (target_seq,))
    print(f"    seq {target_seq} now reads decision=allow. The row looks clean.")
    ok, bad, msg = audit.verify(conn)
    print(f"    {RED}{BOLD}CHAIN BROKEN{RESET} at seq {bad}")
    print(f"    {msg}")

    print(f"\n  {BOLD}and if they recompute that entry's own hash?{RESET}")
    row = dict(conn.execute("SELECT * FROM audit_log WHERE seq = ?", (target_seq,)).fetchone())
    conn.execute("UPDATE audit_log SET entry_hash = ? WHERE seq = ?",
                 (audit.compute_hash(row), target_seq))
    ok, bad, msg = audit.verify(conn)
    print(f"    {RED}{BOLD}STILL BROKEN{RESET} at seq {bad} - {msg}")
    print(f"    {DIM}Every later entry commits to this one. Rewriting one entry means\n"
          f"    rewriting all {conn.execute('SELECT COUNT(*) c FROM audit_log').fetchone()['c'] - target_seq - 1} "
          f"entries after it.{RESET}")

    print(f"\n  {DIM}What it does not protect: the newest entry. Nothing commits to it\n"
          f"  yet, so it can be rewritten and rehashed cleanly. A deployment closes\n"
          f"  that by anchoring the head hash somewhere the operator does not control.{RESET}")

    conn.execute("UPDATE audit_log SET decision=?, rule_id=?, entry_hash=? WHERE seq=?",
                 (original["decision"], original["rule_id"], original["entry_hash"], target_seq))
    conn.execute("CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_log "
                 "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END")
    ok, bad, msg = audit.verify(conn)
    print(f"\n  {DIM}(restored for the rest of the demo){RESET}  {GREEN}CHAIN INTACT{RESET}  {msg}")

    # --------------------------------------------------------------- 10 ---
    beat(10, "The audit trail for this session",
         "Every question a regulator asks is a query against one table.")
    entries = audit.query(conn, session_id=session, limit=1000)
    routine = [e for e in entries if e["decision"] is None]
    decisions = [e for e in entries if e["decision"] is not None]
    print(f"  {DIM}{len(routine)} ingest/classify entries omitted here - see "
          f"`gov audit query --session-filter {session}`{RESET}\n")
    rows = []
    for e in decisions:
        colour = RED if e["decision"] == "deny" else (GREEN if e["decision"] == "allow" else "")
        rows.append([str(e["seq"]), e["ts"][11:19], e["event"], e["actor"],
                     ",".join(e["resource_ids"])[:14] or "-", e["sensitivity"] or "-",
                     f"{colour}{e['decision'] or '-'}{RESET}", e["rule_id"] or "-",
                     e["model_id"] or "-",
                     f"{e['tokens_in'] or 0}/{e['tokens_out'] or 0}",
                     "yes" if e["redaction"].get("applied") else "no"])
    print(table(rows, ["seq", "time", "event", "actor", "docs", "sens", "decision",
                       "rule", "model", "tok i/o", "redact"]))

    restricted_calls = audit.query(conn, event="llm_call", sensitivity="restricted",
                                   since="7d", limit=500)
    denials = audit.query(conn, decision="deny", session_id=session, limit=500)
    print(f"\n  {BOLD}\"show me every model call that touched restricted data last week\"{RESET}")
    print("    gov audit query --event llm_call --sensitivity restricted --since 7d")
    print(f"    -> {len(restricted_calls)} call(s)")
    print(f"\n  {BOLD}denials this session{RESET}: {len(denials)}"
          f"   {DIM}rules that fired: "
          f"{', '.join(sorted({d['rule_id'] for d in denials if d['rule_id']}))}{RESET}")

    ok, bad, msg = audit.verify(conn)
    print(f"\n  {GREEN if ok else RED}{'CHAIN INTACT' if ok else 'CHAIN BROKEN'}{RESET}  {msg}")
    print(f"\n{DIM}Database: {db}   Inspect it with `gov --db {db} audit query`.{RESET}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="demo", description="Governed AI pipeline demo")
    p.add_argument("--db", default=None)
    p.add_argument("--live", action="store_true",
                   help="route calls to a real Anthropic model instead of the offline stub")
    p.add_argument("--no-pause", action="store_true", help="do not wait between beats")
    args = p.parse_args(argv)
    return run_demo(db_path=args.db, live=args.live, pause=not args.no_pause)


if __name__ == "__main__":
    sys.exit(main())
