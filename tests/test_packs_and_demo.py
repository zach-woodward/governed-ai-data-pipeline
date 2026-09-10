"""The stub packs must actually work, and the demo must actually run."""
import pathlib
import sys

from govpipe import audit, gateway
from govpipe.classify.manifest import ingest, load_doc
from govpipe.config import SAMPLES_DIR, get_target
from govpipe.policy import Subject, load

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_finserv_worm_flag_reaches_the_retention_row(conn, offline):
    """The clearest pluggability claim: a different pack changes retention
    behavior with no pipeline change."""
    pack = load("finserv")
    subject = Subject(id="s.ops", roles=["supervisor"], purpose_of_use="supervision")
    r = ingest(conn, pack, SAMPLES_DIR / "citizen_benefits_case.txt",
               session_id="s1", subject=subject, classifier_target=offline)
    doc = load_doc(conn, pack, r["doc_id"])
    result = gateway.call(conn, pack, session_id="s1", action="summarize",
                          subject=subject, target=offline, docs=[doc],
                          prompt="Triage this communication.")
    assert result.status == "completed", result.reason
    rows = list(conn.execute("SELECT * FROM retention"))
    assert rows and all(r["worm"] == 1 for r in rows)
    assert all(r["expires_at"] > audit.now() for r in rows)


def test_finserv_queues_supervisory_review(conn, offline):
    from govpipe import approvals
    pack = load("finserv")
    subject = Subject(id="s.ops", roles=["supervisor"], purpose_of_use="supervision")
    r = ingest(conn, pack, SAMPLES_DIR / "citizen_benefits_case.txt",
               session_id="s1", subject=subject, classifier_target=offline)
    gateway.call(conn, pack, session_id="s1", action="summarize", subject=subject,
                 target=offline, docs=[load_doc(conn, pack, r["doc_id"])],
                 prompt="Triage.")
    queued = approvals.pending(conn, "desk-supervision")
    assert len(queued) == 1


def test_finserv_blocks_mnpi_for_trading(conn, offline):
    pack = load("finserv")
    trader = Subject(id="j.moreau", roles=["trader"], purpose_of_use="trading")
    r = ingest(conn, pack, SAMPLES_DIR / "trade_desk_chat.txt", session_id="s1",
               subject=trader, classifier_target=offline)
    result = gateway.call(conn, pack, session_id="s1", action="summarize", subject=trader,
                          target=offline, docs=[load_doc(conn, pack, r["doc_id"])],
                          prompt="What does this say?")
    assert result.status == "denied"
    assert result.decision.rule_id == "FS-001"      # concealment -> prohibited


def test_pubsec_denies_non_us_residency(conn, offline):
    pack = load("pubsec")
    officer = Subject(id="a.reed", roles=["analyst"], purpose_of_use="operations")
    r = ingest(conn, pack, SAMPLES_DIR / "citizen_benefits_case.txt", session_id="s1",
               subject=officer, classifier_target=offline)
    result = gateway.call(conn, pack, session_id="s1", action="summarize", subject=officer,
                          target=get_target("claude-opus-5-global"),
                          docs=[load_doc(conn, pack, r["doc_id"])], prompt="Summarize.")
    assert result.status == "denied"
    assert result.decision.rule_id in ("PS-002", "ROUTING:restricted")


def test_the_demo_runs_and_leaves_a_verifiable_chain(tmp_path, capsys):
    sys.path.insert(0, str(ROOT))
    import importlib.util
    spec = importlib.util.spec_from_file_location("demo_mod", ROOT / "demo" / "demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    db = tmp_path / "demo.db"
    assert module.run_demo(db_path=db, pause=False) == 0

    out = capsys.readouterr().out
    for expected in ("HIPAA-001", "HIPAA-002", "HIPAA-010", "HIPAA-020",
                     "ROUTING:restricted", "CHAIN BROKEN", "CHAIN INTACT",
                     "[WITHHELD - minimum necessary]", "REFUSED"):
        assert expected in out, f"demo never showed {expected}"
    # Nothing real should be identifiable in what the demo says it sent.
    sent = out.split("what actually crossed the boundary")[1].split("response")[0]
    for leaked in ("Dolores Ashgrove", "412-88-9931", "4471982"):
        assert leaked not in sent

    from govpipe.db import connect
    ok, bad, msg = audit.verify(connect(db))
    assert ok, msg


def test_the_web_tamper_demo_actually_breaks_the_chain(conn, pack, corpus, offline):
    """It once wrote 'allow' onto an entry that was already 'allow' - a no-op
    that left the hash valid, so the demo claimed the chain survived tampering
    that never happened."""
    from govpipe import web
    from govpipe.classify.manifest import load_doc

    subject = Subject(id="dr.reyes", roles=["clinician"], purpose_of_use="treatment")
    doc = load_doc(conn, pack, corpus["patient_note_001.txt"]["doc_id"])
    # An allow first, so the picker has to prefer the deny; then a deny; then a
    # third call so the deny has a successor committing to it.
    gateway.call(conn, pack, session_id="s1", action="release", subject=subject,
                 target=None, docs=[doc], prompt="Release.")
    gateway.call(conn, pack, session_id="s1", action="summarize", subject=subject,
                 target=get_target("claude-opus-5-standard"), docs=[doc], prompt="Go.")
    gateway.call(conn, pack, session_id="s1", action="summarize", subject=subject,
                 target=offline, docs=[doc], prompt="Go.")

    r = web.do_tamper(conn)
    assert "error" not in r
    steps = r["steps"]
    assert steps[0]["blocked"] is True                    # trigger stops the naive edit
    assert steps[1]["chain_ok"] is False                  # rewriting really breaks it
    assert steps[2]["chain_ok"] is False                  # rehashing moves the break
    assert steps[2]["broken_at"] == steps[1]["broken_at"] + 1
    assert steps[3]["chain_ok"] is True                   # and it is put back
    assert r["target_seq"] < r["head_seq"]                # never the unprotected tail
    ok, _, msg = audit.verify(conn)
    assert ok, msg
