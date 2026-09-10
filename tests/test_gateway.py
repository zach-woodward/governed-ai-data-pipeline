"""The gateway is the property the whole design rests on: no model call
happens outside it, and an allow whose obligations fail is a deny."""
import json

import pytest

from govpipe import approvals, audit, gateway, obligations
from govpipe.classify.manifest import load_doc
from govpipe.config import get_target
from govpipe.policy import Obligation


def phi_doc(conn, pack, corpus):
    return load_doc(conn, pack, corpus["patient_note_001.txt"]["doc_id"])


def sud_doc(conn, pack, corpus):
    return load_doc(conn, pack, corpus["sud_intake_003.txt"]["doc_id"])


# ------------------------------------------------------------------ denials
def test_denials_are_audited_and_send_nothing(conn, pack, corpus, clinician):
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=get_target("claude-opus-5-standard"),
                     docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    assert r.status == "denied"
    assert r.prompt_sent is None and r.text is None
    entry = dict(conn.execute("SELECT * FROM audit_log WHERE seq = ?", (r.audit_seq,)).fetchone())
    assert entry["event"] == "policy_deny"
    assert entry["decision"] == "deny"
    assert entry["rule_id"] == "HIPAA-002"


def test_prohibited_data_never_reaches_a_model(conn, pack, corpus, clinician, offline):
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=offline,
                     docs=[sud_doc(conn, pack, corpus)], prompt="Summarize.")
    assert r.status == "denied"
    assert r.decision.rule_id == "HIPAA-001"
    assert conn.execute("SELECT COUNT(*) c FROM audit_log WHERE event='llm_call'"
                        ).fetchone()["c"] == 0


def test_a_mixed_batch_takes_the_highest_classification(conn, pack, corpus, clinician, offline):
    """One prohibited document poisons the batch - which is the point."""
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=offline,
                     docs=[phi_doc(conn, pack, corpus), sud_doc(conn, pack, corpus)],
                     prompt="Summarize both.")
    assert r.status == "denied"
    assert r.decision.rule_id == "HIPAA-001"


# ------------------------------------------------------------------- allows
def test_allowed_call_redacts_before_sending(conn, pack, corpus, clinician, offline):
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=offline,
                     docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    assert r.status == "completed"
    for leaked in ("Dolores Ashgrove", "4471982", "412-88-9931", "4111 1111"):
        assert leaked not in r.prompt_sent, f"{leaked} crossed the boundary"
    assert "[AGE_1]" in r.prompt_sent


def test_minimum_necessary_runs_after_redaction(conn, pack, corpus, clinician, offline):
    """Ordering bug that shipped once: redaction re-read the original text and
    silently undid the section removal."""
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=offline,
                     docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    assert "[WITHHELD - minimum necessary]" in r.prompt_sent
    assert "INSURANCE AND BILLING: [WITHHELD" in r.prompt_sent
    assert "Furosemide" in r.prompt_sent          # kept sections survive


def test_stale_spans_fail_closed(conn, pack, corpus, clinician, offline):
    doc = phi_doc(conn, pack, corpus)
    state = {"doc_texts": {doc.doc_id: "text that has already been rewritten"}}
    ctx = {"conn": conn, "pack": pack, "docs": [doc], "target": offline, "approval_id": None}
    with pytest.raises(obligations.ObligationError, match="offsets are stale"):
        obligations._discharge_redact(state, Obligation("redact", {"types": ["PHI"]}), ctx)


def test_audit_entry_captures_the_prompt_that_was_actually_sent(
        conn, pack, corpus, clinician, offline):
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=offline,
                     docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    entry = dict(conn.execute("SELECT * FROM audit_log WHERE seq = ?", (r.audit_seq,)).fetchone())
    detail = json.loads(entry["detail"])
    assert detail["prompt_sent"] == r.prompt_sent
    assert entry["model_id"] == "local-echo"
    assert entry["tokens_in"] and entry["tokens_out"]
    assert json.loads(entry["redaction"])["applied"] is True


def test_unknown_obligation_fails_closed(conn, pack, corpus, clinician, offline, monkeypatch):
    """A pack that names an obligation the gateway cannot discharge must deny,
    never quietly proceed as if it had."""
    from govpipe.policy import engine

    real = engine.evaluate

    def spiked(p, ctx):
        d = real(p, ctx)
        if d.allowed:
            d.obligations = d.obligations + [Obligation("teleport", {})]
        return d

    monkeypatch.setattr(gateway, "evaluate", spiked)
    r = gateway.call(conn, pack, session_id="s1", action="summarize",
                     subject=clinician, target=offline,
                     docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    assert r.status == "denied"
    assert "teleport" in r.reason
    entry = conn.execute("SELECT event FROM audit_log WHERE seq = ?", (r.audit_seq,)).fetchone()
    assert entry["event"] == "obligation_failure"


def test_obligations_discharge_in_the_defined_order():
    from govpipe.obligations import DISCHARGE_ORDER
    assert DISCHARGE_ORDER.index("approve") < DISCHARGE_ORDER.index("redact")
    assert DISCHARGE_ORDER.index("redact") < DISCHARGE_ORDER.index("minimum_necessary")


# ---------------------------------------------------------------- approvals
def test_release_blocks_until_approved(conn, pack, corpus, clinician):
    doc = phi_doc(conn, pack, corpus)
    r = gateway.call(conn, pack, session_id="s1", action="release", subject=clinician,
                     target=None, docs=[doc], prompt="Release.")
    assert r.status == "pending_approval"
    assert r.approval_id
    assert r.text is None

    with pytest.raises(approvals.ApprovalError, match="requires one of"):
        approvals.decide(conn, r.approval_id, decision="approved", decided_by="dr.reyes",
                         roles=["clinician"], session_id="s1", pack_ref=pack.ref)

    approvals.decide(conn, r.approval_id, decision="approved", decided_by="k.o",
                     roles=["privacy_officer"], session_id="s1", pack_ref=pack.ref)
    done = gateway.call(conn, pack, session_id="s1", action="release", subject=clinician,
                        target=None, docs=[doc], prompt="Release.",
                        approval_id=r.approval_id)
    assert done.status == "completed"


def test_a_denied_approval_does_not_unblock(conn, pack, corpus, clinician):
    doc = phi_doc(conn, pack, corpus)
    r = gateway.call(conn, pack, session_id="s1", action="release", subject=clinician,
                     target=None, docs=[doc], prompt="Release.")
    approvals.decide(conn, r.approval_id, decision="denied", decided_by="k.o",
                     roles=["privacy_officer"], session_id="s1", pack_ref=pack.ref)
    blocked = gateway.call(conn, pack, session_id="s1", action="release", subject=clinician,
                           target=None, docs=[doc], prompt="Release.",
                           approval_id=r.approval_id)
    assert blocked.status == "denied"
    assert "not approved" in blocked.reason


def test_a_forged_approval_id_fails_closed(conn, pack, corpus, clinician):
    r = gateway.call(conn, pack, session_id="s1", action="release", subject=clinician,
                     target=None, docs=[phi_doc(conn, pack, corpus)], prompt="Release.",
                     approval_id="a-doesnotexist")
    assert r.status == "denied"
    assert "does not exist" in r.reason


# ----------------------------------------------------------------- contract
def test_the_pack_audit_contract_is_enforced(conn, pack, corpus, clinician, offline):
    pack.audit["required_fields"] = list(pack.audit["required_fields"]) + ["nonexistent_field"]
    r = gateway.call(conn, pack, session_id="s1", action="summarize", subject=clinician,
                     target=offline, docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    assert r.status == "denied"
    assert "nonexistent_field" in r.reason
    entry = conn.execute("SELECT event FROM audit_log WHERE seq = ?", (r.audit_seq,)).fetchone()
    assert entry["event"] == "audit_contract_failure"


def test_retention_clocks_name_something_the_sweep_can_act_on(
        conn, pack, corpus, clinician, offline):
    doc = phi_doc(conn, pack, corpus)
    gateway.call(conn, pack, session_id="s1", action="summarize", subject=clinician,
                 target=offline, docs=[doc], prompt="Summarize.")
    rows = {r["kind"]: dict(r) for r in conn.execute("SELECT * FROM retention")}
    assert set(rows) == {"audit", "vault"}
    assert rows["vault"]["ref"] == doc.doc_id             # a row the sweep can delete
    assert rows["audit"]["ref"].startswith("seq:")
    # HIPAA keeps the log for six years and the re-identification vault for 30 days.
    assert rows["audit"]["expires_at"] > rows["vault"]["expires_at"]


def test_the_sweep_destroys_re_identification_but_never_the_log(
        conn, pack, corpus, clinician, offline):
    """Retention expiry here means tokens become permanently unresolvable.
    The hash-chained log cannot be purged and must not be."""
    from govpipe import retention

    doc = phi_doc(conn, pack, corpus)
    r = gateway.call(conn, pack, session_id="s1", action="summarize", subject=clinician,
                     target=offline, docs=[doc], prompt="Summarize.")
    assert conn.execute("SELECT COUNT(*) c FROM vault").fetchone()["c"] > 0

    # Force every clock past its expiry.
    conn.execute("UPDATE retention SET expires_at = '2000-01-01T00:00:00'")
    before = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]

    dry = retention.sweep(conn, session_id="s1", pack_ref=pack.ref, dry_run=True)
    assert dry["tokens_destroyed"] == 0
    assert conn.execute("SELECT COUNT(*) c FROM vault").fetchone()["c"] > 0

    done = retention.sweep(conn, session_id="s1", pack_ref=pack.ref, dry_run=False)
    assert done["tokens_destroyed"] > 0
    assert done["immutable_held"] >= 1                    # the audit entry, held
    assert conn.execute("SELECT COUNT(*) c FROM vault").fetchone()["c"] == 0

    # The log grew (two sweep entries) and still verifies. Nothing was removed.
    assert conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"] > before
    ok, _, msg = audit.verify(conn)
    assert ok, msg

    # And the tokens in the recorded prompt can no longer be resolved.
    restored, n = __import__("govpipe.redact", fromlist=["x"]).reidentify(
        conn, [doc.doc_id], r.prompt_sent)
    assert n == 0


def test_the_whole_run_leaves_a_verifiable_chain(conn, pack, corpus, clinician, offline):
    gateway.call(conn, pack, session_id="s1", action="summarize", subject=clinician,
                 target=offline, docs=[phi_doc(conn, pack, corpus)], prompt="Summarize.")
    ok, bad, msg = audit.verify(conn)
    assert ok, msg
