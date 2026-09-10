"""The audit chain is the one component where a silent bug is invisible."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from govpipe import audit
from govpipe.db import connect


def fresh(tmp_path):
    return connect(tmp_path / "t.db")


def test_chain_verifies(tmp_path):
    c = fresh(tmp_path)
    for i in range(5):
        audit.append(c, event="test", session_id="s1", detail={"i": i})
    ok, bad, msg = audit.verify(c)
    assert ok, msg
    assert bad is None
    assert "5 entries" in msg


def test_empty_chain_verifies(tmp_path):
    ok, bad, _ = audit.verify(fresh(tmp_path))
    assert ok and bad is None


def test_first_entry_links_to_genesis(tmp_path):
    c = fresh(tmp_path)
    e = audit.append(c, event="test", session_id="s1")
    assert e["seq"] == 0
    assert e["prev_hash"] == audit.GENESIS_PREV


def test_append_only_triggers_block_writes(tmp_path):
    import sqlite3
    c = fresh(tmp_path)
    audit.append(c, event="test", session_id="s1")
    for sql in ("UPDATE audit_log SET actor='mallory'", "DELETE FROM audit_log"):
        try:
            c.execute(sql)
            raise AssertionError(f"expected trigger to block: {sql}")
        except sqlite3.IntegrityError as exc:
            assert "append-only" in str(exc)


def _drop_triggers(c):
    """Simulate an attacker with direct database access."""
    c.execute("DROP TRIGGER audit_no_update")
    c.execute("DROP TRIGGER audit_no_delete")


def test_content_tampering_is_detected(tmp_path):
    c = fresh(tmp_path)
    for i in range(5):
        audit.append(c, event="test", session_id="s1", detail={"i": i})
    _drop_triggers(c)
    c.execute("UPDATE audit_log SET decision='allow' WHERE seq=2")
    ok, bad, msg = audit.verify(c)
    assert not ok
    assert bad == 2
    assert "content altered" in msg


def test_deletion_is_detected(tmp_path):
    c = fresh(tmp_path)
    for i in range(5):
        audit.append(c, event="test", session_id="s1", detail={"i": i})
    _drop_triggers(c)
    c.execute("DELETE FROM audit_log WHERE seq=2")
    ok, bad, msg = audit.verify(c)
    assert not ok
    assert bad == 3
    assert "deleted" in msg


def test_rehashing_after_edit_still_breaks_the_link(tmp_path):
    """A sophisticated attacker recomputes the edited entry's own hash."""
    c = fresh(tmp_path)
    for i in range(5):
        audit.append(c, event="test", session_id="s1", detail={"i": i})
    _drop_triggers(c)
    row = dict(c.execute("SELECT * FROM audit_log WHERE seq=2").fetchone())
    row["decision"] = "allow"
    c.execute(
        "UPDATE audit_log SET decision=?, entry_hash=? WHERE seq=2",
        ("allow", audit.compute_hash(row)),
    )
    ok, bad, msg = audit.verify(c)
    assert not ok
    # seq 2 now self-verifies, so the break surfaces at seq 3's prev_hash.
    assert bad == 3
    assert "broken link" in msg


def test_query_filters(tmp_path):
    c = fresh(tmp_path)
    audit.append(c, event="llm_call", session_id="s1", sensitivity="restricted",
                 data_types=["PHI"], model_id="claude-opus-5", decision="allow")
    audit.append(c, event="llm_call", session_id="s1", sensitivity="internal",
                 data_types=["PII"], model_id="claude-opus-5", decision="allow")
    audit.append(c, event="ingest", session_id="s2", sensitivity="restricted",
                 data_types=["PHI"])
    assert len(audit.query(c, sensitivity="restricted")) == 2
    assert len(audit.query(c, sensitivity="restricted", event="llm_call")) == 1
    assert len(audit.query(c, data_type="PHI")) == 2
    assert len(audit.query(c, data_type="PII")) == 1
    assert len(audit.query(c, session_id="s2")) == 1
    assert len(audit.query(c, since="1h")) == 3
    assert len(audit.query(c, since="0m")) == 0
    # JSON columns come back decoded
    assert audit.query(c, data_type="PHI")[0]["data_types"] == ["PHI"]
