import pathlib

from govpipe.classify.detectors import Detection, resolve_overlaps, scan
from govpipe.classify.manifest import classify_level, ingest
from govpipe.config import SAMPLES_DIR
from govpipe.policy import load

SAMPLES = [p for p in SAMPLES_DIR.iterdir() if p.suffix.lower() in (".txt", ".csv", ".pdf")]


def test_every_sample_is_marked_synthetic():
    """Nothing in this repository should be mistakable for a real record."""
    for path in SAMPLES:
        text = path.read_text(encoding="utf-8", errors="replace") if path.suffix != ".pdf" \
            else path.read_bytes().decode("latin-1", "replace")
        assert "SYNTHETIC" in text.upper(), f"{path.name} carries no synthetic marker"


def test_expected_classifications(corpus):
    expected = {
        "patient_note_001.txt": ("restricted", "CLS-PHI-MULTI"),
        "patient_note_002.txt": ("restricted", "CLS-PHI-MULTI"),
        "referral_letter.pdf": ("restricted", "CLS-PHI-MULTI"),
        "patient_roster.csv": ("restricted", "CLS-PHI-MULTI"),
        "sud_intake_003.txt": ("prohibited", "CLS-P2"),
        "clinic_operations_memo.txt": ("internal", "CLS-DEFAULT"),
        "trade_desk_chat.txt": ("internal", "CLS-DEFAULT"),
    }
    for name, (level, rule) in expected.items():
        assert corpus[name]["sensitivity"] == level, name
        assert corpus[name]["classification_rule"] == rule, name


def test_an_operations_memo_is_not_phi(corpus):
    """The regression that mattered: a blanket IGNORECASE made the name
    detector match 'SUBJECT:\\nWaiting room furniture'."""
    memo = corpus["clinic_operations_memo.txt"]
    assert memo["data_types"] == []
    assert memo["detections"] == 0


def test_all_18_safe_harbor_identifiers_are_defined(pack):
    ids = {i.id for i in pack.identifiers_for("PHI")}
    for expected in ("name", "geographic", "dates", "phone", "fax", "email", "ssn",
                     "mrn", "health_plan_id", "account", "license", "vehicle",
                     "device", "url", "ip_address", "biometric", "photo",
                     "other_unique_code"):
        assert expected in ids, f"missing Safe Harbor identifier: {expected}"


def test_capture_group_limits_the_span_to_the_value(pack):
    hits = scan(pack, "MRN: 4471982\n")
    mrn = next(h for h in hits if h.identifier == "mrn")
    assert mrn.value == "4471982"          # not "MRN: 4471982"


def test_detection_is_deterministic(pack):
    text = (SAMPLES_DIR / "patient_note_001.txt").read_text()
    first = [(d.identifier, d.start, d.end) for d in scan(pack, text)]
    for _ in range(3):
        assert [(d.identifier, d.start, d.end) for d in scan(pack, text)] == first


def test_overlaps_resolve_to_the_more_confident_detection():
    a = Detection("PHI", "low", "regex", 0.5, 0, 10, "x")
    b = Detection("PHI", "high", "regex", 0.9, 5, 15, "y")
    kept = resolve_overlaps([a, b])
    assert [d.identifier for d in kept] == ["high"]


def test_classification_is_first_match_wins(pack):
    assert classify_level(pack, ["SUD", "PHI"], ["part2_record", "mrn"])["level"] == "prohibited"
    assert classify_level(pack, ["PHI"], ["mrn", "name"])["level"] == "restricted"
    assert classify_level(pack, [], [])["level"] == "internal"


def test_manifest_hash_is_stable_and_recorded(conn, pack, clinician, offline, corpus):
    note = corpus["patient_note_001.txt"]
    again = ingest(conn, pack, pathlib.Path(note["path"]), session_id="s-test",
                   subject=clinician, classifier_target=offline)
    assert again["manifest_hash"] == note["manifest_hash"]
    row = conn.execute("SELECT manifest_hash, pack_id, classifier_version FROM manifests "
                       "WHERE doc_id = ?", (note["doc_id"],)).fetchone()
    assert row["manifest_hash"] == note["manifest_hash"]
    assert row["pack_id"] == "hipaa"
    assert row["classifier_version"] == "hipaa-clf-1.0.0"


def test_swapping_the_pack_changes_the_verdict(conn, clinician, offline):
    chat = SAMPLES_DIR / "trade_desk_chat.txt"
    under_hipaa = ingest(conn, load("hipaa"), chat, session_id="s-test",
                         subject=clinician, classifier_target=offline)
    under_finserv = ingest(conn, load("finserv"), chat, session_id="s-test",
                           subject=clinician, classifier_target=offline)
    assert under_hipaa["sensitivity"] == "internal"
    assert under_finserv["sensitivity"] == "prohibited"
    assert under_finserv["data_types"] == ["MNPI"]


def test_every_pack_loads_and_is_deny_by_default():
    from govpipe.policy import available
    for pid in available():
        p = load(pid)
        assert p.default_decision == "deny"
        assert p.rules, pid
        assert p.data_types, pid


def test_ingest_writes_an_audit_pair(conn, corpus):
    events = [r["event"] for r in conn.execute(
        "SELECT event FROM audit_log WHERE resource_ids LIKE ? ORDER BY seq",
        (f'%{corpus["patient_note_002.txt"]["doc_id"]}%',))]
    assert events[:2] == ["ingest", "classify"]


def test_a_changed_document_will_not_load_under_a_stale_manifest(conn, pack, corpus, tmp_path):
    """A manifest is a claim about specific bytes. Swapping the file behind it
    must not let unclassified content reach the gateway under an old label."""
    import pytest
    from govpipe.classify.manifest import IngestError, load_doc

    memo = corpus["clinic_operations_memo.txt"]
    doc_id = memo["doc_id"]
    assert load_doc(conn, pack, doc_id).doc_id == doc_id   # loads while unchanged

    tampered = tmp_path / "swapped.txt"
    tampered.write_text("SYNTHETIC\nPatient: Ada Lovelace\nSSN: 412-88-9931\n")
    conn.execute("UPDATE documents SET source_path = ? WHERE doc_id = ?",
                 (str(tampered), doc_id))
    with pytest.raises(IngestError, match="no longer matches its manifest"):
        load_doc(conn, pack, doc_id)


def test_detection_digests_are_keyed_not_bare_sha256(conn, corpus):
    """A bare SHA-256 of a social security number is reversible in seconds."""
    import hashlib
    row = conn.execute(
        "SELECT value_hash FROM detections WHERE identifier = 'ssn' LIMIT 1").fetchone()
    assert row is not None
    assert row["value_hash"] != hashlib.sha256(b"412-88-9931").hexdigest()


def test_the_key_is_per_database(tmp_path):
    from govpipe.db import connect, detection_key
    a = detection_key(connect(tmp_path / "a.db"))
    b = detection_key(connect(tmp_path / "b.db"))
    assert a != b and len(a) == 32


def test_a_manifest_from_one_pack_cannot_be_used_under_another(conn, corpus):
    """The bug this test exists for: a HIPAA-manifested document evaluated
    under finserv kept its 'PHI' label in the audit record while finserv's
    detectors - which have no PHI concept - did the redacting. The patient's
    name crossed the boundary under a log that said PHI was handled."""
    import pytest
    from govpipe.classify.manifest import IngestError, load_doc

    doc_id = corpus["patient_note_001.txt"]["doc_id"]
    with pytest.raises(IngestError, match="Labels are not portable between packs"):
        load_doc(conn, load("finserv"), doc_id)
