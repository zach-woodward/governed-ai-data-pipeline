from govpipe import redact
from govpipe.classify.detectors import Detection, scan


def test_tokenize_is_stable_within_a_document(conn, pack, doc_row):
    doc_row()
    text = "Patient: Ada Lovelace saw us. Patient: Ada Lovelace returned. MRN: 4471982"
    hits = scan(pack, text)
    r = redact.apply(conn, pack, "d1", text, hits)
    assert r.text.count("[PATIENT_1]") == 2, r.text
    assert "[MRN_1]" in r.text
    assert len(r.tokens) == 2                     # one per distinct value


def test_ssn_is_dropped_not_tokenized(conn, pack, doc_row):
    doc_row()
    text = "SSN: 412-88-9931"
    r = redact.apply(conn, pack, "d1", text, scan(pack, text))
    assert r.text.strip() == "SSN: [REDACTED:SSN]"
    assert not r.tokens                            # nothing recoverable in the vault
    assert conn.execute("SELECT COUNT(*) c FROM vault").fetchone()["c"] == 0


def test_card_is_masked_keeping_the_last_four(conn, pack, doc_row):
    doc_row()
    text = "Card on file: 4111 1111 1111 1111"
    r = redact.apply(conn, pack, "d1", text, scan(pack, text))
    assert r.text.endswith("xxxxxxxxxxxx1111")


def test_reidentification_round_trips(conn, pack, doc_row):
    doc_row()
    text = "Patient: Ada Lovelace\nMRN: 4471982\n"
    r = redact.apply(conn, pack, "d1", text, scan(pack, text))
    back, n = redact.reidentify(conn, ["d1"], r.text)
    assert back == text
    assert n == 2


def test_reidentification_does_not_eat_longer_tokens(conn, pack, doc_row):
    """[PATIENT_1] must not be substituted inside [PATIENT_10]."""
    doc_row()
    conn.execute("INSERT INTO vault VALUES (?,?,?,?,?,?)",
                 ("[PATIENT_1]", "d1", "PHI", "name", "Ada", "t"))
    conn.execute("INSERT INTO vault VALUES (?,?,?,?,?,?)",
                 ("[PATIENT_10]", "d1", "PHI", "name", "Grace", "t"))
    out, _ = redact.reidentify(conn, ["d1"], "[PATIENT_10] met [PATIENT_1]")
    assert out == "Grace met Ada"


def test_offsets_survive_replacements_of_different_length(conn, pack, doc_row):
    doc_row()
    text = "MRN: 4471982 and SSN: 412-88-9931 and Phone: (802) 555-0147"
    r = redact.apply(conn, pack, "d1", text, scan(pack, text))
    assert "4471982" not in r.text
    assert "412-88-9931" not in r.text
    assert "555-0147" not in r.text


def test_only_named_data_types_are_redacted(conn, pack, doc_row):
    doc_row()
    text = "MRN: 4471982\nCard on file: 4111 1111 1111 1111"
    r = redact.apply(conn, pack, "d1", text, scan(pack, text), data_types=["PCI"])
    assert "4471982" in r.text                     # PHI left alone
    assert "4111 1111" not in r.text


def test_unlocatable_llm_detections_are_skipped(conn, pack, doc_row):
    doc_row()
    text = "MRN: 4471982"
    hits = scan(pack, text) + [
        Detection("PHI", "clinical_narrative", "llm", 0.7, -1, -1, "")
    ]
    r = redact.apply(conn, pack, "d1", text, hits)
    assert "[MRN_1]" in r.text                     # no crash, no bogus replacement


def test_summary_records_what_was_done_not_what_it_said(conn, pack, doc_row):
    doc_row()
    text = "Patient: Ada Lovelace\nSSN: 412-88-9931"
    summary = redact.apply(conn, pack, "d1", text, scan(pack, text)).summary()
    assert summary["applied"] is True
    assert summary["strategies"] == {"drop": 1, "tokenize": 1}
    blob = str(summary)
    assert "Ada" not in blob and "412-88" not in blob
