import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest

from govpipe.classify.manifest import ingest
from govpipe.config import SAMPLES_DIR, get_target
from govpipe.db import connect
from govpipe.policy import Subject, load


@pytest.fixture
def pack():
    return load("hipaa")


@pytest.fixture
def conn(tmp_path):
    return connect(tmp_path / "gov.db")


@pytest.fixture
def offline():
    return get_target("local-echo")


@pytest.fixture
def clinician():
    return Subject(id="dr.reyes", roles=["clinician"], purpose_of_use="treatment")


@pytest.fixture
def corpus(conn, pack, clinician, offline):
    """Ingest every sample; return {filename: ingest result}."""
    out = {}
    for path in sorted(SAMPLES_DIR.iterdir()):
        if path.suffix.lower() not in (".txt", ".csv", ".pdf"):
            continue
        out[path.name] = ingest(conn, pack, path, session_id="s-test",
                                subject=clinician, classifier_target=offline)
    return out


@pytest.fixture
def doc_row(conn):
    """A minimal documents row so vault writes satisfy the foreign key."""
    def _make(doc_id="d1"):
        conn.execute(
            "INSERT OR IGNORE INTO documents (doc_id, source_path, sha256, media_type, "
            "byte_len, text_len, ingested_at) VALUES (?, '-', '-', 'text/plain', 0, 0, 't')",
            (doc_id,),
        )
        return doc_id
    return _make
