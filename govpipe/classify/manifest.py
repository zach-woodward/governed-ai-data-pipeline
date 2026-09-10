"""Ingestion and manifesting.

Every document that enters the pipeline gets a manifest: content hash,
source, sensitivity, the data types found, which method found each one, the
classifier version, and a timestamp. The manifest is hashed too, so a
document's classification can be shown to be the one that was actually
in force when a model call was made.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import sqlite3
from pathlib import Path
from typing import Any

from .. import audit, gateway
from ..db import detection_key
from ..policy import Pack, Subject, Target
from . import detectors, llm_pass

TEXT_SUFFIXES = {".txt", ".md", ".log"}
CSV_SUFFIXES = {".csv", ".tsv"}
PDF_SUFFIXES = {".pdf"}
SUPPORTED = TEXT_SUFFIXES | CSV_SUFFIXES | PDF_SUFFIXES


class IngestError(ValueError):
    pass


def read_document(path: Path) -> tuple[str, str]:
    """Returns (text, media_type). PDFs are text-extracted; a PDF that yields
    no text is an error rather than a silently empty document."""
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES:
        return path.read_text(encoding="utf-8", errors="replace"), "text/plain"
    if suffix in CSV_SUFFIXES:
        raw = path.read_text(encoding="utf-8", errors="replace")
        delim = "\t" if suffix == ".tsv" else ","
        rows = list(csv.reader(io.StringIO(raw), delimiter=delim))
        # Flatten to labelled text so the same detectors work on tabular data.
        if not rows:
            return "", "text/csv"
        header, *body = rows
        lines = []
        for i, row in enumerate(body, start=1):
            lines.append(f"ROW {i}:")
            lines.extend(f"  {h.strip()}: {v.strip()}" for h, v in zip(header, row))
        return "\n".join(lines), "text/csv"
    if suffix in PDF_SUFFIXES:
        from pypdf import PdfReader
        reader = PdfReader(str(path))
        text = "\n\n".join((page.extract_text() or "") for page in reader.pages)
        if not text.strip():
            raise IngestError(
                f"{path.name}: no extractable text. A scanned PDF needs OCR before "
                "it can be classified; this pipeline will not guess."
            )
        return text, "application/pdf"
    raise IngestError(
        f"{path.name}: unsupported type '{suffix}'. Supported: "
        + ", ".join(sorted(SUPPORTED))
    )


def classify_level(pack: Pack, data_types: list[str], identifiers: list[str]) -> dict[str, Any]:
    """Apply the pack's classification.yaml. First match wins."""
    from ..policy.engine import match_clause

    facts = {"data_types": data_types, "identifiers": identifiers}
    for rule in pack.classification_rules:
        cond = rule.get("if") or {}
        if all(match_clause(facts.get(k), c) for k, c in cond.items()):
            return {"level": rule["level"], "rule_id": rule.get("id", "?"),
                    "reason": " ".join((rule.get("reason") or "").split()),
                    "citation": rule.get("citation", "")}
    return {"level": pack.default_level, "rule_id": "CLS-DEFAULT",
            "reason": "No classification rule matched; pack default applies.",
            "citation": ""}


def keyed_hash(key: bytes, value: str) -> str:
    """HMAC rather than a bare digest - see db.detection_key for why."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()


def manifest_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def ingest(
    conn: sqlite3.Connection,
    pack: Pack,
    path: Path,
    *,
    session_id: str,
    subject: Subject,
    classifier_target: Target,
) -> dict[str, Any]:
    """Ingest one file: hash it, detect, classify, manifest, audit."""
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    doc_id = "d-" + sha[:10]
    text, media_type = read_document(path)

    conn.execute(
        "INSERT INTO documents (doc_id, source_path, sha256, media_type, byte_len, "
        "text_len, ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(doc_id) DO UPDATE SET source_path = excluded.source_path",
        (doc_id, str(path), sha, media_type, len(raw), len(text), audit.now()),
    )
    audit.append(
        conn, event="ingest", session_id=session_id, actor=subject.id,
        purpose=subject.purpose_of_use, pack=pack.ref, resource_ids=[doc_id],
        detail={"source": str(path), "sha256": sha, "media_type": media_type,
                "bytes": len(raw), "chars": len(text)},
    )

    # ---- pass 1: patterns ------------------------------------------------
    pattern_hits = detectors.scan(pack, text)
    p_summary = detectors.summarize(pattern_hits)
    provisional = classify_level(pack, p_summary["data_types"], p_summary["identifiers"])

    # ---- pass 2: llm, itself governed -----------------------------------
    doc = gateway.Doc(
        doc_id=doc_id, text=text, sensitivity=provisional["level"],
        data_types=p_summary["data_types"], identifiers=p_summary["identifiers"],
        detections=pattern_hits,
    )
    llm_hits, llm_status = llm_pass.run(
        conn, pack, session_id=session_id, doc=doc, subject=subject,
        target=classifier_target,
    )

    # ---- merge and finalize ---------------------------------------------
    all_hits = detectors.resolve_overlaps(
        pattern_hits + [d for d in llm_hits if d.start >= 0]
    ) + [d for d in llm_hits if d.start < 0]
    summary = detectors.summarize(all_hits)
    final = classify_level(pack, summary["data_types"], summary["identifiers"])

    conn.execute("DELETE FROM detections WHERE doc_id = ?", (doc_id,))
    key = detection_key(conn)
    conn.executemany(
        "INSERT INTO detections (doc_id, data_type, identifier, method, confidence, "
        "span_start, span_end, value_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [(doc_id, d.data_type, d.identifier, d.method, d.confidence,
          d.start, d.end, keyed_hash(key, d.value)) for d in all_hits],
    )

    payload = {
        "doc_id": doc_id, "sha256": sha, "source": str(path),
        "sensitivity": final["level"], "classification_rule": final["rule_id"],
        "data_types": summary["data_types"], "identifiers": summary["identifiers"],
        "methods": summary["methods"], "pack": pack.ref,
        "classifier_version": pack.classifier.get("version_tag", "unversioned"),
    }
    mhash = manifest_hash(payload)
    conn.execute(
        "INSERT INTO manifests (doc_id, sensitivity, classification_rule, data_types, "
        "identifiers, methods, pack_id, pack_version, classifier_version, classified_at, "
        "manifest_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(doc_id) DO UPDATE SET sensitivity=excluded.sensitivity, "
        "classification_rule=excluded.classification_rule, "
        "data_types=excluded.data_types, identifiers=excluded.identifiers, "
        "methods=excluded.methods, pack_id=excluded.pack_id, "
        "pack_version=excluded.pack_version, classifier_version=excluded.classifier_version, "
        "classified_at=excluded.classified_at, manifest_hash=excluded.manifest_hash",
        (doc_id, final["level"], final["rule_id"], json.dumps(summary["data_types"]),
         json.dumps(summary["identifiers"]), json.dumps(summary["methods"], sort_keys=True),
         pack.id, pack.version, pack.classifier.get("version_tag", "unversioned"),
         audit.now(), mhash),
    )
    audit.append(
        conn, event="classify", session_id=session_id, actor=subject.id,
        purpose=subject.purpose_of_use, pack=pack.ref, resource_ids=[doc_id],
        sensitivity=final["level"], data_types=summary["data_types"],
        rule_id=final["rule_id"],
        detail={"reason": final["reason"], "citation": final["citation"],
                "identifiers": summary["identifiers"], "methods": summary["methods"],
                "pattern_pass": {"found": len(pattern_hits),
                                 "level": provisional["level"],
                                 "rule_id": provisional["rule_id"]},
                "llm_pass": llm_status, "manifest_hash": mhash,
                "classifier_version": pack.classifier.get("version_tag")},
    )

    return {"doc_id": doc_id, "path": str(path), "sha256": sha,
            "sensitivity": final["level"], "classification_rule": final["rule_id"],
            "reason": final["reason"], "citation": final["citation"],
            "data_types": summary["data_types"], "identifiers": summary["identifiers"],
            "methods": summary["methods"], "detections": len(all_hits),
            "pattern_hits": len(pattern_hits), "llm_hits": len(llm_hits),
            "llm_status": llm_status, "manifest_hash": mhash,
            "provisional_level": provisional["level"]}


def load_doc(conn: sqlite3.Connection, pack: Pack, doc_id: str) -> gateway.Doc:
    """Rebuild a classified document for a gateway call.

    Detections are re-derived from the current pack rather than replayed from
    the database, so that a pack change is reflected immediately and cannot be
    bypassed by a stale row. The stored manifest still governs the sensitivity
    label - reclassifying is an explicit `gov ingest`, not a side effect.
    """
    row = conn.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()
    if row is None:
        raise IngestError(f"no document '{doc_id}'")
    manifest = conn.execute(
        "SELECT * FROM manifests WHERE doc_id = ?", (doc_id,)
    ).fetchone()
    if manifest is None:
        raise IngestError(f"document '{doc_id}' has no manifest; run ingest first")

    source = Path(row["source_path"])
    if not source.is_file():
        raise IngestError(
            f"document '{doc_id}' was classified from {source}, which no longer exists"
        )
    # The manifest is a claim about specific bytes. If the file behind it has
    # changed, the classification does not describe what we would be about to
    # send, so refuse rather than proceed on a stale label.
    current = hashlib.sha256(source.read_bytes()).hexdigest()
    if current != row["sha256"]:
        raise IngestError(
            f"document '{doc_id}' no longer matches its manifest: {source} now hashes "
            f"to {current[:12]}… but was classified as {row['sha256'][:12]}…. "
            "Re-ingest it before use."
        )
    # A manifest is a statement made by one pack. Its sensitivity and data-type
    # labels mean nothing under a different pack's vocabulary, and mixing them
    # is worse than useless: the audit entry would record "PHI" while the
    # redaction that ran came from a pack with no concept of PHI, so PHI would
    # cross the boundary in the clear under a log that says it was handled.
    if (manifest["pack_id"], manifest["pack_version"]) != (pack.id, pack.version):
        raise IngestError(
            f"document '{doc_id}' was classified under "
            f"{manifest['pack_id']}@{manifest['pack_version']} but is being used under "
            f"{pack.ref}. Labels are not portable between packs - re-ingest it "
            f"with `gov --pack {pack.id} ingest {source}` first."
        )

    text, _ = read_document(source)
    return gateway.Doc(
        doc_id=doc_id, text=text, sensitivity=manifest["sensitivity"],
        data_types=json.loads(manifest["data_types"]),
        identifiers=json.loads(manifest["identifiers"]),
        detections=detectors.scan(pack, text),
    )
