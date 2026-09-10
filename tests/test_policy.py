"""Policy engine behavior, exercised against the real HIPAA pack."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest

from govpipe.config import get_target
from govpipe.policy import Context, Resource, Subject, evaluate, load
from govpipe.policy.pack import PackError

PACK = load("hipaa")
BAA = get_target("claude-opus-5-baa")
STD = get_target("claude-opus-5-standard")
GLOBAL = get_target("claude-opus-5-global")


def ctx(action="summarize", sensitivity="restricted", data_types=("PHI",),
        identifiers=("name", "mrn"), target=BAA, purpose="treatment", roles=("clinician",)):
    return Context(
        action=action,
        subject=Subject(id="u1", roles=list(roles), purpose_of_use=purpose),
        resource=Resource(doc_ids=["d1"], sensitivity=sensitivity,
                          data_types=list(data_types), identifiers=list(identifiers)),
        target=target,
    )


# --------------------------------------------------------------- deny paths
def test_prohibited_is_denied_even_on_a_covered_model():
    d = evaluate(PACK, ctx(sensitivity="prohibited", data_types=("SUD", "PHI")))
    assert not d.allowed
    assert d.rule_id == "HIPAA-001"
    assert "42 CFR" in d.citation


def test_phi_to_non_baa_model_is_denied_by_rule_not_by_routing():
    d = evaluate(PACK, ctx(target=STD))
    assert not d.allowed
    # Deny rules run before the routing gate, so the citation survives.
    assert d.rule_id == "HIPAA-002"
    assert "164.308(b)(1)" in d.citation


def test_marketing_purpose_is_denied():
    d = evaluate(PACK, ctx(purpose="marketing"))
    assert not d.allowed
    assert d.rule_id == "HIPAA-003"


def test_routing_gate_catches_residency_even_when_baa_holds():
    d = evaluate(PACK, ctx(target=GLOBAL))
    assert not d.allowed
    assert d.rule_id == "ROUTING:restricted"
    assert "EU" in d.reason


def test_unlisted_purpose_falls_through_to_default_deny():
    d = evaluate(PACK, ctx(purpose="research"))
    assert not d.allowed
    assert d.rule_id == "DEFAULT-DENY"


def test_unlisted_action_falls_through_to_default_deny():
    d = evaluate(PACK, ctx(action="classify", purpose="treatment", target=STD))
    assert not d.allowed


# -------------------------------------------------------------- allow paths
def test_phi_summary_on_covered_model_is_allowed_with_obligations():
    d = evaluate(PACK, ctx())
    assert d.allowed
    assert d.rule_id == "HIPAA-010"
    types = {o.type for o in d.obligations}
    assert types == {"redact", "minimum_necessary", "retain", "residency", "audit"}
    assert d.obligation("redact").params["strategy"] == "tokenize"
    assert d.obligation("minimum_necessary").params["profile"] == "clinical_summary"


def test_always_obligations_are_unioned_into_every_allow():
    for c in (ctx(), ctx(action="release"), ctx(sensitivity="internal", data_types=())):
        d = evaluate(PACK, c)
        assert d.allowed
        assert d.obligation("audit").params["level"] == "full"


def test_release_requires_human_approval():
    d = evaluate(PACK, ctx(action="release"))
    assert d.allowed
    assert d.rule_id == "HIPAA-020"
    ob = d.obligation("approve")
    assert ob.params["queue"] == "phi-release"
    assert ob.params["roles"] == ["privacy_officer"]


def test_classifier_bootstrap_rule_permits_the_llm_pass():
    d = evaluate(PACK, ctx(action="classify", purpose="unspecified"))
    assert d.allowed
    assert d.rule_id == "HIPAA-005"
    assert d.obligation("redact") is not None


def test_classifier_bootstrap_never_runs_on_prohibited_material():
    d = evaluate(PACK, ctx(action="classify", sensitivity="prohibited",
                           data_types=("SUD",), purpose="unspecified"))
    assert not d.allowed
    assert d.rule_id == "HIPAA-001"


def test_internal_data_is_allowed_without_redaction():
    d = evaluate(PACK, ctx(sensitivity="internal", data_types=(), identifiers=()))
    assert d.allowed
    assert d.rule_id == "HIPAA-030"
    assert d.obligation("redact") is None


# ------------------------------------------------------------- match syntax
def test_missing_target_never_matches_a_target_clause():
    """An action with no model attached must not trip a model-shaped rule."""
    c = ctx(action="release", target=None)
    d = evaluate(PACK, c)
    assert d.allowed and d.rule_id == "HIPAA-020"


def test_count_operator():
    from govpipe.policy.engine import match_clause
    assert match_clause(["a", "b"], {"count": {"gte": 2}})
    assert not match_clause(["a"], {"count": {"gte": 2}})
    assert match_clause(["a"], {"count": {"lte": 1}})


def test_none_of_operator():
    from govpipe.policy.engine import match_clause
    assert match_clause(["a"], {"none_of": ["b"]})
    assert not match_clause(["a", "b"], {"none_of": ["b"]})


def test_decision_trace_names_every_rule_considered():
    d = evaluate(PACK, ctx())
    assert any("HIPAA-001" in line for line in d.trace)
    assert any("HIPAA-010: ALLOW" in line for line in d.trace)


# ----------------------------------------------------------- pack validation
def _write_pack(tmp_path, **overrides):
    import shutil
    src = pathlib.Path(__file__).resolve().parent.parent / "packs" / "hipaa"
    dst = tmp_path / "hipaa"
    shutil.copytree(src, dst)
    for name, text in overrides.items():
        (dst / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_unknown_context_field_fails_at_load(tmp_path):
    d = _write_pack(tmp_path, **{"rules.yaml": """
default: deny
rules:
  - id: X
    when: {patient_mood: [happy]}
    then: {decision: allow}
"""})
    with pytest.raises(PackError, match="unknown field 'patient_mood'"):
        load("hipaa", packs_dir=d)


def test_unknown_obligation_fails_at_load(tmp_path):
    d = _write_pack(tmp_path, **{"rules.yaml": """
default: deny
rules:
  - id: X
    when: {sensitivity: [internal]}
    then: {decision: allow, obligations: [{teleport: {}}]}
"""})
    with pytest.raises(PackError, match="unknown obligation 'teleport'"):
        load("hipaa", packs_dir=d)


def test_pack_cannot_opt_out_of_deny_by_default(tmp_path):
    d = _write_pack(tmp_path, **{"rules.yaml": """
default: allow
rules:
  - id: X
    when: {sensitivity: [internal]}
    then: {decision: allow}
"""})
    with pytest.raises(PackError, match="deny-by-default"):
        load("hipaa", packs_dir=d)


def test_deny_rule_with_obligations_fails_at_load(tmp_path):
    d = _write_pack(tmp_path, **{"rules.yaml": """
default: deny
rules:
  - id: X
    when: {sensitivity: [prohibited]}
    then: {decision: deny, obligations: [{redact: {}}]}
"""})
    with pytest.raises(PackError, match="cannot carry obligations"):
        load("hipaa", packs_dir=d)


def test_bad_regex_fails_at_load(tmp_path):
    d = _write_pack(tmp_path, **{"detectors.yaml": """
data_types:
  PHI:
    identifiers:
      - {id: broken, method: regex, pattern: '([unclosed', confidence: 0.5}
"""})
    with pytest.raises(PackError, match="does not compile"):
        load("hipaa", packs_dir=d)


def test_missing_file_fails_at_load(tmp_path):
    import shutil
    src = pathlib.Path(__file__).resolve().parent.parent / "packs" / "hipaa"
    shutil.copytree(src, tmp_path / "hipaa")
    (tmp_path / "hipaa" / "routing.yaml").unlink()
    with pytest.raises(PackError, match="missing required file"):
        load("hipaa", packs_dir=tmp_path)
