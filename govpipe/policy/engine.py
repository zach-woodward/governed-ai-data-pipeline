"""The policy engine: context in, one Decision out.

Evaluation order is fixed and deliberately boring, because it has to be
explainable out loud:

    1. explicit deny rules, in file order   -> first match denies
    2. the routing gate from routing.yaml   -> model must satisfy the
                                               requirements for this
                                               sensitivity level
    3. explicit allow rules, in file order  -> first match allows, carrying
                                               its obligations plus the
                                               pack's `always` obligations
    4. default                              -> deny

There is no priority arithmetic and no most-specific-match resolution. A
decision is binary; everything else a regime demands (redaction, approval,
retention, audit depth) rides along as an obligation on an allow. An allow
whose obligations the gateway cannot discharge is a deny.
"""
from __future__ import annotations

from typing import Any

from .pack import Pack
from .schema import Context, Decision, Obligation, Rule


def _as_set(value: Any) -> set:
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {v for v in value}
    return {value}


def match_clause(field_value: Any, clause: Any) -> bool:
    """A missing field (None) never matches. That keeps a rule written for a
    model call from firing on an action that has no model attached."""
    if field_value is None:
        return False
    if isinstance(clause, dict):
        values = _as_set(field_value)
        for op, operand in clause.items():
            if op == "any_of":
                if not (values & _as_set(operand)):
                    return False
            elif op == "all_of":
                if not _as_set(operand) <= values:
                    return False
            elif op == "none_of":
                if values & _as_set(operand):
                    return False
            elif op == "count":
                n = len(values)
                if "gte" in operand and n < operand["gte"]:
                    return False
                if "lte" in operand and n > operand["lte"]:
                    return False
        return True
    if isinstance(clause, list):
        # Membership for scalars; overlap for set-valued fields.
        if isinstance(field_value, (list, tuple, set)):
            return bool(_as_set(field_value) & _as_set(clause))
        return field_value in clause
    return field_value == clause


def matches(rule: Rule, flat: dict[str, Any]) -> bool:
    """All clauses must match (AND). An empty `when` matches everything."""
    return all(match_clause(flat.get(f), c) for f, c in rule.when.items())


def _routing_gate(pack: Pack, ctx: Context) -> tuple[bool, str, str]:
    """Returns (ok, rule_id, reason). Skipped when no model is involved."""
    reqs = pack.routing.get(ctx.resource.sensitivity)
    if ctx.target is None or not reqs:
        return True, "", ""
    rid = f"ROUTING:{ctx.resource.sensitivity}"
    if reqs.get("allow") is False:
        return False, rid, (
            f"routing.yaml forbids sending {ctx.resource.sensitivity} data to any model"
        )
    for attr in ("baa", "zero_retention"):
        if reqs.get(attr) is True and not getattr(ctx.target, attr):
            return False, rid, (
                f"{ctx.resource.sensitivity} data requires a model with {attr}=true; "
                f"'{ctx.target.key}' has {attr}=false"
            )
    allowed_geo = reqs.get("residency")
    if allowed_geo:
        excess = set(ctx.target.residency) - set(allowed_geo)
        if excess:
            return False, rid, (
                f"{ctx.resource.sensitivity} data is restricted to {allowed_geo}; "
                f"'{ctx.target.key}' may process in {sorted(excess)}"
            )
    return True, "", ""


def evaluate(pack: Pack, ctx: Context) -> Decision:
    flat = ctx.flatten()
    trace: list[str] = []

    # 1. deny-overrides
    for rule in pack.rules:
        if rule.decision != "deny":
            continue
        if matches(rule, flat):
            trace.append(f"{rule.id}: DENY (matched)")
            return Decision(
                allowed=False, rule_id=rule.id,
                reason=rule.description or "denied by policy",
                citation=rule.citation, trace=trace,
            )
        trace.append(f"{rule.id}: no match")

    # 2. routing gate
    ok, rid, reason = _routing_gate(pack, ctx)
    if not ok:
        trace.append(f"{rid}: DENY (model does not satisfy routing requirements)")
        return Decision(
            allowed=False, rule_id=rid, reason=reason,
            citation=pack.authority, trace=trace,
        )
    if rid == "" and ctx.target is not None:
        trace.append(f"ROUTING:{ctx.resource.sensitivity}: satisfied")

    # 3. first matching allow
    for rule in pack.rules:
        if rule.decision != "allow":
            continue
        if matches(rule, flat):
            trace.append(f"{rule.id}: ALLOW (matched)")
            obligations = _merge(rule.obligations, pack.always)
            return Decision(
                allowed=True, rule_id=rule.id,
                reason=rule.description or "permitted by policy",
                obligations=obligations, citation=rule.citation, trace=trace,
            )
        trace.append(f"{rule.id}: no match")

    # 4. default deny
    trace.append("DEFAULT: DENY (no rule matched)")
    return Decision(
        allowed=False, rule_id="DEFAULT-DENY",
        reason=pack.default_reason, citation=pack.authority, trace=trace,
    )


def _merge(rule_obligations: list[Obligation], always: list[Obligation]) -> list[Obligation]:
    """Rule obligations win over `always` obligations of the same type."""
    by_type = {o.type: o for o in always}
    by_type.update({o.type: o for o in rule_obligations})
    return [by_type[t] for t in sorted(by_type)]
