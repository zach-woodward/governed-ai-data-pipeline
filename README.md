# Governed AI Data Pipeline

A reference architecture for running LLM workloads over regulated data with
governance controls that are **enforced**, not asserted. Local-first, single
machine, SQLite, Python. Built to be explained live in front of an audience.

> **Scope, and what this is not.** This demonstrates a design. It is not a
> compliance product, it has not been reviewed by counsel or assessed by an
> auditor, and nothing here is legal advice. The regulatory citations
> throughout name the control each rule is *modelled on* — they are not a
> claim that this implementation satisfies that control. Only the HIPAA pack is
> complete; `pubsec` and `finserv` are stubs and say so in their own
> `pack.yaml`. Every sample document is synthetic. Read
> [What is real, and what is demo-scale](#what-is-real-and-what-is-demo-scale)
> before drawing conclusions about any of it.
>
> **Licensing.** All rights reserved — see [LICENSE](LICENSE). Published to be
> read, not to be reused.

The claim it is built to demonstrate: a compliance regime can be a set of
declarative files, and the pipeline underneath can be regime-agnostic. Swapping
the active policy pack changes classification, redaction, model routing,
retention, and audit requirements without touching a line of pipeline code.

```
$ ./run demo                    # the whole story, offline, ~2 minutes
$ ./run demo --no-pause         # same, without waiting for [enter]
$ ./run serve                   # the same thing as a web UI on :9010
$ ./.venv/bin/python demo/demo.py --live    # route the same calls to a real model
```

Two ways to show it. `./run demo` is a guided terminal walkthrough that pauses
between beats — you drive it, and it's the better format for an audience,
because the persuasive moments are raw evidence. `./run serve` puts the same
core behind a web UI on the LAN so someone can click through it themselves:
try to send PHI to a non-BAA model, get denied, and see the rule and the CFR
citation that stopped it. **The web UI has no authentication** — it belongs on
a trusted network or behind Tailscale, never on the public internet.

The demo runs **offline by default** — no API key, no egress, no network. The
governance behavior is identical either way; only the model at the far end
changes.

---

## Explaining it to someone in ninety seconds

`./run serve` opens on a **How it works** tab written for someone hearing about
this for the first time — a compliance officer, a VP, a customer. It reads from
the pack that is loaded, so it is never out of date with the rules it describes.

The three beats it is built around, in the order they land best:

1. **"Nothing reaches an AI model until a rulebook says yes — and says what has
   to be stripped out first."** One sentence, then the four steps: read, decide,
   clean, ask. Underneath them, a log that cannot be edited.

2. **"Every request gets one of three answers."** *No* — some things never go,
   whichever model you point at. *Yes, if…* — allowed once conditions are met.
   *Ask a person* — the software stops and waits for a named role. And if
   nothing matches, the answer is no.

3. **"The regulations live in files, not in the software."** Switch the pack in
   the header. The rules, the routing requirements, and the three answers all
   change; nothing was rebuilt.

Then let them poke at it: try to send a patient note to a model with no BAA and
watch it refuse, or press **Try to tamper with it** on the Audit log tab.

*The precise version* — the four-gate evaluation ladder, the obligation
discharge order, the fail-closed guarantee — is a disclosure below that, for
whoever in the room wants it.

---

## What it actually does

```
   data/landing/                    packs/hipaa/          config/models.yaml
   txt · csv · pdf                  six YAML files        what each model IS
        │                                 │                       │
        ▼                                 ▼                       │
  ┌───────────────┐               ┌──────────────┐                │
  │  CLASSIFY     │  patterns ──▶ │  POLICY      │◀───────────────┘
  │  then LLM     │  then LLM     │  ENGINE      │
  └───────┬───────┘               └──────┬───────┘
          │  manifest                    │  allow + obligations, or deny
          │  (hashed)                    ▼
          │                       ┌──────────────┐
          └──────────────────────▶│   GATEWAY    │──▶ model
                                  │ choke point  │
                                  └──────┬───────┘
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
              redact + vault      approval queue        AUDIT LOG
              (re-identify         (human in the        (hash-chained,
               inside only)         loop)                append-only)
```

Seven components, none over ~370 lines:

| Component | File | What it is |
|---|---|---|
| Audit log | `govpipe/audit.py` | Append-only, hash-chained. `verify()` names the first broken seq. |
| Policy engine | `govpipe/policy/engine.py` | Context in, one `Decision` out. Deny by default. |
| Classification | `govpipe/classify/` | Regex pass, then a governed LLM pass. Records which found what. |
| Redaction | `govpipe/redact.py` | Tokenize / mask / hash / drop, with a local re-identification vault. |
| Gateway | `govpipe/gateway.py` | The only path to a model. Fails closed if any obligation cannot be met. |
| Obligations | `govpipe/obligations.py` | The complete list of obligations the core can carry out, and their order. |
| Approvals | `govpipe/approvals.py` | Human review queue. Enforces the roles policy named. |

---

## The policy pack schema

A pack is a directory of six YAML files, **one per thing a compliance regime
changes**, plus an optional `detectors.py` for detection logic regex cannot
express.

```
packs/hipaa/
├── pack.yaml            identity, audit requirements, retention defaults
├── detectors.yaml       what data types exist and how to find them
├── classification.yaml  detected types + context  ->  sensitivity level
├── redaction.yaml       what happens to each entity before a call
├── routing.yaml         what a model must BE to receive each level
└── rules.yaml           the decision table, deny by default
```

Three packs ship: **hipaa** (complete — all 18 Safe Harbor identifiers,
minimum-necessary profiles, BAA routing, 42 CFR Part 2 prohibition),
**pubsec** and **finserv** (stubs, clearly marked, but genuinely runnable).

### The decision model

A decision is **binary**. Everything else a regime demands rides along as an
**obligation** on an allow:

```yaml
- id: HIPAA-010
  description: De-identified PHI may be summarized by a covered model.
  when:
    sensitivity: [restricted]
    data_types: {any_of: [PHI]}
    action: [summarize, extract]
    target.baa: true
    target.zero_retention: true
    subject.purpose_of_use: [treatment, payment, operations, quality_improvement]
  then:
    decision: allow
    obligations:
      - redact: {types: [PHI, PCI], strategy: tokenize}
      - minimum_necessary: {profile: clinical_summary}
      - retain: {prompt_days: 2190, output_days: 30}
      - residency: {allowed: [US]}
  citation: "45 CFR 164.502(b), 164.514(d)"
```

**An allow whose obligations cannot all be discharged is a deny**, and is
logged as one. That single property is what the design rests on.

### Evaluation order

Fixed and deliberately boring, because it has to be explainable out loud:

1. explicit **deny** rules, in file order — first match denies
2. the **routing gate** from `routing.yaml` — the model must satisfy the
   requirements for this sensitivity level
3. explicit **allow** rules, in file order — first match allows, carrying its
   obligations plus the pack's `always` obligations
4. **default deny**

No priority arithmetic. No most-specific-match resolution.

### What a rule may match on

The complete vocabulary. A pack that references anything else **fails to load**:

```
action                     classify | summarize | extract | release | export
subject.id / .roles / .purpose_of_use
sensitivity                public | internal | restricted | prohibited
data_types / identifiers / jurisdiction
target.key / .model_id / .provider / .baa / .zero_retention / .residency
```

Operators: list membership, `any_of`, `all_of`, `none_of`, `count: {gte, lte}`.
That is all of them.

### Validation happens at load, never at decision time

A malformed pack fails loudly when you load it, not silently when it matters:

```
$ ./run --pack broken pack show
error: broken/rules.yaml BAD-1: rule matches unknown field 'patient_mood'.
       Known: action, data_types, identifiers, jurisdiction, sensitivity, …
```

Packs cannot opt out of deny-by-default, deny rules cannot carry obligations,
every regex must compile, and every obligation must be one the gateway knows
how to discharge.

---

## The audit log

Every entry's hash covers its own canonical JSON **and** the previous entry's
hash. Altering or removing any entry breaks every hash after it.

```
$ ./run audit verify
CHAIN INTACT  chain intact across 49 entries
```

What the chain does **not** protect is its own head. An entry is protected by
the entries that commit to it, so the newest entry can be rewritten and
rehashed cleanly by anyone with database access. That is a property of the
construction, not a defect here, and the fix is to anchor the head hash
somewhere the operator does not control — publish it, sign it, or write it to
append-only storage off the box. Both the CLI and web tamper demos deliberately
target an entry with successors, because rewriting the tail would demonstrate
the opposite of the point.

SQLite triggers block `UPDATE` and `DELETE` on `audit_log`, but those are a
speed bump, not the control — anyone who can reach the database can drop a
trigger. The chain is what actually detects it, and the demo shows exactly
that: drop the trigger, edit a row, and the chain reports the break; recompute
that row's own hash, and the break simply moves to the next entry.

**The audit log is the system of record.** Documents, detections, the vault,
and approvals are operational state. The query CLI reads only the chain:

```bash
./run audit query --event llm_call --sensitivity restricted --since 7d
./run audit query --decision deny --since 24h
./run audit query --data-type PHI --actor-filter dr.reyes --json
./run audit show 20            # one entry, in full, including the exact prompt sent
```

---

## The chicken-and-egg problem, and how it is handled

LLM-assisted classification is itself a data egress: to ask a model what
category a document falls into, you have to send it the document you have not
classified yet. Most demonstrations of this shape quietly ignore that.

Here, **the classification pass goes through the same gateway as everything
else**, under a rule the pack has to write explicitly:

```yaml
- id: HIPAA-005
  description: The classification pass is itself a governed model call.
  when:
    action: [classify]
    target.baa: true
    target.zero_retention: true
  then:
    decision: allow
    obligations:
      - redact: {types: [PHI, SUD, PCI], strategy: tokenize}
      - retain: {prompt_days: 2190, output_days: 30}
```

It runs on a pattern-redacted copy, against a covered model, and never on
material the pattern pass already flagged prohibited — because HIPAA-001 is a
deny rule and deny rules run first. The classifier call appears in the audit
trail like any other call.

Live, the second pass earns its place: it finds `clinical_narrative` and
`other_unique_code`, which no regex can express. The manifest records which
pass found each identifier.

---

## Quickstart

```bash
python3 -m venv .venv
./.venv/bin/pip install -e ".[dev]"

./run demo                                  # the scripted demonstration
./run pack list                             # available policy packs
./run pack show hipaa                       # every rule, obligation, and citation
./run ingest                                # classify data/samples/
./run docs                                  # what is in the pipeline
./run docs d-61c5403dac                     # one document's manifest and detections

./run --actor dr.reyes --roles clinician --purpose treatment \
      ask --doc d-61c5403dac --action summarize \
      --prompt "Summarize the clinical course." \
      --target local-echo --show-prompt --explain

./run approvals list
./run approvals approve a-9f086fad --actor k.oyelaran --roles privacy_officer
./run audit query --event llm_call --sensitivity restricted --since 7d
./run audit verify
./run retention list
```

Credentials for `--live` resolve the standard way: `ANTHROPIC_API_KEY`,
`ANTHROPIC_AUTH_TOKEN`, or an `ant auth login` profile. Nothing is hardcoded.

---

## Sample data

Seven synthetic documents in `data/samples/` — fictional patient records
(txt, csv, pdf), a 42 CFR Part 2 intake, an ordinary operations memo, a
citizen benefits case file, and a trade-desk chat. Every one carries a
`SYNTHETIC — NOT REAL DATA` marker, and a test asserts it.

The same three documents, under three packs:

| pack | patient_note_001 | citizen_benefits_case | trade_desk_chat |
|---|---|---|---|
| hipaa | restricted (PHI, PCI) | restricted (PHI) | **internal** |
| pubsec | restricted (PII) | restricted (CUI, PII) | **internal** |
| finserv | restricted (PII, PCI) | restricted (PII) | **prohibited** (MNPI) |

The trade-desk chat is invisible to HIPAA and to the CUI pack and prohibited
under finserv. Nothing about the pipeline changed — only which six files
were loaded.

---

## What is real, and what is demo-scale

Being straight about this is part of the point.

**Real:**
- The hash chain, and its tamper detection.
- Deny-by-default, obligation discharge, and fail-closed on any obligation
  that cannot be met.
- Pack validation at load time, including the matchable-field vocabulary.
- The gateway as a genuine single choke point — there is no other path to a
  model in this codebase.
- Role enforcement on the approval queue, enforced in `approvals.py` rather
  than in a UI.
- All 18 HIPAA Safe Harbor identifier categories, each carrying its CFR cite.
- A manifest is a claim about specific bytes *made by one pack*. If the file
  changes after classification, or if the document is used under a different
  pack than classified it, `load_doc` refuses. Both guards exist because both
  failures produced an audit record claiming data was handled while it left in
  the clear.
- Retention expiry destroys the re-identification vault rows, which makes every
  token that pointed at them permanently unresolvable. The hash-chained log
  cannot be purged and is reported as held instead — the sweep says so rather
  than pretending otherwise.
- Detection digests are HMAC'd with a per-database key. A bare SHA-256 of a
  social security number is reversible in seconds; this records that two
  documents share a value without recording what it is.

**Demo-scale, deliberately:**
- The vault stores re-identification values in plain SQLite. A deployment
  would put them behind a KMS-held key; the interface would not change. (The
  *detections* table is already keyed — it is the vault, which by definition
  must be reversible, that is in the clear.)
- Model attributes in `config/models.yaml` (`baa`, `zero_retention`,
  `residency`) are asserted, not verified against contract metadata. The
  pipeline refuses to proceed without them being asserted — which is the
  behavior being demonstrated.
- `minimum_necessary` removes ALL-CAPS labelled sections. Real records are
  structured; the profile would key off fields.
- Regex detectors will miss things and will over-trigger. That is why the
  `method` column exists in every classification table, and why every
  detection carries a confidence.
- WORM retention is a flag on a row, not write-once media. The sweep honors
  the flag; the storage underneath is ordinary SQLite.
- `pubsec` and `finserv` are stubs and say so in their own `pack.yaml`. They
  deny more than a complete pack would, which is the correct direction for a
  stub to be wrong in.

**Deliberately not enabled:** server-side refusal fallbacks. The gateway pins
a specific model because policy determined *that* model satisfies the routing
requirements. Letting the API silently reroute to a different model would make
the `model_id` in the audit record a claim that cannot be stood behind.

---

## Layout

```
govpipe/
├── audit.py             hash-chained append-only log + query + verify
├── db.py                SQLite schema, append-only triggers
├── config.py            paths, model inventory
├── gateway.py           the choke point
├── obligations.py       the eight obligation dischargers, in discharge order
├── redact.py            tokenize/mask/hash/drop + vault + re-identify
├── approvals.py         human review queue with role enforcement
├── retention.py         retention clocks, WORM-aware sweep
├── cli.py               the `gov` command
├── web.py               minimal web view (stdlib only)
├── static/index.html    the single-page UI, no CDN
├── policy/
│   ├── schema.py        Context, Decision, Obligation — the core contract
│   ├── pack.py          load + validate a pack directory
│   └── engine.py        evaluate(pack, context) -> Decision
└── classify/
    ├── detectors.py     pattern pass, overlap resolution
    ├── llm_pass.py      the governed second pass
    └── manifest.py      ingest, classify, manifest, audit

packs/{hipaa,pubsec,finserv}/    six YAML files each
config/models.yaml               what each model target IS
data/samples/                    synthetic corpora
demo/demo.py                     the ten-beat demonstration
tests/                           76 tests
```

## Tests

```bash
./.venv/bin/python -m pytest
```

76 tests. The ones worth reading are `tests/test_audit.py` (including an
attacker who recomputes the edited entry's own hash) and `tests/test_gateway.py`
(obligation ordering, fail-closed paths, forged approval ids).
