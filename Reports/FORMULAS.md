# CAVE-OT scoring: standards and project policy

Authoritative reference for `cave-ot-3` (2026-10-09). Older reports describe
retired formulas and must not be used as evidence of standards compliance.

## What the standards actually prescribe

| Item | Finding | Implementation |
|---|---|---|
| CIA 20/30/50 percentages | No such fixed weights were identified in NIST SP 800-82r3. Its sections 4.1.1-4.1.2 call for organization-specific likelihood, consequences, safety and continuity assessment. | Removed that arithmetic from live scoring. Complete vectors use FIRST Environmental equations. |
| PLC=1, RTU=.95 or per-device .97/.98 criticalities | No primary support for a fixed IEC/NIST/NERC device-to-number table was identified. IEC 62443-3-2 public scope concerns zone/conduit risk assessment and target security levels. The full paid IEC text was not audited. | Existing criticalities remain explicitly configured testbed assumptions, not measured or standards-prescribed values. |
| CVSS CIA constants | FIRST v3.1 table 16: N=0, L=.22, H=.56. | Used only in the proper v3.1 equations. Do not infer a vector from a base score or use these values as arbitrary percentages. |
| CVSS security requirements | FIRST v3.1 table 16: L=.5, M=1, H=1.5, X=1. | Supported CR/IR/AR, with X (Not Defined) by default. Selecting H is an analyst decision about severe consequences, not a universal OT requirement. |
| CVSS qualitative bands | FIRST table 14: 0 None; .1-3.9 Low; 4-6.9 Medium; 7-8.9 High; 9-10 Critical. | CVSS uses these bands. Custom priority reuses 4/7/9 boundaries for consistency; zero custom priority remains LOW. It is not CVSS severity. |
| EPSS -> exploit maturity | FIRST EPSS is probability of exploitation in the wild over the next 30 days; it does not identify exploit-code maturity. | No EPSS-to-E mapping. Only actual vector E contributes to CVSS Temporal/Environmental. |
| KEV -> remediation level | KEV is evidence of known exploitation, not evidence about fix availability. | No KEV-to-RL mapping. Only actual vector RL contributes to CVSS. |
| KEV bonus .75 or 10% | CISA recommends KEV as a prioritization input; no support found for either fixed numeric bonus. | .75 points remains an explicit project heuristic. KEV does not prove exploitation on this asset. |
| EPSS .75, IDS 1.5, anomaly 1, criticality floor .5, IDS event capacity 30 | These are project design parameters, not NIST/NERC/FIRST constants. | Centralized in `risk_policy.py`, version `testbed-priority-1`; provisional, requiring calibration. |
| Five-minute alert window | Operational design choice, not a standards mandate. | Default 300 seconds; configurable. Expired/undated/future evidence cannot boost live priority. |
| NERC CIP patch/vulnerability requirements | CIP-007-6 R2 addresses patch tracking/applicability and installation or mitigation plans. CIP-010-4 addresses configuration and vulnerability assessment for applicable BES systems. | These controls do not supply a numeric scoring equation. A water-treatment simulation is not automatically within NERC CIP scope; no compliance certification is claimed. |

## Standard severity calculation

`cvss31.py` implements FIRST CVSS v3.1 sections 6-7 and Appendix A, including
modified metrics, changed scope, security requirements, temporal metrics and
double Roundup for Environmental scoring. It requires all eight Base metrics.
CVSS v2/v3.0/v4.0 vectors are preserved but are not passed through this v3.1
calculator. Their reported severity remains the fallback, explicitly identified.

Full vectors are preserved from NVD through CSV processing, training corpora and
candidate discovery. Existing model binaries cannot acquire missing vectors
without rebuilding from original source data. A complete v3.1 vector produces a
separate `cvss_environmental` value and its effective vector. Invalid/missing
vectors leave that field null; CIA values are not fabricated or used to reconstruct
missing exploitability metrics. Reported CVSS is retained independently.

Temporal E/RL/RC default to X unless actual vector evidence supplies them. EPSS,
KEV and Suricata never populate those standard metrics.

## Custom operational priority

```
severity = FIRST CVSS v3.1 Environmental when a complete valid vector exists
           otherwise the reported CVSS score
base = severity * (0.5 + 0.5 * configured_asset_criticality)
exploitation = 0.75 * EPSS + (0.75 if KEV-listed else 0)
IDS = 1.5 * min(sum(each recent alert's weight) / 30, 1)
      alert weights: priority 1 -> 1; priority 2 -> 0.6; others -> 0
anomaly = confirmed_anomaly_score * 1.0
priority_total = base + exploitation + IDS + anomaly
risk_score = round(min(priority_total, 10), 1)
```

The whole expression remains a CAVE-OT prioritization heuristic, not official
CVSS Environmental, NIST risk, NERC compliance, probability, or expected loss.
Keep uncertainty/applicability separate: a POTENTIAL CVE with a high priority
does not establish that the device is vulnerable. Analyst confirmation remains
required. IDS/anomaly are endpoint evidence, not proof of a particular CVE attack.

IDS and anomaly may describe related traffic. Their additive weights are not
validated as independent signals. Do not invent a supposedly standard correlation
discount. Existing bounded bonuses remain provisional until labeled evaluation.
The uncapped total preserves ordering among capped/rounded ties, without changing
the displayed 0-10 scale. PostgreSQL stores versioned evidence and total; the
dashboard exposes standard Environmental and custom priority separately.

## IDS freshness and weighting fixes

- Parse timestamps, signature, destination and explicit priority from fast.log.
- Use only records aged 0-300 seconds by default; reject missing/invalid/future
  timestamps. Preserve timestamp in JSON and recheck it at scoring time.
- Infer omitted years nearest the current log-local date, including New Year;
  logs with no year cannot reliably distinguish years-old archived records.
- Interpret timestamps in the configured log timezone. Docker pins TZ and log
  timezone to UTC. VM deployments must match their actual Suricata timezone.
- Exact duplicate log records count once; genuine separate timestamps remain
  separate observations. Incident-level deduplication is a future design choice.
- Sum priority weights per event, not count times the most severe event.
  One priority-1 plus 29 priority-2 events adds .92 points, not 1.5.
- Mark previously stored IDS signatures inactive when absent from the new window;
  retain their rows as history. Counts now represent a rolling window, not totals.
- Anomalies contribute only after caller confirmation; a first spike adds zero.

## Configuration and rollout

`risk_policy.py` names all project policy coefficients. Environment settings:

| Variable | Default | Meaning |
|---|---|---|
| CAVE_OT_ALERT_WINDOW_SECONDS | 300 | Recent evidence window, 1-86400 seconds |
| CAVE_OT_ALERT_LOG_TIMEZONE | UTC | IANA zone matching actual fast.log timestamps |
| CAVE_OT_CVSS_CR / IR / AR | X | L/M/H/X requirements selected by an analyst |

For example, `CAVE_OT_CVSS_AR=H` applies FIRST's 1.5 requirement multiplier;
the choice of high availability requirement must be justified for the plant.
Default X overrides nothing in preserved vectors. Explicit per-asset
`cvss_requirements` passed to scoring can select requirements without guessing.
Restart processes after changing policy settings. Docker Compose forwards settings.

Rebuild the engine to include the new modules. Rebuild NVD-derived corpora only
when original datasets are available and vectors are needed; do not overwrite
models using invented data. Apply the existing idempotent migration entry point
`python Database/migrate_audit_fixes.py`, which adds nullable `risk_evidence` and
`priority_total` columns through `runtime_constraints.py`. Existing rows are not
re-scored by the additive schema change; the next completed cycle writes version 3.
Historical version 2 scores keep their original tiers, so history is not relabeled.

## Verification and limitations

The independent comparison against FIRST's reference JavaScript calculator used
all 2,592 Base vectors plus 3,000 seeded extended Temporal/Environmental vectors.
All 16,776 Base/Temporal/Environmental score comparisons matched exactly. See
`Reports/RISK_STANDARDS_CONFORMANCE.json`. This establishes calculator conformance
on those cases, not certification or calibration of the custom priority weights.

Regression tests exercise expiry, mixed severities, duplicate records, rollover,
legacy fallback, cached-context rechecking, unconfirmed anomalies, tier boundaries,
uncapped ordering, vector propagation and database metadata serialization.
Live Docker/Suricata and PostgreSQL checks still require a configured deployment.

## Primary references

1. [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document), sections 4-7, table 14, table 16, Appendix A.
2. [FIRST reference calculator](https://www.first.org/cvss/calculator/cvsscalc31.js).
3. [FIRST EPSS](https://www.first.org/epss/).
4. [NIST SP 800-82r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf), sections 4.1.1-4.1.2, printed pages 46-53.
5. [IEC 62443-3-2 official public scope](https://webstore.iec.ch/en/publication/30727). Full paid normative text was not assessed.
6. [NERC CIP-007-6](https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-007-6.pdf), R2.
7. [NERC CIP-010-4](https://www.nerc.com/standards/reliability-standards/cip/cip-010-4).
8. [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [BOD 22-01 publication](https://www.cisa.gov/sites/default/files/publications/Reducing_the_Significant_Risk_of_Known_Exploited_Vulnerabilities_20211103.pdf).
