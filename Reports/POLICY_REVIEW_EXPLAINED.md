# CAVE-OT policy review: presentation and implementation guide

Updated 9 October 2026. The live feature now separates automatic plant checks
from recorded analyst decisions. It is an advisory local prototype, not a
certificate of NIST/NERC compliance and not a device-enforcement mechanism.

## 1. What problem this feature solves

A vulnerability score answers which potential finding deserves attention. A
policy check answers whether available facts satisfy a selected plant rule.
An analyst decision records what a person chooses to do after reviewing those
facts. These are different questions and are displayed separately.

For example, a PLC can have potential CVEs, a known plaintext protocol, and no
verified patch date. The engine recommends restrictions because a transport rule
fails. An analyst can record approval of continued operation with a documented
exception/compensating-control rationale. The transport failure and missing
patch evidence remain visible. Approval does not turn the asset into COMPLIANT.

## 2. Data flow

```
Observed traffic + configured inventory + candidate CVEs
                         ↓
                 PostgreSQL asset/CVE records
                         ↓
                 Active plant rules
                         ↓
             Deterministic rule evaluation
                         ↓
     Current check results + recommendation + policy alerts
                         ↓
        Analyst opens current assessment and records a decision
                         ↓
       Separate review ledger: name, reason, time, evidence snapshot
```

Discovery supplies endpoints, protocols and some transport evidence. Configured
inventory supplies the simulated identity/firmware/zone/criticality; that identity
is explicitly unverified. The CVE matcher supplies potential/confirmed/unknown
applicability records. Patch dates and vendor lifecycle support require additional
inventory/vendor evidence: they cannot reliably be inferred from a PCAP.

Current live policy checks use `policy_engine.evaluate`. The historical
RandomForest policy experiment is not required and is not deciding these results.
The same evaluator serves manual Evaluate and automatic monitoring ingestion.

## 3. Rule scope comes before the condition

A rule can be scoped to a zone, device type, service or port. A rule for a known
different zone is NOT_APPLICABLE, not a failure. If the required zone/service is
unknown, applicability may be UNKNOWN. Invalid inputs and unsupported rules are
also UNKNOWN; neither is silently treated as a pass.

The engine then evaluates the applicable condition. Its outcomes are:

| Result | Meaning | Example |
|---|---|---|
| PASS | Available evidence satisfies this selected rule | Verified lifecycle says firmware is supported |
| FAIL | Available evidence violates this selected rule | Observed plaintext transport violates the selected encryption rule |
| UNKNOWN | Evidence is missing, invalid or insufficient | No verified patch date |
| NOT_APPLICABLE | The rule does not apply to this known scope | IT web rule on an OT PLC |

## 4. The eight implemented rule types

| Rule | Evidence used | Actual evaluation |
|---|---|---|
| OT Zone Encryption | Zone and verified `encrypted` flag | OT traffic: false fails; true passes; missing is unknown |
| IT Zone HTTPS Only | IT zone, web service, encryption evidence | In-scope plaintext fails; unknown encryption stays unknown |
| IT Zone OT Protocol Restriction | IT zone and observed protocol | Configured plant prohibition of Modbus/S7comm/DNP3/BACnet produces failure |
| SCADA Zone Protocol Restriction | SCADA_Zone and protocol | Checks the implemented prohibited-protocol set; missing service is unknown |
| DMZ Zone Segmentation | DMZ and protocol | Flags configured OT protocols in the DMZ; not a firewall/connectivity verification |
| Patch Compliance | Verified days-since-patch and configured threshold | Missing date is unknown; age above the selected threshold fails |
| Firmware EOL Check | Verified vendor lifecycle flag | True fails, false passes, missing is unknown |
| High CVSS Alert | Confirmed applicable CVEs and configured CVSS threshold | Confirmed CVSS >= threshold fails the plant check; unresolved applicability/incomplete assessment is unknown |

These are selected plant policy checks. The blanket OT encryption rule, protocol
sets and patch-age threshold are not universal mandates copied from NIST. Legacy
OT can require reviewed compensating controls. References shown in the UI are
rationale, not evidence that every requirement of a standard was evaluated.

The 35-day patch-age rule is a project threshold. NERC CIP-007-6 R2 addresses
patch applicability evaluations and installation or mitigation planning, not
simply whether every water-plant device was patched in the previous 35 days.
NERC BES applicability must also be established separately. Likewise, merely
listening on port 443 is not proof that traffic is encrypted; the testbed's
Historian has produced plaintext HTTP on that port.

## 5. How the system recommendation is selected

The decision order is:

1. Any failed configured transport/zone restriction rule → RESTRICT.
2. Other known failures → REMEDIATE.
3. No failures, but unresolved/invalid/missing evidence → NEEDS_REVIEW.
4. All applicable checks pass with sufficient evidence → APPROVE.

RESTRICT can therefore coexist with missing evidence: one known failure already
justifies a recommendation, even if other checks cannot be completed. The
stored compliance status is NON_COMPLIANT when failures exist, NEEDS_REVIEW when
there are only unresolved inputs, or COMPLIANT when applicable checks pass.

Automatic priority is a separate project heuristic: failures on configured
criticality >= .9 are URGENT, other failures HIGH, unresolved evidence REVIEW,
and passing results ROUTINE. These labels prioritize the queue; they are not
probabilities or standard-prescribed asset criticalities.

## 6. What the page now displays

| Field | Meaning |
|---|---|
| System Recommendation | Automatic result of the selected rules |
| Rule Checks | Explicit failed, missing-evidence, passed and not-applicable counts |
| Analyst Decision | The latest named manual review, or Not reviewed |
| Evidence changed | The previous manual decision no longer matches the current policy inputs |
| Priority | Order in which the system suggests reviewing the asset |

The previous percentage was evidence completeness, not security. For a dosing
PLC with one known encryption failure and three unknown applicable checks, 25%
meant one of four checks was evaluable. It did not mean 25% compliant or 75%
vulnerable. The new UI presents: **1 failed, 3 missing evidence, 0 passed**.
Not-applicable checks are reported separately. The backend preserves old
coverage data for compatibility, but the confusing UI percentage/progress bar
has been removed.

## 7. View evidence, Evaluate and Refresh

**View evidence** opens the stored rule-by-rule results. Each item shows scope
outcome, reason, suggested next step and policy reference. It can explain a known
plaintext observation or a missing patch date; it is not a raw packet viewer.
The latest analyst decision and rationale are shown separately when available.

**Evaluate** reruns the rules against current stored asset/CVE evidence and saves
the result. It updates current violations and policy alerts. It does not launch
a network scan, obtain missing vendor facts, patch a controller, restrict traffic,
or save a human decision. **Evaluate All** does this for all assets.

**Refresh** reloads saved results. Regular automatic monitoring also updates the
system assessment. Repeated evaluation does not overwrite manual reviews.

## 8. Policy alerts are different from IDS detections

Each failed plant rule produces a POLICY finding. Unknown checks do not create
a failure alert. These records are replaced/updated during evaluation rather than
counted as new network attacks on every refresh. Policy alerts are not flagged
as active attacks.

Suricata detections are traffic matching configured signatures. An anomaly is
traffic deviating from a baseline. Neither proves successful exploitation. Policy
checks use structured facts; they do not manufacture patch/EOL evidence from
IDS matches. A high candidate risk can coexist with NEEDS_REVIEW because its
applicability is still unverified.

## 9. Manual analyst workflow

1. Select **View evidence** for the asset and inspect failures/missing facts.
2. Click **Manual decision**. The server loads a fresh assessment from current
   policy inputs, rather than trusting an old browser result.
3. Enter a reviewer name, choose a decision, and supply a reason.
4. If approving despite failed/missing checks, explicitly acknowledge that this
   is an exception. Record relevant compensating controls and follow-up in the
   reason. This does not make those checks pass.
5. Save. The record appears in the Analyst Decision column and decision history.

Available analyst choices:

| Choice | Workflow meaning |
|---|---|
| APPROVE | Record approval of continued operation in this policy-review context |
| REJECT | Reject operational approval |
| RESTRICT | Request restrictions/control review |
| REMEDIATE | Request remediation planning |
| DEFER | Defer pending additional evidence or review |

None of these choices executes a device action. The local prototype records a
self-reported reviewer name; it does not authenticate an analyst account. Do not
present the name as verified identity or this workflow as production enforcement.

The server requires a valid decision, reviewer name, rationale and assessment
fingerprint. It rejects malformed inputs, cross-origin browser decision posts,
missing approval acknowledgment, and stale evidence. It serializes changes on
the asset row and writes the review transactionally alongside a fresh automatic
assessment. Audit history is append-only through the provided application API.

## 10. Evidence binding and reevaluation

The review records relevant asset facts, active rules, CVE applicability/severity,
check outcomes and the system recommendation. A fingerprint binds the decision
to those inputs. A browser saving against changed inputs gets HTTP 409 and must
review the new assessment before trying again.

Patch/lifecycle/transport/applicability/rule changes can mark a previous decision
as requiring review again. Ordinary last-seen updates and packet-count changes
do not invalidate a policy decision, because these are not inputs to the current
policy rules. Traffic incident assessment remains a separate responsibility.
Current-evidence status is not a permanent operational authorization.

## 11. Where the results are stored

- `policy_compliance`: latest automatic assessment for each asset.
- `policy_violations`: current failed rule details.
- `alerts`: POLICY findings and separately ingested IDS records.
- `policy_manual_reviews`: reviewer, decision, rationale, time, acknowledgment,
  system recommendation, fingerprint and the reviewed evidence snapshot.

An analyst may disagree with the recommendation. Both results remain visible.
For example, system RESTRICT + analyst APPROVE is an acknowledged exception, not
COMPLIANT. System APPROVE + analyst REJECT preserves passing checks while recording
the person's operational objection. Manual approval does not confirm a CVE.

## 12. Missing CVEs: the defensible explanation

No standard found requires omitting PI Server or D20MX from a CVE CSV. The current
evidence does not establish that their absence was deliberately planned. The
defensible deliberate behavior is to avoid fabricating unsupported matches.

Use: "These endpoints have no eligible matches in the current corpus and remain
unassessed for CVE-based risk. They remain in inventory, traffic monitoring and
plant-policy review. Product aliases, version coverage and vendor advisories
require additional assessment."

NIST SP 800-82r3 section 6.3.2.4 supports combining automated and manual
vulnerability identification, and testing scans offline for OT suitability. Its
RA-5 OT overlay describes passive monitoring/manual inventory review followed
by cross-referencing known vulnerability sources. That supports a conservative
assessment method; it does not excuse a corpus gap or mean those devices are safe.

## 13. Anomalous count changing from 3 to 1

The count represents current stored anomaly flags, not lifetime detections. Each
endpoint is assessed independently. Two consecutive unusual samples confirm a
flag; a normal sample resets it. If two flagged endpoints subsequently return to
normal, the count can go from three to one. Exact historical identities require
before/after snapshots. The detector does not enforce a three-asset quota.

## 14. Setup and verification

Normal setup/migration now creates the ledger through `runtime_constraints`.
It can also be created explicitly:

```
python Database/migrate_policy_reviews.py
```

The feature passed 25 actual Flask/PostgreSQL workflow checks in an isolated
temporary schema, including acknowledgment, stale inputs, reevaluation, history,
and preserving automatic findings. JavaScript tests covered counts, save payload,
dialog acknowledgment and stale-evidence recovery. No synthetic analyst decisions
were written into the live database. Live GET/page checks verified 15 policy
assets and that monitoring remained running.

## A presentation sentence

"CAVE-OT evaluates available evidence against selected plant policies, explains
failures and missing facts, and proposes a review action. An analyst records a
separate decision with a reason and an evidence snapshot. Automatic updates
cannot erase that human review, and changed policy evidence prompts revalidation."

## Primary references

- [NIST SP 800-82r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf), section 6.3.2.4 and RA-5 OT overlay.
- [NERC CIP-007-6](https://www.nerc.com/globalassets/standards/reliability-standards/cip/cip-007-6.pdf), R2; applicable BES systems and patch assessment/mitigation processes must be distinguished from the demo's patch-age threshold.
- [CISA control-system patch-management practice](https://www.cisa.gov/sites/default/files/recommended_practices/RP_Patch_Management_S508C.pdf), vendor/configuration-aware assessment and operational impact considerations.
