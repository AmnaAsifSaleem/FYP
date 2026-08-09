# CAVE-OT — Known Gaps / Follow-Up Work

Running list of things identified during testing/review that aren't fixed yet.
Not urgent for the current live demo — tracked here so they don't get lost.

---

## 1. Asset discovery assumes every device is known — no "Unknown" path

**Problem:** `smart_discover.py` identifies a device purely by looking up its port
in a static table (`PORT_MAP` / `CONPOT_CONFIG`). This works in the testbed because
every device on every port was configured by us. In a real deployment, an
unrecognized port/device would currently have no defined behavior — the pipeline
assumes full knowledge of the asset roster.

**What to do:**
- When a port/protocol combination doesn't match any entry in `PORT_MAP`, insert
  the asset as `vendor: "Unknown"`, `product: "Unknown"`, `firmware: "Unknown"`
  instead of silently failing or being skipped (there's already a fallback branch
  for this in `discover_assets()` — the "Unknown" case exists in code but isn't
  something we've deliberately designed around end-to-end, e.g. what CVE matching
  does with an "Unknown" vendor/product string, how it displays on the dashboard,
  whether it still gets a generic protocol-level risk baseline).
- Decide what CVE matching should do for an "Unknown" device — likely: skip
  TF-IDF matching entirely (no meaningful query text) and instead apply a
  generic protocol-level risk heuristic (e.g. "unauthenticated Modbus" is
  inherently risky regardless of vendor).
- Surface "Unknown" assets clearly on the dashboard (distinct visual state, not
  blended in with identified devices) so an analyst knows it needs manual
  tagging, rather than the tool implying false confidence.

**Why it matters:** came up discussing real-world viability — port number alone
only tells you the protocol, not the vendor/product, in a real network. Handling
unknown devices gracefully (rather than assuming a closed, fully-known device set)
is the actual gap between "testbed" and "works on a real network."

---

## 2. Policy Compliance is 100% ML classification — no deterministic rule layer

**Problem:** `Policy_Compliance/policy_predictor.py` (RandomForestClassifier) makes
the *entire* compliance decision. The `policy_rules` DB table (7 seeded NIST SP
800-82r3 / NERC CIP-007-6 / CISA DiD rules) exists and is fully populated, but
`Dashboard/policy_api.py` only ever reads it for a passive `GET /rules` display
endpoint — it is never consulted by the actual prediction logic.

**What to do:**
- Implement the "gatekeeper" pattern already described in
  `CAVE-OT_Iteration_and_Roadmap.md` section 2.3: deterministic rule checks
  first (cheap, explainable, auditable), ML classifier output attached as a
  secondary confidence signal, not the sole decision-maker.
- Concretely: before/alongside calling `predictor.predict()`, check the asset
  against matching `policy_rules` rows (zone/service/port match) and produce a
  hard ALLOW/BLOCK/NEEDS_REVIEW verdict from the rules; only use the ML
  compliance_score as supporting context, not the final answer.
- Also worth revisiting: `NEEDS_REVIEW` (a real label in the training data,
  27/3000 rows) currently gets silently folded into "non-compliant" during
  training (`policy_preprocessor.py`, binary target). A rule-based layer could
  reintroduce a genuine third state instead of collapsing it.

**Why it matters:** an evaluator will reasonably ask "would you trust an ML
model alone to gate actions on a water treatment plant?" — the honest answer
is no, and the architecture should already say no. Right now it doesn't.

---

## 3. Repo / VM file layout needs restructuring — too scattered, too easy to drift

**Problem:** established this session the hard way — the repo's `cave_monitor.py`
and the VM's actual live `cave_monitor.py` had diverged (different device
rosters, different concurrency handling) without anyone noticing until it broke
something. More generally: project files are spread across the repo root,
`shared folder/`, `A:\VM\CAVE-OT\shared folder\` (the real VM mount), `vm_extra/`,
`Assets/`, `model/`, and multiple near-duplicate scripts (`risk_scorer.py` vs
`risk_scorer_v2.py`, `discover.py` vs `smart_discover.py`, etc. — see
`PROJECT_STRUCTURE.md`'s deprecated-files table). No single source of truth for
"what's actually running where."

**What to do:**
- Pick one canonical location for VM-side scripts and stop hand-editing the
  Windows-side shared-folder copy as if it were the source of truth — right now
  edits made directly in `A:\VM\CAVE-OT\shared folder\` don't get committed to
  git at all unless manually copied back, which is exactly how the drift happened.
- Decide a clear sync direction: either (a) the git repo is authoritative and a
  script/step pushes it to the VM before each run, or (b) the VM is authoritative
  for VM-side files and there's a deliberate pull-and-commit step — not both
  edited independently like today.
- Clean up the deprecated/superseded files `PROJECT_STRUCTURE.md` already
  identifies (`risk_scorer.py`, `discover.py`, `newdiscover.py`, `traffic.py`,
  `live_comms.py`, the old TUI variants, etc.) — archive or delete rather than
  leaving them sitting alongside the real ones.
- Consider whether `model/*.pkl`, `Datasets/`, and VM disk images really need to
  be as scattered as they are now (repo root `model/`, VM shared folder root,
  `A:\VM\CAVE-OT\` itself) — at minimum, document clearly in `PROJECT_STRUCTURE.md`
  which copy is authoritative if more than one must exist.

**Why it matters:** the `cave_monitor.py` divergence this session wasn't a one-off
— it's a structural risk that will keep causing silent bugs (like the dead
entry-point and stale-topology bugs both were) as long as the same logical file
can exist as multiple, independently-editable copies with no sync discipline.
