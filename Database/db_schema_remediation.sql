-- Remediation Advisor + Policy Gatekeeper Database Schema Extension
-- Adds remediation tables to existing CAVE-OT database

-- Current-state recommendation per (asset, CVE) pair
CREATE TABLE IF NOT EXISTS remediation_recommendations (
    id                          SERIAL PRIMARY KEY,
    asset_id                    INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    cve_id                      VARCHAR(20) NOT NULL,
    risk_score_at_generation    FLOAT DEFAULT 0.0,
    risk_tier_at_generation     VARCHAR(10),

    recommendation              TEXT NOT NULL,
    rationale                   TEXT,
    ot_safety_note              TEXT,
    requires_maintenance_window BOOLEAN DEFAULT FALSE,
    llm_confidence               FLOAT DEFAULT 0.0,
    llm_model                   VARCHAR(50),
    retrieved_context           JSONB,

    gatekeeper_verdict          VARCHAR(20) NOT NULL CHECK (gatekeeper_verdict IN ('ALLOW','BLOCK','NEEDS_REVIEW')),
    gatekeeper_reasons          JSONB,
    gatekeeper_matched_rules    JSONB,
    ml_confidence_signal        JSONB,

    status                      VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                                 CHECK (status IN ('PENDING','APPROVED','REJECTED','DEFERRED')),
    decision_note                TEXT,
    decided_at                  TIMESTAMP,

    generated_at                TIMESTAMP DEFAULT NOW(),
    updated_at                  TIMESTAMP DEFAULT NOW(),

    CONSTRAINT uq_remediation_asset_cve UNIQUE (asset_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_status  ON remediation_recommendations(status);
CREATE INDEX IF NOT EXISTS idx_remediation_verdict ON remediation_recommendations(gatekeeper_verdict);
CREATE INDEX IF NOT EXISTS idx_remediation_asset   ON remediation_recommendations(asset_id);

-- Append-only history of every gatekeeper evaluation (audit/evidence trail —
-- independent of the human-decision UPDATE on the main row above)
CREATE TABLE IF NOT EXISTS remediation_gatekeeper_audit (
    id                   SERIAL PRIMARY KEY,
    recommendation_id    INTEGER NOT NULL REFERENCES remediation_recommendations(id) ON DELETE CASCADE,
    asset_id             INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    verdict              VARCHAR(20) NOT NULL CHECK (verdict IN ('ALLOW','BLOCK','NEEDS_REVIEW')),
    reasons              JSONB,
    matched_rules        JSONB,
    ml_confidence_signal JSONB,
    evaluated_at         TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_gk_audit_recommendation ON remediation_gatekeeper_audit(recommendation_id);
