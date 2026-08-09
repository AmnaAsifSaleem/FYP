-- Policy Compliance Database Schema Extension
-- Add policy compliance tables to existing CAVE-OT database

-- Policy compliance results table
CREATE TABLE IF NOT EXISTS policy_compliance (
    id SERIAL PRIMARY KEY,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    compliance_status VARCHAR(20) NOT NULL CHECK (compliance_status IN ('COMPLIANT', 'NON_COMPLIANT', 'NEEDS_REVIEW')),
    compliance_score FLOAT DEFAULT 0.0,
    confidence FLOAT DEFAULT 0.0,
    explanation TEXT,
    key_factors JSONB,
    checked_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(asset_id)
);

-- Policy violations detail table
CREATE TABLE IF NOT EXISTS policy_violations (
    id SERIAL PRIMARY KEY,
    compliance_id INTEGER NOT NULL REFERENCES policy_compliance(id) ON DELETE CASCADE,
    violated_policy TEXT NOT NULL,
    policy_source VARCHAR(100),
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    remediation TEXT,
    detected_at TIMESTAMP DEFAULT NOW()
);

-- Policy rules reference table
CREATE TABLE IF NOT EXISTS policy_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    description TEXT,
    policy_source VARCHAR(100),
    zone VARCHAR(20),
    service VARCHAR(50),
    port INTEGER,
    encrypted BOOLEAN,
    device_type VARCHAR(50),
    cvss_threshold FLOAT,
    epss_threshold FLOAT,
    days_since_patch_threshold INTEGER,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_policy_compliance_asset_id ON policy_compliance(asset_id);
CREATE INDEX idx_policy_compliance_status ON policy_compliance(compliance_status);
CREATE INDEX idx_policy_compliance_score ON policy_compliance(compliance_score DESC);
CREATE INDEX idx_policy_violations_compliance_id ON policy_violations(compliance_id);
CREATE INDEX idx_policy_rules_zone_service ON policy_rules(zone, service);

-- Insert sample policy rules based on NIST SP 800-82r3 and CISA DiD
INSERT INTO policy_rules (rule_name, description, policy_source, zone, service, encrypted, is_active) VALUES
('OT Zone Encryption', 'All communications in OT zone must be encrypted', 'NIST SP 800-82r3 §6.2.3', 'OT', NULL, TRUE, TRUE),
('SCADA Zone Protocol Restriction', 'Only approved protocols allowed in SCADA zone', 'CISA DiD §2.4.1', 'SCADA_Zone', NULL, NULL, TRUE),
('IT Zone HTTPS Only', 'Web services in IT zone must use HTTPS', 'NIST SP 800-82r3 §5.2.3', 'IT', 'HTTP', TRUE, TRUE),
('DMZ Zone Segmentation', 'DMZ must not contain OT protocols', 'NIST SP 800-82r3 §6.2.10', 'DMZ', NULL, NULL, TRUE),
('Patch Compliance', 'Devices must be patched within 35 days', 'NERC CIP-007-6 R2', NULL, NULL, NULL, TRUE),
('Firmware EOL Check', 'Devices with end-of-life firmware are non-compliant', 'NIST SP 800-82r3 §5.2.5.2', NULL, NULL, NULL, TRUE),
('High CVSS Alert', 'Devices with CVSS >= 7.0 require immediate attention', 'CISA DiD §2.6.1', NULL, NULL, NULL, TRUE);

-- View for compliance dashboard
CREATE OR REPLACE VIEW compliance_dashboard AS
SELECT 
    a.id as asset_id,
    a.ip,
    a.port,
    a.vendor,
    a.product,
    a.device_type,
    a.zone,
    a.service,
    pc.compliance_status,
    pc.compliance_score,
    pc.confidence,
    pc.explanation,
    pc.checked_at,
    COUNT(pv.id) as violation_count,
    STRING_AGG(DISTINCT pv.severity, ', ') as violation_severities
FROM assets a
LEFT JOIN policy_compliance pc ON a.id = pc.asset_id
LEFT JOIN policy_violations pv ON pc.id = pv.compliance_id
GROUP BY a.id, a.ip, a.port, a.vendor, a.product, a.device_type, a.zone, a.service, 
         pc.compliance_status, pc.compliance_score, pc.confidence, pc.explanation, pc.checked_at
ORDER BY pc.compliance_score ASC, a.criticality DESC;

-- Function to update policy compliance
CREATE OR REPLACE FUNCTION update_policy_compliance(
    p_asset_id INTEGER,
    p_compliance_status VARCHAR,
    p_compliance_score FLOAT,
    p_confidence FLOAT,
    p_explanation TEXT,
    p_key_factors JSONB DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_compliance_id INTEGER;
BEGIN
    -- Insert or update compliance record
    INSERT INTO policy_compliance (asset_id, compliance_status, compliance_score, confidence, explanation, key_factors)
    VALUES (p_asset_id, p_compliance_status, p_compliance_score, p_confidence, p_explanation, p_key_factors)
    ON CONFLICT (asset_id) 
    DO UPDATE SET 
        compliance_status = EXCLUDED.compliance_status,
        compliance_score = EXCLUDED.compliance_score,
        confidence = EXCLUDED.confidence,
        explanation = EXCLUDED.explanation,
        key_factors = EXCLUDED.key_factors,
        checked_at = NOW()
    RETURNING id INTO v_compliance_id;
    
    RETURN v_compliance_id;
END;
$$ LANGUAGE plpgsql;