CREATE TABLE IF NOT EXISTS assets (id SERIAL PRIMARY KEY, ip VARCHAR(45) NOT NULL, port INTEGER NOT NULL, service VARCHAR(50), device_type VARCHAR(50), zone VARCHAR(10) DEFAULT 'OT', vendor VARCHAR(100), product VARCHAR(100), firmware VARCHAR(50), description TEXT, criticality FLOAT DEFAULT 0.5, packet_count INTEGER DEFAULT 0, anomaly_score FLOAT DEFAULT 0.0, is_anomalous BOOLEAN DEFAULT FALSE, anomaly_reason TEXT, first_seen TIMESTAMP DEFAULT NOW(), last_seen TIMESTAMP DEFAULT NOW(), status VARCHAR(10) DEFAULT 'ACTIVE', CONSTRAINT unique_ip_port UNIQUE (ip, port));
CREATE TABLE IF NOT EXISTS vulnerabilities (id SERIAL PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE, cve_id VARCHAR(20) NOT NULL, cvss FLOAT DEFAULT 0.0, epss FLOAT DEFAULT 0.0, kev BOOLEAN DEFAULT FALSE, c_impact FLOAT DEFAULT 0.0, i_impact FLOAT DEFAULT 0.0, a_impact FLOAT DEFAULT 0.0, similarity FLOAT DEFAULT 0.0, risk_score FLOAT DEFAULT 0.0, risk_tier VARCHAR(10) DEFAULT 'LOW', discovered_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW(), CONSTRAINT unique_asset_cve UNIQUE (asset_id, cve_id));
CREATE TABLE IF NOT EXISTS alerts (id SERIAL PRIMARY KEY, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE, vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE SET NULL, alert_signature VARCHAR(255), alert_category VARCHAR(100), severity INTEGER DEFAULT 3, protocol VARCHAR(20), src_ip VARCHAR(45), dst_ip VARCHAR(45), src_port INTEGER, dst_port INTEGER, is_active_attack BOOLEAN DEFAULT FALSE, alert_count INTEGER DEFAULT 1, raw_event TEXT, detected_at TIMESTAMP DEFAULT NOW(), CONSTRAINT unique_asset_alert UNIQUE (asset_id, alert_signature));
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets (status);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets (ip);
CREATE INDEX IF NOT EXISTS idx_vuln_asset_id ON vulnerabilities (asset_id);
CREATE INDEX IF NOT EXISTS idx_vuln_risk_tier ON vulnerabilities (risk_tier);
CREATE INDEX IF NOT EXISTS idx_vuln_risk_score ON vulnerabilities (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_asset_id ON alerts (asset_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS attack_paths (
    id               SERIAL PRIMARY KEY,
    entry_asset      VARCHAR(60)  NOT NULL,
    target_asset     VARCHAR(60)  NOT NULL,
    hops             INTEGER      NOT NULL,
    cost             FLOAT        NOT NULL,
    max_risk_on_path FLOAT        NOT NULL,
    path_json        TEXT         NOT NULL,
    computed_at      TIMESTAMP    DEFAULT NOW(),
    CONSTRAINT uq_attack_path UNIQUE (entry_asset, target_asset)
);

CREATE INDEX IF NOT EXISTS idx_ap_cost ON attack_paths (cost ASC);

CREATE TABLE IF NOT EXISTS attack_path_nodes (
    device_name    VARCHAR(60) PRIMARY KEY,
    zone           VARCHAR(10) NOT NULL,
    criticality    FLOAT       NOT NULL,
    vendor         VARCHAR(120) DEFAULT '',
    product        VARCHAR(120) DEFAULT '',
    risk_score     FLOAT       NOT NULL,
    is_attacked    INTEGER     NOT NULL,
    top_cve_id     VARCHAR(20),
    top_cve_cvss   FLOAT,
    top_cve_tier   VARCHAR(10),
    top_cve_desc   TEXT,
    updated_at     TIMESTAMP   DEFAULT NOW()
);
