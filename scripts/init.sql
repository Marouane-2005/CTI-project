-- Script d'initialisation de la base de données CTI
-- Créé automatiquement au démarrage du conteneur PostgreSQL

-- Création des extensions nécessaires
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Table pour les indicateurs de menace
CREATE TABLE IF NOT EXISTS indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL UNIQUE,
    source VARCHAR(100),
    confidence INTEGER DEFAULT 50,
    severity VARCHAR(20) DEFAULT 'medium',
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tags TEXT[],
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table pour les CVEs
CREATE TABLE IF NOT EXISTS cves (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id VARCHAR(20) NOT NULL UNIQUE,
    description TEXT,
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(200),
    severity VARCHAR(20),
    published_date TIMESTAMP,
    modified_date TIMESTAMP,
    references TEXT[],
    cwe_ids VARCHAR(50)[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table pour les rapports d'analyse
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(200) NOT NULL,
    content TEXT,
    report_type VARCHAR(50),
    generated_by VARCHAR(100),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_path VARCHAR(500),
    metadata JSONB
);

-- Table pour les sources de données
CREATE TABLE IF NOT EXISTS data_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    url VARCHAR(500),
    api_key_encrypted TEXT,
    last_sync TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    sync_frequency INTEGER DEFAULT 3600, -- en secondes
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table pour les alertes
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    indicator_id UUID REFERENCES indicators(id),
    triggered_by VARCHAR(100),
    triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'open',
    resolved_at TIMESTAMP,
    metadata JSONB
);

-- Index pour améliorer les performances
CREATE INDEX IF NOT EXISTS idx_indicators_type ON indicators(type);
CREATE INDEX IF NOT EXISTS idx_indicators_source ON indicators(source);
CREATE INDEX IF NOT EXISTS idx_indicators_first_seen ON indicators(first_seen);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_published_date ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered_at ON alerts(triggered_at);

-- Fonction pour mettre à jour automatiquement updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers pour mettre à jour updated_at automatiquement
CREATE TRIGGER update_indicators_updated_at BEFORE UPDATE ON indicators 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cves_updated_at BEFORE UPDATE ON cves 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insertion de données de test (optionnel)
INSERT INTO data_sources (name, url, status) VALUES
    ('AlienVault OTX', 'https://otx.alienvault.com/api/v1', 'active'),
    ('Abuse.ch', 'https://abuse.ch/api', 'active'),
    ('VirusTotal', 'https://www.virustotal.com/vtapi/v2', 'active'),
    ('Shodan', 'https://api.shodan.io', 'active'),
    ('Twitter', 'https://api.twitter.com/2', 'active'),
    ('Telegram', 'https://api.telegram.org', 'active'),
    ('MISP', 'https://misp-project.org/api', 'inactive')
ON CONFLICT (name) DO NOTHING;

-- Vues utiles pour les rapports
CREATE OR REPLACE VIEW recent_indicators AS
SELECT * FROM indicators 
WHERE first_seen >= CURRENT_DATE - INTERVAL '7 days'
ORDER BY first_seen DESC;

CREATE OR REPLACE VIEW high_severity_alerts AS
SELECT * FROM alerts 
WHERE severity IN ('high', 'critical') 
AND status = 'open'
ORDER BY triggered_at DESC;