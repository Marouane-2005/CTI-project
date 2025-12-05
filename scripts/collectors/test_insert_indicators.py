import json
import psycopg2
from datetime import datetime

# Charger la config
with open("config/database.json") as f:
    config = json.load(f)
pg = config["postgresql"]

# Connexion PostgreSQL
conn = psycopg2.connect(
    host=pg["host"],
    port=pg["port"],
    dbname=pg["database"],
    user=pg["username"],
    password=pg["password"]
)
cursor = conn.cursor()

# Créer la table si elle n'existe pas
cursor.execute('''
    CREATE TABLE IF NOT EXISTS indicators (
        id SERIAL PRIMARY KEY,
        indicator_value VARCHAR NOT NULL,
        indicator_type VARCHAR NOT NULL,
        source VARCHAR,
        description TEXT,
        malware_family VARCHAR,
        confidence_level INT,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        tags JSONB,
        collected_at TIMESTAMP,
        processed BOOLEAN DEFAULT FALSE
    )
''')

# Exemple d’indicateur
indicator = {
    "value": "malicious.com",
    "type": "domain",
    "source": "OTX",
    "description": "Domaine malveillant observé",
    "malware_family": "Emotet",
    "confidence_level": 85,
    "first_seen": datetime.utcnow(),
    "last_seen": datetime.utcnow(),
    "tags": ["phishing", "malware"],
    "collected_at": datetime.utcnow()
}

# Insertion
cursor.execute('''
    INSERT INTO indicators (
        indicator_value, indicator_type, source, description, malware_family,
        confidence_level, first_seen, last_seen, tags, collected_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
''', (
    indicator["value"],
    indicator["type"],
    indicator["source"],
    indicator["description"],
    indicator["malware_family"],
    indicator["confidence_level"],
    indicator["first_seen"],
    indicator["last_seen"],
    json.dumps(indicator["tags"]),
    indicator["collected_at"]
))

conn.commit()
cursor.close()
conn.close()

print("✅ Indicateur inséré avec succès dans PostgreSQL")