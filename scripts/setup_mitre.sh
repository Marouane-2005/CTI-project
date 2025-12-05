#!/bin/bash
echo "Setting up MITRE ATT&CK integration..."

# Créer les répertoires nécessaires
mkdir -p data/mitre
mkdir -p logs/mitre

# Initialiser la base de données MITRE
python -c "
from pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher
enricher = MitreAttackEnricher()
print('MITRE database initialized')
"

# Première synchronisation
python -c "
import asyncio
from pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher
async def setup():
    enricher = MitreAttackEnricher()
    await enricher.update_mitre_data()
    print('Initial MITRE data loaded')
asyncio.run(setup())
"

echo "MITRE ATT&CK setup completed!"