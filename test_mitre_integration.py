import pytest
import asyncio
from scripts.pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher
from scripts.pipeline.enrichers.opencti_mitre_connector import OpenCTIMitreConnector

@pytest.mark.asyncio
async def test_cve_mitre_mapping():
    enricher = MitreAttackEnricher()
    
    cve_data = {
        "id": "CVE-2023-TEST",
        "description": "Remote code execution via PowerShell command injection"
    }
    
    mappings = enricher.map_cve_to_techniques(cve_data)
    assert len(mappings) > 0
    assert any("T1059.001" in mapping[0] for mapping in mappings)  # PowerShell

@pytest.mark.asyncio 
async def test_opencti_sync():
    # Mock config pour les tests
    test_config = {"url": "http://localhost:8082", "token": "test-token"}
    connector = OpenCTIMitreConnector(test_config)
    
    # Test de la synchronisation (avec mock)
    result = await connector.sync_mitre_to_opencti()
    assert result is True