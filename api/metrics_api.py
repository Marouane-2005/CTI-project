from fastapi import APIRouter, HTTPException
from scripts.pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])
mitre_enricher = MitreAttackEnricher()

@router.post("/enrich/cve")
async def enrich_cve_endpoint(cve_data: dict):
    """Endpoint pour enrichir un CVE avec MITRE"""
    try:
        mappings = mitre_enricher.map_cve_to_techniques(cve_data)
        return {"cve_id": cve_data.get("id"), "mitre_mappings": mappings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/stats")
async def get_mitre_stats():
    """Statistiques MITRE pour le dashboard"""
    return mitre_enricher.get_attack_statistics()

@app.route('/api/dashboard/live-threats', methods=['GET'])
def get_live_threats():
    # Utilise vos collectors existants
    threats = []
    # Intégration avec abuse_ch_collector, otx_collector, etc.
    return jsonify(threats)