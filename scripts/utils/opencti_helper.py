"""
Utilitaires pour l'intégration OpenCTI
"""

import os
import json
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

class OpenCTIHelper:
    """Classe d'aide pour les opérations OpenCTI"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.base_url = config["opencti"]["url"]
        self.token = config["opencti"]["token"]
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def test_connection(self) -> bool:
        """Test de connexion à OpenCTI"""
        try:
            response = requests.get(
                f"{self.base_url}/graphql",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False
    
    def get_indicators_count(self) -> int:
        """Récupération du nombre d'indicateurs"""
        query = """
        query GetIndicatorsCount {
            indicators {
                edges {
                    node {
                        id
                    }
                }
            }
        }
        """
        
        try:
            response = requests.post(
                f"{self.base_url}/graphql",
                headers=self.headers,
                json={"query": query},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return len(data.get("data", {}).get("indicators", {}).get("edges", []))
            
        except Exception:
            pass
        
        return 0
    
    def create_indicator_batch(self, indicators: List[Dict]) -> bool:
        """Création d'indicateurs par batch"""
        # Implémentation de la création par lot
        for indicator in indicators:
            # Logique de création individuelle ou par batch
            pass
        return True

class STIXConverter:
    """Convertisseur vers le format STIX 2.1"""
    
    @staticmethod
    def ioc_to_stix(ioc: Dict) -> Dict:
        """Conversion d'un IOC vers STIX"""
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{STIXConverter._generate_uuid()}",
            "created": datetime.now().isoformat() + "Z",
            "modified": datetime.now().isoformat() + "Z",
            "pattern": STIXConverter._create_pattern(ioc),
            "labels": ["malicious-activity"],
            "confidence": ioc.get("confidence", 50)
        }
    
    @staticmethod
    def _generate_uuid() -> str:
        """Génération d'un UUID pour STIX"""
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def _create_pattern(ioc: Dict) -> str:
        """Création du pattern STIX"""
        ioc_type = ioc.get('type', '').lower()
        value = ioc.get('value', '')
        
        patterns = {
            'ip': f"[ipv4-addr:value = '{value}']",
            'domain': f"[domain-name:value = '{value}']",
            'url': f"[url:value = '{value}']",
            'hash': f"[file:hashes.MD5 = '{value}']"
        }
        
        return patterns.get(ioc_type, f"[x-custom:value = '{value}']")