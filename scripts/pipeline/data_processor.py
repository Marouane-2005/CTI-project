#!/usr/bin/env python3
"""
Processeur de données CTI pour l'intégration OpenCTI
Compatible avec l'architecture existante
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import pandas as pd

# Ajout du répertoire parent au chemin
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from utils.database import DatabaseManager


class CTIDataProcessor:
    """Processeur principal des données CTI"""
    
    def __init__(self):
        """Initialisation du processeur"""
        self.logger = get_logger(__name__)
        self.db = DatabaseManager()
        self.processed_stats = {
            "total_processed": 0,
            "iocs": 0,
            "cves": 0,
            "reports": 0,
            "errors": 0
        }
    
    def normalize_ioc_data(self, raw_iocs: List[Dict]) -> List[Dict]:
        """Normalisation des données IOC"""
        try:
            self.logger.info(f"🔄 Normalisation de {len(raw_iocs)} IOCs...")
            normalized_iocs = []
            
            for ioc in raw_iocs:
                try:
                    # Normalisation du format
                    normalized_ioc = {
                        "id": ioc.get("id"),
                        "value": self._clean_ioc_value(ioc.get("value", "")),
                        "type": self._normalize_ioc_type(ioc.get("type", "")),
                        "confidence": self._normalize_confidence(ioc.get("confidence", 50)),
                        "source": ioc.get("source", "Unknown"),
                        "first_seen": self._normalize_datetime(ioc.get("first_seen")),
                        "last_seen": self._normalize_datetime(ioc.get("last_seen")),
                        "threat_types": self._normalize_threat_types(ioc.get("threat_types", [])),
                        "tags": ioc.get("tags", []),
                        "tlp": self._normalize_tlp(ioc.get("tlp", "WHITE")),
                        "is_active": ioc.get("is_active", True),
                        "kill_chain_phases": ioc.get("kill_chain_phases", [])
                    }
                    
                    # Validation
                    if self._validate_ioc(normalized_ioc):
                        normalized_iocs.append(normalized_ioc)
                        self.processed_stats["iocs"] += 1
                    else:
                        self.logger.warning(f"⚠️ IOC invalide ignoré: {ioc.get('value', 'unknown')}")
                        self.processed_stats["errors"] += 1
                
                except Exception as e:
                    self.logger.error(f"❌ Erreur normalisation IOC {ioc.get('value', 'unknown')}: {e}")
                    self.processed_stats["errors"] += 1
                    continue
            
            self.logger.info(f"✅ {len(normalized_iocs)} IOCs normalisés avec succès")
            return normalized_iocs
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de la normalisation des IOCs: {e}")
            return []
    
    def _clean_ioc_value(self, value: str) -> str:
        """Nettoyage de la valeur IOC"""
        if not value:
            return ""
        
        # Suppression des espaces et caractères spéciaux
        value = value.strip().lower()
        
        # Nettoyage spécifique par type
        if value.startswith("http"):
            # URL: suppression des paramètres de tracking
            value = value.split("?")[0].split("#")[0]
        elif "[.]" in value:
            # Domain/IP defanged: restauration
            value = value.replace("[.]", ".")
        elif "hxxp" in value:
            # URL defanged: restauration
            value = value.replace("hxxp", "http")
        
        return value
    
    def _normalize_ioc_type(self, ioc_type: str) -> str:
        """Normalisation du type d'IOC"""
        type_mapping = {
            "ip": "ipv4",
            "ip-addr": "ipv4",
            "ipv4-addr": "ipv4",
            "domain": "domain-name",
            "domain-name": "domain-name",
            "url": "url",
            "hash": "file-hash",
            "md5": "file-hash-md5",
            "sha1": "file-hash-sha1",
            "sha256": "file-hash-sha256",
            "email": "email-addr",
            "file": "file"
        }
        
        return type_mapping.get(ioc_type.lower(), ioc_type.lower())
    
    def _normalize_confidence(self, confidence: Union[int, str]) -> int:
        """Normalisation du niveau de confiance (0-100)"""
        try:
            conf = int(confidence)
            return max(0, min(100, conf))  # Clamp between 0-100
        except (ValueError, TypeError):
            return 50  # Valeur par défaut
    
    def _normalize_datetime(self, dt_value: Any) -> Optional[str]:
        """Normalisation des dates vers ISO format"""
        if not dt_value:
            return None
        
        try:
            if isinstance(dt_value, str):
                # Tentative de parsing de différents formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%SZ"]:
                    try:
                        dt = datetime.strptime(dt_value, fmt)
                        return dt.isoformat() + "Z"
                    except ValueError:
                        continue
            elif isinstance(dt_value, datetime):
                return dt_value.isoformat() + "Z"
        except Exception as e:
            self.logger.warning(f"⚠️ Date invalide: {dt_value} - {e}")
        
        return None
    
    def _normalize_threat_types(self, threat_types: List[str]) -> List[str]:
        """Normalisation des types de menace"""
        normalized_types = []
        
        type_mapping = {
            "malware": "malicious-activity",
            "phishing": "malicious-activity",
            "botnet": "malicious-activity",
            "c2": "malicious-activity",
            "apt": "malicious-activity",
            "suspicious": "suspicious-activity",
            "benign": "benign"
        }
        
        for threat_type in threat_types:
            normalized = type_mapping.get(threat_type.lower(), threat_type)
            if normalized not in normalized_types:
                normalized_types.append(normalized)
        
        return normalized_types or ["malicious-activity"]
    
    def _normalize_tlp(self, tlp: str) -> str:
        """Normalisation du Traffic Light Protocol"""
        tlp_levels = ["WHITE", "GREEN", "AMBER", "RED"]
        tlp_upper = tlp.upper()
        return tlp_upper if tlp_upper in tlp_levels else "WHITE"
    
    def _validate_ioc(self, ioc: Dict) -> bool:
        """Validation d'un IOC normalisé"""
        # Vérifications basiques
        if not ioc.get("value"):
            return False
        
        if not ioc.get("type"):
            return False
        
        # Validation spécifique par type
        ioc_type = ioc["type"]
        value = ioc["value"]
        
        if ioc_type == "ipv4":
            return self._validate_ipv4(value)
        elif ioc_type == "domain-name":
            return self._validate_domain(value)
        elif ioc_type == "url":
            return self._validate_url(value)
        elif "file-hash" in ioc_type:
            return self._validate_hash(value, ioc_type)
        
        return True  # Validation basique passée
    
    def _validate_ipv4(self, ip: str) -> bool:
        """Validation d'une adresse IPv4"""
        import ipaddress
        try:
            ipaddress.ipv4_address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validation d'un nom de domaine"""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
    
    def _validate_url(self, url: str) -> bool:
        """Validation d'une URL"""
        import re
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))
    
    def _validate_hash(self, hash_value: str, hash_type: str) -> bool:
        """Validation d'un hash"""
        import re
        hash_patterns = {
            "file-hash-md5": r'^[a-fA-F0-9]{32}$',
            "file-hash-sha1": r'^[a-fA-F0-9]{40}$',
            "file-hash-sha256": r'^[a-fA-F0-9]{64}$'
        }
        
        pattern = hash_patterns.get(hash_type, r'^[a-fA-F0-9]+$')
        return bool(re.match(pattern, hash_value))
    
    def enrich_ioc_data(self, iocs: List[Dict]) -> List[Dict]:
        """Enrichissement des données IOC"""
        try:
            self.logger.info(f"🔍 Enrichissement de {len(iocs)} IOCs...")
            enriched_iocs = []
            
            for ioc in iocs:
                try:
                    # Enrichissement depuis la base de données existante
                    enriched_ioc = ioc.copy()
                    
                    # Ajout des informations de géolocalisation pour les IPs
                    if ioc["type"] == "ipv4":
                        geo_info = self._get_geo_info(ioc["value"])
                        if geo_info:
                            enriched_ioc["geo_info"] = geo_info
                    
                    # Ajout des informations WHOIS pour les domaines
                    elif ioc["type"] == "domain-name":
                        whois_info = self._get_whois_info(ioc["value"])
                        if whois_info:
                            enriched_ioc["whois_info"] = whois_info
                    
                    # Recherche d'historique dans la base
                    historical_data = self._get_historical_data(ioc["value"])
                    if historical_data:
                        enriched_ioc["historical_detections"] = historical_data
                    
                    # Score de réputation calculé
                    reputation_score = self._calculate_reputation_score(enriched_ioc)
                    enriched_ioc["reputation_score"] = reputation_score
                    
                    enriched_iocs.append(enriched_ioc)
                    
                except Exception as e:
                    self.logger.warning(f"⚠️ Erreur enrichissement IOC {ioc.get('value')}: {e}")
                    enriched_iocs.append(ioc)  # Ajout sans enrichissement
                    continue
            
            self.logger.info(f"✅ {len(enriched_iocs)} IOCs enrichis")
            return enriched_iocs
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'enrichissement: {e}")
            return iocs  # Retour des données originales
    
    def _get_geo_info(self, ip: str) -> Optional[Dict]:
        """Récupération des informations de géolocalisation"""
        try:
            # Ici vous pouvez intégrer votre logique de géolocalisation
            # Par exemple via MaxMind GeoIP ou une API
            geo_info = self.db.get_ip_geolocation(ip)
            return geo_info
        except Exception as e:
            self.logger.debug(f"Pas d'info géo pour {ip}: {e}")
            return None
    
    def _get_whois_info(self, domain: str) -> Optional[Dict]:
        """Récupération des informations WHOIS"""
        try:
            # Intégration avec votre système WHOIS existant
            whois_info = self.db.get_domain_whois(domain)
            return whois_info
        except Exception as e:
            self.logger.debug(f"Pas d'info WHOIS pour {domain}: {e}")
            return None
    
    def _get_historical_data(self, ioc_value: str) -> Optional[List[Dict]]:
        """Récupération des données historiques"""
        try:
            historical = self.db.get_ioc_history(ioc_value, limit=10)
            return historical
        except Exception as e:
            self.logger.debug(f"Pas d'historique pour {ioc_value}: {e}")
            return None
    
    def _calculate_reputation_score(self, ioc: Dict) -> int:
        """Calcul du score de réputation (0-100)"""
        base_score = ioc.get("confidence", 50)
        
        # Ajustements basés sur l'enrichissement
        if ioc.get("historical_detections"):
            base_score += len(ioc["historical_detections"]) * 5
        
        if ioc.get("geo_info", {}).get("is_malicious"):
            base_score += 20
        
        if "malicious-activity" in ioc.get("threat_types", []):
            base_score += 15
        
        # Plafonnement
        return min(100, max(0, base_score))
    
    def process_cve_data(self, raw_cves: List[Dict]) -> List[Dict]:
        """Traitement et normalisation des données CVE"""
        try:
            self.logger.info(f"🛡️ Traitement de {len(raw_cves)} CVEs...")
            processed_cves = []
            
            for cve in raw_cves:
                try:
                    processed_cve = {
                        "cve_id": cve.get("cve_id", "").upper(),
                        "description": cve.get("description", ""),
                        "cvss_score": float(cve.get("cvss_score", 0)),
                        "severity": self._normalize_severity(cve.get("severity", "UNKNOWN")),
                        "published_date": self._normalize_datetime(cve.get("published_date")),
                        "modified_date": self._normalize_datetime(cve.get("modified_date")),
                        "references": cve.get("references", []),
                        "cwe_ids": cve.get("cwe_ids", []),
                        "affected_products": cve.get("affected_products", []),
                        "exploitability_score": cve.get("exploitability_score", 0),
                        "impact_score": cve.get("impact_score", 0),
                        "vector_string": cve.get("vector_string", "")
                    }
                    
                    if self._validate_cve(processed_cve):
                        processed_cves.append(processed_cve)
                        self.processed_stats["cves"] += 1
                    else:
                        self.processed_stats["errors"] += 1
                
                except Exception as e:
                    self.logger.warning(f"⚠️ Erreur traitement CVE {cve.get('cve_id')}: {e}")
                    self.processed_stats["errors"] += 1
                    continue
            
            self.logger.info(f"✅ {len(processed_cves)} CVEs traités")
            return processed_cves
            
        except Exception as e:
            self.logger.error(f"❌ Erreur traitement CVEs: {e}")
            return []
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalisation de la sévérité CVE"""
        severity_mapping = {
            "low": "LOW",
            "medium": "MEDIUM", 
            "high": "HIGH",
            "critical": "CRITICAL"
        }
        return severity_mapping.get(severity.lower(), "UNKNOWN")
    
    def _validate_cve(self, cve: Dict) -> bool:
        """Validation d'un CVE"""
        import re
        
        # Validation du format CVE ID
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        if not re.match(cve_pattern, cve.get("cve_id", "")):
            return False
        
        # Validation du score CVSS
        cvss_score = cve.get("cvss_score", 0)
        if not (0 <= cvss_score <= 10):
            return False
        
        return True
    
    def generate_report_data(self, processed_data: Dict) -> Dict:
        """Génération des données de rapport"""
        try:
            self.logger.info("📊 Génération du rapport de traitement...")
            
            report = {
                "timestamp": datetime.now().isoformat() + "Z",
                "processing_stats": self.processed_stats,
                "data_quality": {
                    "total_items": self.processed_stats["total_processed"],
                    "success_rate": self._calculate_success_rate(),
                    "error_rate": self._calculate_error_rate()
                },
                "summary": {
                    "iocs": {
                        "total": len(processed_data.get("iocs", [])),
                        "by_type": self._count_by_type(processed_data.get("iocs", [])),
                        "high_confidence": self._count_high_confidence(processed_data.get("iocs", []))
                    },
                    "cves": {
                        "total": len(processed_data.get("cves", [])),
                        "by_severity": self._count_by_severity(processed_data.get("cves", [])),
                        "critical_count": self._count_critical_cves(processed_data.get("cves", []))
                    }
                }
            }
            
            self.logger.info("✅ Rapport généré avec succès")
            return report
            
        except Exception as e:
            self.logger.error(f"❌ Erreur génération rapport: {e}")
            return {"error": str(e), "timestamp": datetime.now().isoformat()}
    
    def _calculate_success_rate(self) -> float:
        """Calcul du taux de succès"""
        total = self.processed_stats["total_processed"]
        errors = self.processed_stats["errors"]
        return ((total - errors) / total * 100) if total > 0 else 0.0
    
    def _calculate_error_rate(self) -> float:
        """Calcul du taux d'erreur"""
        total = self.processed_stats["total_processed"]
        errors = self.processed_stats["errors"]
        return (errors / total * 100) if total > 0 else 0.0
    
    def _count_by_type(self, iocs: List[Dict]) -> Dict:
        """Comptage des IOCs par type"""
        counts = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            counts[ioc_type] = counts.get(ioc_type, 0) + 1
        return counts
    
    def _count_high_confidence(self, iocs: List[Dict]) -> int:
        """Comptage des IOCs à haute confiance (>= 80)"""
        return len([ioc for ioc in iocs if ioc.get("confidence", 0) >= 80])
    
    def _count_by_severity(self, cves: List[Dict]) -> Dict:
        """Comptage des CVEs par sévérité"""
        counts = {}
        for cve in cves:
            severity = cve.get("severity", "UNKNOWN")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_critical_cves(self, cves: List[Dict]) -> int:
        """Comptage des CVEs critiques"""
        return len([cve for cve in cves if cve.get("severity") == "CRITICAL"])


def main():
    """Fonction principale pour test"""
    processor = CTIDataProcessor()
    
    # Exemple de traitement
    sample_iocs = [
        {
            "value": "192.168.1.100",
            "type": "ip",
            "confidence": 85,
            "source": "Internal Analysis"
        }
    ]
    
    normalized = processor.normalize_ioc_data(sample_iocs)
    enriched = processor.enrich_ioc_data(normalized)
    
    print(f"✅ Traité {len(enriched)} IOCs")


if __name__ == "__main__":
    main()