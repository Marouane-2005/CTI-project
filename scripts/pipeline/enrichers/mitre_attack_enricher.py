# pipeline/enrichers/mitre_attack_enricher.py

import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

# Gestion conditionnelle de l'import requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.getLogger(__name__).warning("requests module not available, MITRE data update will be disabled")

from .base_enricher import BaseEnricher

@dataclass
class AttackTechnique:
    """Représente une technique MITRE ATT&CK"""
    technique_id: str
    name: str
    description: str
    tactic: str
    subtechniques: List[str]
    platforms: List[str]
    kill_chain_phases: List[str]
    references: List[Dict]

@dataclass
class AttackGroup:
    """Représente un groupe APT/Threat Actor"""
    group_id: str
    name: str
    aliases: List[str]
    description: str
    techniques: List[str]
    software: List[str]

class MitreAttackEnricher(BaseEnricher):
    """Enrichisseur MITRE ATT&CK pour votre projet CTI"""
    
    def __init__(self, config_path: str = "config/mitre_config.json"):
    # Appeler le constructeur parent
      super().__init__(config_path)
    
    # S'assurer que la configuration a toutes les valeurs nécessaires
      self._ensure_default_config()
    
      self.logger = logging.getLogger(__name__)
    
    # Utiliser des chemins relatifs
      self.db_path = os.path.join("data", "mitre_attack.db")
      self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
      self._init_database()
        
    def _load_mitre_config(self, config_path: str) -> Dict:
        """Charge la configuration MITRE ATT&CK"""
        default_config = {
            "update_frequency": "weekly",
            "frameworks": ["enterprise-attack", "mobile-attack", "ics-attack"],
            "auto_mapping": True,
            "confidence_threshold": 0.7,
            "enable_subtechniques": True
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            mitre_config = {**default_config, **config}
            self.config.update(mitre_config)
            return mitre_config
        except FileNotFoundError:
            self.logger.warning(f"Config file not found, using defaults")
            self.config.update(default_config)
            return default_config
    
    async def enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
     try:
        data_type = data.get("type", "").lower()
        
        if data_type == "vulnerability" or "cve" in data.get("id", "").lower():
            techniques = self.map_cve_to_techniques(data)
            if techniques:
                data["mitre_attack"] = {
                    "techniques": [
                        {
                            "technique_id": tech_id,
                            "confidence": conf,
                            "name": self.get_technique_details(tech_id).name if self.get_technique_details(tech_id) else ""
                        }
                        for tech_id, conf in techniques
                    ],
                    "enriched_at": datetime.now().isoformat()
                }
                
                # Envoyer vers OpenCTI
                await self.send_to_opencti(data)
                
        elif data_type == "indicator" or data_type == "ioc":
            techniques = self.map_ioc_to_techniques(data)
            if techniques:
                data["mitre_attack"] = {
                    "techniques": [
                        {
                            "technique_id": tech_id,
                            "confidence": conf,
                            "name": self.get_technique_details(tech_id).name if self.get_technique_details(tech_id) else ""
                        }
                        for tech_id, conf in techniques
                    ],
                    "enriched_at": datetime.now().isoformat()
                }
                
                # Envoyer vers OpenCTI
                await self.send_to_opencti(data)
                
        return data
        
     except Exception as e:
        self.logger.error(f"Error in MITRE enrichment: {e}")
        return data

    # 3. Ajouter la méthode validate_data() manquante
    def validate_data(self, data: Dict) -> bool:
    
     try:
        if not isinstance(data, dict):
            self.logger.warning("Data is not a dictionary")
            return False
            
        # Vérifier la présence d'un ID
        if not data.get("id"):
            self.logger.warning("Data missing required 'id' field")
            return False
            
        # Vérifier le type de données
        data_type = data.get("type", "").lower()
        valid_types = ["vulnerability", "indicator", "ioc", "cve"]
        
        # Accepter si le type est valide OU si l'ID contient des mots-clés valides
        if data_type in valid_types:
            return True
            
        # Vérification par mot-clé dans l'ID
        data_id = data.get("id", "").lower()
        if any(keyword in data_id for keyword in ["cve", "ioc"]):
            return True
            
        self.logger.warning(f"Data type '{data_type}' not supported and no valid keywords in ID")
        return False
        
     except Exception as e:
        self.logger.error(f"Error validating data: {e}")
        return False
    def _init_database(self):
        """Initialise la base de données MITRE ATT&CK locale"""
        try:
            # Créer le répertoire data dans le répertoire courant
            data_dir = Path("data")
            data_dir.mkdir(exist_ok=True)
            
            # Vérifier les permissions d'écriture
            if not os.access(data_dir, os.W_OK):
                self.logger.error(f"No write permission for {data_dir}")
                # Essayer un répertoire alternatif
                import tempfile
                temp_dir = Path(tempfile.gettempdir()) / "cti_project" / "data"
                temp_dir.mkdir(parents=True, exist_ok=True)
                self.db_path = str(temp_dir / "mitre_attack.db")
                self.logger.warning(f"Using temporary directory: {self.db_path}")
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Tables creation code remains the same...
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS techniques (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        tactic TEXT,
                        platforms TEXT,
                        kill_chain_phases TEXT,
                        parent_technique TEXT,
                        is_subtechnique BOOLEAN DEFAULT FALSE,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS groups (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        aliases TEXT,
                        description TEXT,
                        techniques TEXT,
                        software TEXT,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS cve_technique_mapping (
                        cve_id TEXT,
                        technique_id TEXT,
                        confidence REAL,
                        mapping_method TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (cve_id, technique_id)
                    )
                """)
                
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS ioc_technique_mapping (
                        ioc_hash TEXT,
                        technique_id TEXT,
                        confidence REAL,
                        mapping_method TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (ioc_hash, technique_id)
                    )
                """)
                
                conn.commit()
                self.logger.info(f"Database initialized at: {self.db_path}")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    
    def _ensure_default_config(self):
      defaults = {
        "update_frequency": "weekly",
        "frameworks": ["enterprise-attack"],
        "auto_mapping": True,
        "confidence_threshold": 0.7,
        "enable_subtechniques": True
     }
    
      for key, value in defaults.items():
        if key not in self.config:
            self.config[key] = value
            self.logger.info(f"Added default config value: {key} = {value}")
    
    async def update_mitre_data(self) -> bool:
      if not REQUESTS_AVAILABLE:
        self.logger.error("requests module not available, cannot update MITRE data")
        return False
        
      try:
        self.logger.info("Updating MITRE ATT&CK data...")
        frameworks = self.config.get("frameworks", ["enterprise-attack"])
        
        for framework in frameworks:
            success = await self._download_framework_data(framework)
            if not success:
                self.logger.warning(f"Failed to update framework: {framework}")
        
        self.logger.info("MITRE ATT&CK data updated successfully")
        return True
        
      except Exception as e:
        self.logger.error(f"Error updating MITRE data: {e}")
        return False
    
    async def _download_framework_data(self, framework: str) -> bool:
      if not REQUESTS_AVAILABLE:
        return False
        
      url = f"{self.base_url}/{framework}/{framework}.json"
    
      try:
        self.logger.info(f"Downloading {framework} from {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        # Traiter les techniques
        techniques_count = 0
        groups_count = 0
        
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                await self._store_technique(obj)
                techniques_count += 1
            elif obj.get("type") == "intrusion-set":
                await self._store_group(obj)
                groups_count += 1
        
        self.logger.info(f"Processed {techniques_count} techniques and {groups_count} groups for {framework}")
        return True
        
      except requests.exceptions.RequestException as e:
        self.logger.error(f"Network error downloading {framework}: {e}")
        return False
      except Exception as e:
        self.logger.error(f"Error processing {framework}: {e}")
        return False
    
    
    async def send_to_opencti(self, enriched_data: Dict) -> bool:
     try:
        # ❌ PROBLÈME : Import circulaire
        # from .opencti_mitre_connector import OpenCTIMitreConnector
        
        # ✅ SOLUTION : Import dynamique conditionnel
        try:
            import importlib
            opencti_module = importlib.import_module('pipeline.enrichers.opencti_mitre_connector')
            OpenCTIMitreConnector = opencti_module.OpenCTIMitreConnector
        except ImportError:
            self.logger.warning("OpenCTI connector not available")
            return False
        
        # Créer une instance du connecteur
        opencti_connector = OpenCTIMitreConnector("opencti_mitre_config.json")
        
        # Envoyer les données
        return await opencti_connector.sync_enriched_data_to_opencti(enriched_data)
        
     except Exception as e:
        self.logger.error(f"Error sending to OpenCTI: {e}")
        return False

# Modifier la méthode enrich pour inclure l'envoi vers OpenCTI
    
    
    async def _store_technique(self, technique_data: Dict):
        """Stocke une technique MITRE ATT&CK en base"""
        try:
            technique_id = technique_data.get("external_references", [{}])[0].get("external_id", "")
            name = technique_data.get("name", "")
            description = technique_data.get("description", "")
            
            # Extraire les tactiques
            tactics = []
            for phase in technique_data.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name"))
            
            # Déterminer si c'est une sous-technique
            is_subtechnique = "." in technique_id
            parent_technique = technique_id.split(".")[0] if is_subtechnique else None
            
            platforms = json.dumps(technique_data.get("x_mitre_platforms", []))
            kill_chain_phases = json.dumps(tactics)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO techniques 
                    (id, name, description, tactic, platforms, kill_chain_phases, 
                     parent_technique, is_subtechnique, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    technique_id, name, description, tactics[0] if tactics else "",
                    platforms, kill_chain_phases, parent_technique, is_subtechnique,
                    datetime.now()
                ))
                
        except Exception as e:
            self.logger.error(f"Error storing technique: {e}")
    
    async def _store_group(self, group_data: Dict):
     try:
        group_id = group_data.get("external_references", [{}])[0].get("external_id", "")
        name = group_data.get("name", "")
        aliases = json.dumps(group_data.get("aliases", []))
        description = group_data.get("description", "")
        
        # AJOUT : Extraire plus d'informations
        associated_techniques = []
        associated_software = []
        
        # Parser les relations si disponibles
        for ref in group_data.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                # Récupérer techniques et malwares associés depuis les relations
                pass
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO groups 
                (id, name, aliases, description, techniques, software, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (group_id, name, aliases, description, 
                  json.dumps(associated_techniques), 
                  json.dumps(associated_software), 
                  datetime.now()))
                
     except Exception as e:
            self.logger.error(f"Error storing group: {e}")
    
    
    # Ajouter cette méthode améliorée dans mitre_attack_enricher.py

    def map_cve_to_techniques_enhanced(self, cve_data: Dict) -> List[Tuple[str, float]]:
      mappings = []
    
      try:
        cve_description = cve_data.get("description", "").lower()
        cve_id = cve_data.get("id", "")
        cvss_score = cve_data.get("cvss_score", 0)
        
        # Mapping étendu avec plus de techniques
        enhanced_technique_keywords = {
            # Execution
            "T1059.001": ["powershell", "ps1", "invoke-", "iex", "downloadstring"],
            "T1059.003": ["cmd.exe", "command prompt", "batch", "bat", "shell"],
            "T1059.005": ["visual basic", "vbs", "vbscript", "wscript"],
            "T1059.007": ["javascript", "jscript", "js", "wsh"],
            
            # Persistence  
            "T1547.001": ["startup", "run key", "currentversion\\run"],
            "T1053.005": ["scheduled task", "schtasks", "at command"],
            "T1574.001": ["dll search order", "dll hijacking", "search order"],
            "T1574.002": ["dll side-loading", "side-loading"],
            
            # Privilege Escalation
            "T1055.001": ["dll injection", "process injection"],
            "T1055.012": ["process hollowing", "hollowing"],
            "T1134": ["access token", "token manipulation"],
            "T1068": ["privilege escalation", "elevation", "uac bypass"],
            
            # Defense Evasion
            "T1027.002": ["software packing", "packed", "upx", "packer"],
            "T1027.010": ["command obfuscation", "obfuscated"],
            "T1070.004": ["file deletion", "delete file", "remove file"],
            "T1112": ["registry modification", "reg add", "registry key"],
            "T1218.011": ["rundll32", "rundll32.exe"],
            "T1218.010": ["regsvr32", "regsvr32.exe"],
            
            # Credential Access
            "T1003.001": ["lsass", "mimikatz", "credential dumping"],
            "T1110": ["brute force", "password spray", "credential stuffing"],
            "T1555": ["password store", "credential store"],
            
            # Discovery
            "T1083": ["file discovery", "directory listing", "enumerate files"],
            "T1057": ["process discovery", "tasklist", "ps command"],
            "T1082": ["system information", "systeminfo", "uname"],
            "T1033": ["system owner", "whoami", "user discovery"],
            
            # Collection
            "T1005": ["data from local", "local data", "file collection"],
            "T1039": ["data from network", "network share"],
            "T1115": ["clipboard data", "clipboard"],
            
            # Command and Control
            "T1071.001": ["web protocols", "http", "https", "web traffic"],
            "T1571": ["non-standard port", "alternative port"],
            "T1090": ["proxy", "connection proxy"],
            
            # Exfiltration
            "T1041": ["exfiltration c2", "data exfiltration"],
            "T1052": ["exfiltration removable", "usb exfiltration"],
            
            # Impact
            "T1486": ["data encrypted", "ransomware", "encryption"],
            "T1489": ["service stop", "stop service"],
            "T1490": ["inhibit recovery", "delete backup"]
        }
        
        # Scoring avec poids ajustés selon CVSS
        cvss_multiplier = min(cvss_score / 10.0, 1.0) if cvss_score > 0 else 0.5
        
        for technique_id, keywords in enhanced_technique_keywords.items():
            score = 0
            matched_keywords = []
            
            for keyword in keywords:
                if keyword in cve_description:
                    score += 1
                    matched_keywords.append(keyword)
            
            if score > 0:
                # Calcul de confiance amélioré
                base_confidence = min(score / len(keywords), 1.0)
                # Bonus si plusieurs mots-clés matchent
                keyword_bonus = min(len(matched_keywords) * 0.1, 0.3)
                # Ajustement selon CVSS
                final_confidence = min((base_confidence + keyword_bonus) * cvss_multiplier, 1.0)
                
                if final_confidence >= self.config.get("confidence_threshold", 0.6):
                    mappings.append((technique_id, final_confidence))
                    
                    # Enrichir le stockage avec plus de métadonnées
                    self._store_cve_mapping_enhanced(
                        cve_id, technique_id, final_confidence, 
                        "enhanced_keyword", matched_keywords, cvss_score
                    )
        
        return sorted(mappings, key=lambda x: x[1], reverse=True)[:15]  # Top 15
        
      except Exception as e:
        self.logger.error(f"Error in enhanced CVE mapping: {e}")
        return []

    def _store_cve_mapping_enhanced(self, cve_id: str, technique_id: str, confidence: float, 
                               method: str, matched_keywords: List[str], cvss_score: float):
     try:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Créer table enrichie si elle n'existe pas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cve_technique_mapping_enhanced (
                    cve_id TEXT,
                    technique_id TEXT,
                    confidence REAL,
                    mapping_method TEXT,
                    matched_keywords TEXT,
                    cvss_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (cve_id, technique_id)
                )
            """)
            
            cursor.execute("""
                INSERT OR REPLACE INTO cve_technique_mapping_enhanced 
                (cve_id, technique_id, confidence, mapping_method, matched_keywords, cvss_score, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (cve_id, technique_id, confidence, method, 
                  json.dumps(matched_keywords), cvss_score, datetime.now()))
                  
     except Exception as e:
        self.logger.error(f"Error storing enhanced CVE mapping: {e}")

    def generate_mitre_report(self) -> Dict:
      try:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Techniques par tactique
            cursor.execute("""
                SELECT t.tactic, COUNT(DISTINCT t.id) as total_techniques,
                       COUNT(DISTINCT m.technique_id) as mapped_techniques
                FROM techniques t
                LEFT JOIN cve_technique_mapping m ON t.id = m.technique_id
                GROUP BY t.tactic
                ORDER BY mapped_techniques DESC
            """)
            
            tactics_coverage = []
            for row in cursor.fetchall():
                tactic, total, mapped = row
                coverage_pct = (mapped / total * 100) if total > 0 else 0
                tactics_coverage.append({
                    "tactic": tactic,
                    "total_techniques": total,
                    "mapped_techniques": mapped,
                    "coverage_percentage": round(coverage_pct, 2)
                })
            
            # Top CVE par nombre de techniques mappées
            cursor.execute("""
                SELECT cve_id, COUNT(*) as technique_count,
                       AVG(confidence) as avg_confidence
                FROM cve_technique_mapping
                GROUP BY cve_id
                ORDER BY technique_count DESC
                LIMIT 20
            """)
            
            top_cves = [
                {
                    "cve_id": row[0],
                    "technique_count": row[1],
                    "avg_confidence": round(row[2], 3)
                }
                for row in cursor.fetchall()
            ]
            
            return {
                "tactics_coverage": tactics_coverage,
                "top_cves": top_cves,
                "generated_at": datetime.now().isoformat()
            }
            
      except Exception as e:
        self.logger.error(f"Error generating MITRE report: {e}")
        return {}
    
    def map_cve_to_techniques(self, cve_data: Dict) -> List[Tuple[str, float]]:
    
      mappings = []
    
      try:
        cve_description = cve_data.get("description", "").lower()
        cve_id = cve_data.get("id", "")
        
        # Récupérer le seuil de confiance depuis la config, avec une valeur par défaut
        confidence_threshold = self.config.get("confidence_threshold", 0.7)
        
        # Mots-clés pour mapping automatique
        technique_keywords = {
            "T1059": ["command", "script", "execution", "powershell", "cmd", "bash"],
            "T1055": ["injection", "process", "dll", "memory"],
            "T1083": ["file", "discovery", "enumerate", "directory"],
            "T1070": ["log", "clear", "delete", "evidence", "cleanup"],
            "T1105": ["download", "upload", "transfer", "file"],
            "T1027": ["obfuscated", "encoded", "encrypted", "packed"],
            "T1057": ["process", "discovery", "list", "enumerate"],
            "T1082": ["system", "information", "discovery", "version"],
            "T1053": ["scheduled", "task", "cron", "job"],
            "T1112": ["registry", "modify", "key", "value"],
            "T1071": ["application", "layer", "protocol", "http", "https"],
            "T1090": ["proxy", "connection", "redirect"],
            "T1036": ["masquerading", "disguise", "legitimate"],
            "T1140": ["deobfuscate", "decode", "decrypt"],
            "T1074": ["data", "staged", "collection"]
        }
        
        # Scoring basé sur les mots-clés
        for technique_id, keywords in technique_keywords.items():
            score = 0
            for keyword in keywords:
                if keyword in cve_description:
                    score += 1
            
            if score > 0:
                confidence = min(score / len(keywords), 1.0)
                if confidence >= confidence_threshold:
                    mappings.append((technique_id, confidence))
                    
                    # Stocker le mapping
                    self._store_cve_mapping(cve_id, technique_id, confidence, "keyword_based")
        
        return sorted(mappings, key=lambda x: x[1], reverse=True)
        
      except Exception as e:
        self.logger.error(f"Error mapping CVE {cve_data.get('id')}: {e}")
        return []

    
    def map_ioc_to_techniques(self, ioc_data: Dict) -> List[Tuple[str, float]]:
        """Mappe automatiquement un IOC aux techniques MITRE ATT&CK"""
        mappings = []
        
        try:
            ioc_type = ioc_data.get("type", "").lower()
            ioc_value = ioc_data.get("value", "").lower()
            ioc_hash = ioc_data.get("hash", "")
            
            # Mapping basé sur le type d'IOC
            type_mappings = {
                "domain": [("T1071.001", 0.8), ("T1090", 0.6)],  # Web protocols, Proxy
                "ip": [("T1071.001", 0.7), ("T1090", 0.7)],      # Web protocols, Proxy
                "url": [("T1071.001", 0.9), ("T1105", 0.7)],     # Web protocols, Ingress transfer
                "email": [("T1071.003", 0.8), ("T1566", 0.9)],   # Mail protocols, Phishing
                "file_hash": [("T1105", 0.7), ("T1027", 0.6)],   # File transfer, Obfuscation
                "registry": [("T1112", 0.9), ("T1547", 0.7)],    # Registry, Boot autostart
                "mutex": [("T1055", 0.8), ("T1106", 0.6)],       # Process injection, Native API
                "service": [("T1543", 0.8), ("T1569", 0.7)]      # Create service, System services
            }
            
            if ioc_type in type_mappings:
                for technique_id, confidence in type_mappings[ioc_type]:
                    mappings.append((technique_id, confidence))
                    self._store_ioc_mapping(ioc_hash, technique_id, confidence, "type_based")
            
            # Mapping basé sur des patterns dans la valeur
            if "powershell" in ioc_value or ".ps1" in ioc_value:
                mappings.append(("T1059.001", 0.9))  # PowerShell
            if "cmd.exe" in ioc_value or ".bat" in ioc_value:
                mappings.append(("T1059.003", 0.9))  # Windows Command Shell
            if "rundll32" in ioc_value:
                mappings.append(("T1218.011", 0.8))  # Rundll32
            if "regsvr32" in ioc_value:
                mappings.append(("T1218.010", 0.8))  # Regsvr32
                
            return list(set(mappings))  # Supprimer les doublons
            
        except Exception as e:
            self.logger.error(f"Error mapping IOC: {e}")
            return []
    
    def _store_cve_mapping(self, cve_id: str, technique_id: str, confidence: float, method: str):
        """Stocke un mapping CVE -> Technique"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO cve_technique_mapping 
                    (cve_id, technique_id, confidence, mapping_method, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (cve_id, technique_id, confidence, method, datetime.now()))
        except Exception as e:
            self.logger.error(f"Error storing CVE mapping: {e}")
    
    def _store_ioc_mapping(self, ioc_hash: str, technique_id: str, confidence: float, method: str):
        """Stocke un mapping IOC -> Technique"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO ioc_technique_mapping 
                    (ioc_hash, technique_id, confidence, mapping_method, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (ioc_hash, technique_id, confidence, method, datetime.now()))
        except Exception as e:
            self.logger.error(f"Error storing IOC mapping: {e}")
    
    def get_technique_details(self, technique_id: str) -> Optional[AttackTechnique]:
        """Récupère les détails d'une technique MITRE ATT&CK"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, name, description, tactic, platforms, kill_chain_phases
                    FROM techniques WHERE id = ?
                """, (technique_id,))
                
                row = cursor.fetchone()
                if row:
                    return AttackTechnique(
                        technique_id=row[0],
                        name=row[1],
                        description=row[2],
                        tactic=row[3],
                        subtechniques=[],
                        platforms=json.loads(row[4]) if row[4] else [],
                        kill_chain_phases=json.loads(row[5]) if row[5] else [],
                        references=[]
                    )
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting technique details: {e}")
            return None
    
    async def enrich_mitre_relationships(self):
      if not REQUESTS_AVAILABLE:
        self.logger.warning("Cannot enrich relationships without requests module")
        return False
    
      try:
        # Télécharger le fichier des relations
        relationship_url = f"{self.base_url}/enterprise-attack/relationship/enterprise-attack.json"
        response = requests.get(relationship_url, timeout=30)
        response.raise_for_status()
        
        relationships_data = response.json()
        
        # Parser les relations group -> technique
        for obj in relationships_data.get("objects", []):
            if obj.get("type") == "relationship":
                source_ref = obj.get("source_ref", "")
                target_ref = obj.get("target_ref", "")
                relationship_type = obj.get("relationship_type", "")
                
                if relationship_type == "uses":
                    await self._store_relationship(source_ref, target_ref, relationship_type)
        
        self.logger.info("✅ MITRE relationships enriched successfully")
        return True
        
      except Exception as e:
        self.logger.error(f"Error enriching MITRE relationships: {e}")
        return False

    async def _store_relationship(self, source_ref: str, target_ref: str, relationship_type: str):
     try:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Créer table des relations si elle n'existe pas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS mitre_relationships (
                    source_ref TEXT,
                    target_ref TEXT,
                    relationship_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (source_ref, target_ref, relationship_type)
                )
            """)
            
            cursor.execute("""
                INSERT OR IGNORE INTO mitre_relationships 
                (source_ref, target_ref, relationship_type)
                VALUES (?, ?, ?)
            """, (source_ref, target_ref, relationship_type))
            
     except Exception as e:
        self.logger.error(f"Error storing relationship: {e}")
    
    def get_attack_statistics(self) -> Dict:
        """Génère des statistiques pour le dashboard SOC"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Techniques les plus mappées
                cursor.execute("""
                    SELECT technique_id, COUNT(*) as count 
                    FROM (
                        SELECT technique_id FROM cve_technique_mapping
                        UNION ALL
                        SELECT technique_id FROM ioc_technique_mapping
                    ) 
                    GROUP BY technique_id 
                    ORDER BY count DESC 
                    LIMIT 20
                """)
                top_techniques = cursor.fetchall()
                
                # Répartition par tactique
                cursor.execute("""
                    SELECT t.tactic, COUNT(*) as count
                    FROM techniques t
                    JOIN (
                        SELECT technique_id FROM cve_technique_mapping
                        UNION ALL
                        SELECT technique_id FROM ioc_technique_mapping
                    ) m ON t.id = m.technique_id
                    GROUP BY t.tactic
                    ORDER BY count DESC
                """)
                tactics_distribution = cursor.fetchall()
                
                # Score de couverture ATT&CK
                cursor.execute("SELECT COUNT(*) FROM techniques")
                total_techniques = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(DISTINCT technique_id) FROM (
                        SELECT technique_id FROM cve_technique_mapping
                        UNION
                        SELECT technique_id FROM ioc_technique_mapping
                    )
                """)
                covered_techniques = cursor.fetchone()[0]
                
                coverage_score = (covered_techniques / total_techniques) * 100 if total_techniques > 0 else 0
                
                return {
                    "top_techniques": [{"technique": t[0], "count": t[1]} for t in top_techniques],
                    "tactics_distribution": [{"tactic": t[0], "count": t[1]} for t in tactics_distribution],
                    "coverage_score": round(coverage_score, 2),
                    "total_techniques": total_techniques,
                    "covered_techniques": covered_techniques
                }
                
        except Exception as e:
            self.logger.error(f"Error generating statistics: {e}")
            return {}

# Exemple d'utilisation
if __name__ == "__main__":
    import asyncio
    
    async def main():
        enricher = MitreAttackEnricher()
        
        # Mettre à jour les données MITRE
        await enricher.update_mitre_data()
        
        # Exemple de mapping CVE
        cve_example = {
            "id": "CVE-2023-1234",
            "description": "Remote code execution vulnerability allowing command injection through PowerShell"
        }
        
        mappings = enricher.map_cve_to_techniques(cve_example)
        print(f"CVE mappings: {mappings}")
        
        # Statistiques
        stats = enricher.get_attack_statistics()
        print(f"Attack statistics: {stats}")
    
    asyncio.run(main())