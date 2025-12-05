# pipeline/enrichers/opencti_mitre_connector.py

# En haut du fichier opencti_mitre_connector.py :
import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
import sqlite3
# Gestion conditionnelle de l'import pycti
try:
    from pycti import OpenCTIApiClient
    PYCTI_AVAILABLE = True
except ImportError:
    PYCTI_AVAILABLE = False
    OpenCTIApiClient = None
    logging.getLogger(__name__).warning("pycti module not available, OpenCTI connector will be disabled")

from .mitre_attack_enricher import MitreAttackEnricher
from .base_enricher import BaseEnricher

def check_dependencies():
    """Vérifie les dépendances et affiche les modules manquants"""
    missing_modules = []
    
    try:
        import requests
    except ImportError:
        missing_modules.append("requests")
    
    try:
        from pycti import OpenCTIApiClient
    except ImportError:
        missing_modules.append("pycti")
    
    if missing_modules:
        print(f"⚠️ Missing optional modules: {', '.join(missing_modules)}")
        print("Some features may be disabled. Install with:")
        for module in missing_modules:
            if module == "pycti":
                print(f"   pip install pycti")
            else:
                print(f"   pip install {module}")
        print()
    
    return missing_modules



class OpenCTIMitreConnector(BaseEnricher):
    """Connecteur pour synchroniser MITRE ATT&CK avec OpenCTI"""
    
    
    
    def __init__(self, config_path: str = "opencti_mitre_config.json"):  # Nouveau nom
     super().__init__(config_path)
     self.logger = logging.getLogger(__name__)
     self.opencti_client = None
     self.mitre_enricher = None
     self.force_update = True  # ✅ NOUVEAU: Force la mise à jour
    
    # Initialiser l'enrichisseur MITRE en premier
     try:
        self.mitre_enricher = MitreAttackEnricher()
        self.logger.info("MITRE enricher initialized successfully")
     except Exception as e:
        self.logger.error(f"Failed to initialize MITRE enricher: {e}")
        raise
    
    # Charger la configuration OpenCTI
     self.opencti_config = self._load_opencti_config(config_path)
    
    # Initialiser OpenCTI seulement si activé et pycti disponible
     if PYCTI_AVAILABLE and self.opencti_config.get("enabled", True):
        self._init_opencti_client()
     else:
        if not PYCTI_AVAILABLE:
            self.logger.warning("pycti module not available, OpenCTI features disabled")
        else:
            self.logger.info("OpenCTI connector disabled by configuration")

    # Dans opencti_mitre_connector.py, remplacer la méthode _init_opencti_client :

    def _init_opencti_client(self):
     try:
        self.logger.info(f"Connecting to OpenCTI at {self.opencti_config.get('url')}")
        
        
        # ✅ SOLUTION : Créer le client avec seulement les paramètres supportés
        self.opencti_client = OpenCTIApiClient(
            url=self.opencti_config.get("url"),
            token=self.opencti_config.get("token"),
            log_level=self.opencti_config.get("log_level", "info")
        )
        
        # Test de connexion avec retry manuel
        max_retries = 3
        retry_delay = 5  # secondes
        
        for attempt in range(max_retries):
            self.logger.info(f"Connection attempt {attempt + 1}/{max_retries}")
            
            if self._test_opencti_connection():
                self.logger.info("✅ OpenCTI client connected successfully")
                return
            
            if attempt < max_retries - 1:
                self.logger.warning(f"Connection failed, retrying in {retry_delay}s...")
                import time
                time.sleep(retry_delay)
        
        # Si tous les tests échouent
        self.logger.error("❌ Failed to connect to OpenCTI after all retries")
        self.opencti_client = None
            
     except Exception as e:
        self.logger.error(f"❌ Failed to initialize OpenCTI client: {e}")
        self.opencti_client = None

    # Dans opencti_mitre_connector.py, remplacer la méthode test_connection :

    def _test_opencti_connection(self) -> bool:
     if not self.opencti_client:
        return False
    
     try:
        # Test avec plus de détails
        result = self.opencti_client.query("query { about { version } }")
        
        if result and isinstance(result, dict):
            version_info = result.get('data', {}).get('about', {})
            self.logger.info(f"✅ OpenCTI connection successful - Version: {version_info.get('version', 'unknown')}")
            return True
        else:
            self.logger.warning(f"❌ Unexpected response format: {type(result)} - {result}")
            return False
            
     except Exception as e:
        self.logger.debug(f"Connection test failed with details: {str(e)}")
        return False
    
    def test_connection(self) -> bool:
     if not self.opencti_client:
        self.logger.warning("OpenCTI client not initialized")
        return False
    
     try:
        # Test simple avec la requête about
        result = self.opencti_client.query("query { about { version } }")
        
        if result and isinstance(result, dict):
            self.logger.info("✅ OpenCTI connection test successful")
            return True
        else:
            self.logger.warning(f"❌ Unexpected response format: {type(result)}")
            return False
            
     except Exception as e:
        self.logger.error(f"❌ Connection test failed: {e}")
        return False
    
    async def sync_techniques_to_opencti(self) -> bool:
      if not self.is_opencti_available():
        return False
    
      try:
        import sqlite3
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, description, tactic, platforms FROM techniques")
            techniques = cursor.fetchall()
            
            for technique in techniques:
                technique_id, name, description, tactic, platforms = technique
                
                # Créer l'Attack Pattern dans OpenCTI
                try:
                    attack_pattern = self.opencti_client.attack_pattern.create(
                        name=f"{technique_id} - {name}",
                        description=description,
                        x_mitre_id=technique_id,
                        x_mitre_platforms=json.loads(platforms) if platforms else [],
                        confidence=self.opencti_config.get("confidence_level", 3)
                    )
                    self.logger.debug(f"Created attack pattern: {technique_id}")
                except Exception as e:
                    if "already exists" in str(e).lower():
                        self.logger.debug(f"Attack pattern {technique_id} already exists")
                    else:
                        self.logger.error(f"Failed to create attack pattern {technique_id}: {e}")
        
        return True
      except Exception as e:
        self.logger.error(f"Error syncing techniques: {e}")
        return False

    async def sync_enriched_data_to_opencti(self, enriched_data: Dict) -> bool:
      if not self.is_opencti_available():
        return False
    
      try:
        data_type = enriched_data.get("type", "").lower()
        mitre_data = enriched_data.get("mitre_attack", {})
        
        if not mitre_data:
            return True  # Pas de données MITRE à synchroniser
        
        if data_type == "vulnerability":
            return await self._sync_vulnerability_to_opencti(enriched_data)
        elif data_type in ["indicator", "ioc"]:
            return await self._sync_indicator_to_opencti(enriched_data)
        
        return True
      except Exception as e:
        self.logger.error(f"Error syncing enriched data: {e}")
        return False

    async def _sync_vulnerability_to_opencti(self, cve_data: Dict) -> bool:
     try:
        # Créer la vulnérabilité
        vulnerability = self._create_or_get_vulnerability(cve_data)
        if not vulnerability:
            return False
        
        # Créer les relations avec les techniques MITRE
        mitre_techniques = cve_data.get("mitre_attack", {}).get("techniques", [])
        for technique in mitre_techniques:
            technique_id = technique.get("technique_id")
            confidence = technique.get("confidence", 0.5)
            
            # Trouver l'Attack Pattern dans OpenCTI
            attack_pattern = self._find_attack_pattern_by_mitre_id(technique_id)
            if attack_pattern:
                self._create_vulnerability_technique_relation(
                    vulnerability["id"], 
                    attack_pattern["id"], 
                    confidence
                )
        
        return True
     except Exception as e:
        self.logger.error(f"Error syncing vulnerability: {e}")
        return False

    def _create_vulnerability_technique_relation(self, vuln_id: str, technique_id: str, confidence: float):
     try:
        
        # ✅ NOUVEAU (correct)
        self.opencti_client.stix_core_relationship.create(
            fromId=vuln_id,
            toId=technique_id,
            relationship_type="related-to",
            confidence=int(confidence * 100),
            description=f"Vulnerability exploits MITRE ATT&CK technique"
        )
     except Exception as e:
        if "already exists" not in str(e).lower():
            self.logger.error(f"Failed to create relation: {e}")
    
    async def enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
     try:
        # Si OpenCTI n'est pas disponible, utiliser seulement MITRE local
        if not self.opencti_client or not self.test_connection():
            self.logger.info("Using local MITRE enrichment (OpenCTI unavailable)")
            return await self.mitre_enricher.enrich(data)
        
        # Enrichissement OpenCTI normal
        data_type = data.get("type", "").lower()
        
        if data_type == "vulnerability" or "cve" in data.get("id", "").lower():
            return await self.enrich_cve_with_mitre(data)
        elif data_type == "indicator" or data_type == "ioc":
            return await self.enrich_ioc_with_mitre(data)
        else:
            return data
            
     except Exception as e:
        self.logger.error(f"Error in OpenCTI-MITRE enrichment: {e}")
        # Fallback vers enrichissement local
        return await self.mitre_enricher.enrich(data)

    def validate_data(self, data: Dict) -> bool:
     try:
        # Vérifications de base
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
            
        self.logger.warning(f"Data type '{data_type}' not supported for OpenCTI-MITRE enrichment")
        return False
        
     except Exception as e:
        self.logger.error(f"Error validating data for OpenCTI enrichment: {e}")
        return False
    
    def _load_opencti_config(self, config_path: str) -> Dict:
     default_config = {
    "url": os.getenv("OPENCTI_URL", "http://opencti:8080"),
    "token": os.getenv("OPENCTI_TOKEN", "dd817c8c-3123-4b18-a3b6-24f4d0ef8f90"),
    "log_level": os.getenv("OPENCTI_LOG_LEVEL", "info"),
    "confidence_level": int(os.getenv("OPENCTI_CONFIDENCE", "3")),
    "update_existing_data": True,  # ✅ MODIFIER : Désactiver par défaut
    "force_refresh": False,         # ✅ MODIFIER : Désactiver par défaut
     "smart_update": True,
    "cleanup_before_sync": False,   # ✅ NOUVEAU : Option de nettoyage
    "batch_size": 50,              # ✅ NOUVEAU : Taille des lots
    "enabled": os.getenv("OPENCTI_ENABLED", "true").lower() == "true"
}
    
     try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                file_config = json.load(f)
            
            # Fusionner correctement la configuration OpenCTI du fichier
            if "opencti" in file_config:
                opencti_config = file_config["opencti"]
                merged_config = {**default_config, **opencti_config}
                self.logger.info(f"Loaded OpenCTI config from {config_path}")
                return merged_config
            else:
                self.logger.warning("No 'opencti' section in config file")
                return default_config
        else:
            self.logger.info("Using OpenCTI config from environment variables")
            return default_config
     except Exception as e:
        self.logger.warning(f"Error loading config file, using defaults: {e}")
        return default_config

    async def enrich(self, data: Dict[str, Any]) -> Dict[str, Any]:
     try:
        # Validation des données
        if not self.validate_data(data):
            self.logger.warning("Data validation failed, returning original data")
            return data
        
        # Si OpenCTI n'est pas disponible, utiliser seulement MITRE local
        if not self.is_opencti_available():
            self.logger.info("OpenCTI unavailable, using local MITRE enrichment only")
            if self.mitre_enricher:
                return await self.mitre_enricher.enrich(data)
            else:
                self.logger.warning("No enricher available")
                return data
        
        # Enrichissement OpenCTI + MITRE
        data_type = data.get("type", "").lower()
        
        if data_type == "vulnerability" or "cve" in data.get("id", "").lower():
            return await self.enrich_cve_with_mitre(data)
        elif data_type == "indicator" or data_type == "ioc":
            return await self.enrich_ioc_with_mitre(data)
        else:
            # Type non supporté pour OpenCTI, utiliser MITRE local
            if self.mitre_enricher:
                return await self.mitre_enricher.enrich(data)
            else:
                return data
                
     except Exception as e:
        self.logger.error(f"Error in OpenCTI-MITRE enrichment: {e}")
        # Fallback vers enrichissement local en cas d'erreur
        try:
            if self.mitre_enricher:
                return await self.mitre_enricher.enrich(data)
            else:
                return data
        except Exception as fallback_error:
            self.logger.error(f"Fallback enrichment also failed: {fallback_error}")
            return data
    

    def test_connection(self) -> bool:
     if not self.opencti_client:
        return False
    
     try:
        # Essayer plusieurs méthodes de test
        health = self.opencti_client.health_check()
        if isinstance(health, bool):
            return health
        elif isinstance(health, dict):
            return True
        else:
            # Fallback : tester avec get_settings
            result = self.opencti_client.query("query { about { version } }")
            return result is not None and isinstance(result, dict)
     except Exception as e:
        self.logger.debug(f"Connection test failed: {e}")
        return False

    def is_opencti_available(self) -> bool:
     if not PYCTI_AVAILABLE or not self.opencti_client:
        return False
    
     return self.test_connection()
      
    async def sync_mitre_to_opencti(self) -> bool:
     if not PYCTI_AVAILABLE or not self.opencti_client:
        self.logger.error("OpenCTI not available, cannot sync")
        return False
         
     try:
        self.logger.info("🔄 Starting MITRE ATT&CK sync to OpenCTI...")
        
        # Test de connectivité
        if not self.test_connection():
            self.logger.error("Cannot connect to OpenCTI")
            return False
        
        # ✅ CORRECTION 6: Vérifier la configuration avant sync
        force_refresh = self.opencti_config.get("force_refresh", False)
        smart_update = self.opencti_config.get("smart_update", True)
        
        self.logger.info(f"🔧 Sync mode: force_refresh={force_refresh}, smart_update={smart_update}")
        
        # Nettoyage conditionnel SEULEMENT si force_refresh=True
        if force_refresh:
            self.logger.info("🗑️ Force refresh enabled, cleaning existing data...")
            await self._cleanup_existing_mitre_data()
        else:
            self.logger.info("⏭️ Using smart update mode (no cleanup)")
        
        # Compteurs globaux
        total_stats = {
            "attack_patterns_created": 0,
            "attack_patterns_updated": 0,
            "attack_patterns_skipped": 0,
            "intrusion_sets_created": 0,
            "intrusion_sets_updated": 0,
            "intrusion_sets_skipped": 0,
            "relations_created": 0,
            "total_errors": 0
        }
        
        # 1. Synchroniser Attack Patterns avec la nouvelle logique
        self.logger.info("📊 Syncing attack patterns with smart update...")
        pattern_stats = await self._sync_attack_patterns_with_update_stats()
        
        # Mettre à jour les stats globales
        for key in ["attack_patterns_created", "attack_patterns_updated", "attack_patterns_skipped"]:
            total_stats[key] = pattern_stats.get(key, 0)
        
        # 2. Synchroniser Intrusion Sets
        self.logger.info("👥 Syncing intrusion sets...")
        group_stats = await self._sync_intrusion_sets_with_update_stats()
        
        for key in ["intrusion_sets_created", "intrusion_sets_updated", "intrusion_sets_skipped"]:
            total_stats[key] = group_stats.get(key, 0)
        
        # 3. Synchroniser les relations
        self.logger.info("🔗 Syncing relationships...")
        relation_stats = await self._sync_relationships_with_update_stats()
        total_stats["relations_created"] = relation_stats.get("relations_created", 0)
        
        # Rapport final détaillé
        self.logger.info("=" * 50)
        self.logger.info("📋 MITRE ATT&CK Sync Summary:")
        self.logger.info(f"   📊 Attack Patterns:")
        self.logger.info(f"      ✨ Created: {total_stats['attack_patterns_created']}")
        self.logger.info(f"      📝 Updated: {total_stats['attack_patterns_updated']}")
        self.logger.info(f"      ⏭️ Skipped: {total_stats['attack_patterns_skipped']}")
        self.logger.info(f"   👥 Intrusion Sets:")
        self.logger.info(f"      ✨ Created: {total_stats['intrusion_sets_created']}")
        self.logger.info(f"      📝 Updated: {total_stats['intrusion_sets_updated']}")
        self.logger.info(f"      ⏭️ Skipped: {total_stats['intrusion_sets_skipped']}")
        self.logger.info(f"   🔗 Relations: {total_stats['relations_created']} created")
        self.logger.info(f"   ❌ Total Errors: {total_stats['total_errors']}")
        self.logger.info("=" * 50)
        
        # Déterminer le succès
        total_processed = (total_stats['attack_patterns_created'] + 
                          total_stats['attack_patterns_updated'] + 
                          total_stats['attack_patterns_skipped'])
        
        success = total_processed > 0 and total_stats['total_errors'] < 50
        
        if success:
            self.logger.info("✅ MITRE sync completed successfully")
        else:
            self.logger.warning(f"⚠️ MITRE sync completed with issues")
        
        return success
        
     except Exception as e:
        self.logger.error(f"Error in sync: {e}")
        return False

# ✅ NOUVELLE MÉTHODE : Version avec statistiques détaillées
    async def _sync_attack_patterns_with_update_stats(self) -> dict:
     import sqlite3
    
     stats = {"attack_patterns_created": 0, "attack_patterns_updated": 0, "attack_patterns_skipped": 0}
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, name, description, tactic, platforms, kill_chain_phases,
                       parent_technique, is_subtechnique, last_updated
                FROM techniques
                ORDER BY id
            """)
            
            techniques = cursor.fetchall()
            self.logger.info(f"🔄 Processing {len(techniques)} techniques...")
            
            for i, technique in enumerate(techniques):
                tech_id, name, desc, tactic, platforms, kcp, parent, is_sub, updated = technique
                
                try:
                    # ✅ CORRECTION 1: Vérifier d'abord si la technique existe vraiment
                    existing = self.opencti_client.attack_pattern.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "mode": "or",
                                    "operator": "eq",
                                    "values": [tech_id]
                                }
                            ],
                            "filterGroups": []
                        }
                    )
                    
                    attack_pattern_data = self._prepare_enhanced_attack_pattern_data(
                        tech_id, name, desc, tactic, platforms, kcp, parent, is_sub
                    )
                    
                    # ✅ CORRECTION 2: Logique améliorée pour force_refresh
                    if existing and len(existing) > 0:
                        force_refresh = self.opencti_config.get("force_refresh", False)
                        
                        if force_refresh:
                            # Supprimer et recréer
                            try:
                                self.opencti_client.attack_pattern.delete(id=existing[0]["id"])
                                self.logger.debug(f"🗑️ Deleted existing: {tech_id}")
                                
                                attack_pattern = self.opencti_client.attack_pattern.create(**attack_pattern_data)
                                stats["attack_patterns_updated"] += 1
                                self.logger.debug(f"✅ RECREATED: {tech_id}")
                                
                            except Exception as e:
                                self.logger.warning(f"Cannot recreate {tech_id}: {e}")
                                attack_pattern = existing[0]
                                stats["attack_patterns_skipped"] += 1
                        else:
                            # ✅ CORRECTION 3: Vérifier si mise à jour nécessaire
                            needs_update = self._check_if_technique_needs_update(existing[0], attack_pattern_data)
                            
                            if needs_update:
                                try:
                                    # Mettre à jour les champs modifiables
                                    updated_pattern = self.opencti_client.attack_pattern.update(
                                        id=existing[0]["id"],
                                        **self._get_updatable_fields(attack_pattern_data)
                                    )
                                    stats["attack_patterns_updated"] += 1
                                    self.logger.debug(f"📝 UPDATED: {tech_id}")
                                except Exception as e:
                                    self.logger.debug(f"Update failed for {tech_id}: {e}")
                                    stats["attack_patterns_skipped"] += 1
                            else:
                                stats["attack_patterns_skipped"] += 1
                                self.logger.debug(f"⏭️ UNCHANGED: {tech_id}")
                    else:
                        # ✅ CORRECTION 4: Créer nouvelle technique
                        try:
                            attack_pattern = self.opencti_client.attack_pattern.create(**attack_pattern_data)
                            stats["attack_patterns_created"] += 1
                            self.logger.debug(f"✨ CREATED: {tech_id}")
                        except Exception as e:
                            self.logger.error(f"Creation failed for {tech_id}: {e}")
                            continue
                    
                    # Progress logging amélioré
                    if (i + 1) % 100 == 0:
                        self.logger.info(f"Progress: {i + 1}/{len(techniques)} - "
                                       f"Created: {stats['attack_patterns_created']}, "
                                       f"Updated: {stats['attack_patterns_updated']}, "
                                       f"Skipped: {stats['attack_patterns_skipped']}")
                    
                except Exception as e:
                    self.logger.error(f"Error processing {tech_id}: {e}")
                    continue
            
            self.logger.info(f"✅ Attack patterns final: {stats['attack_patterns_created']} created, "
                           f"{stats['attack_patterns_updated']} updated, "
                           f"{stats['attack_patterns_skipped']} skipped")
                    
     except Exception as e:
        self.logger.error(f"Error in attack patterns sync: {e}")
    
     return stats
    

    def _check_if_technique_needs_update(self, existing_pattern: Dict, new_data: Dict) -> bool:
     try:
        # Champs à comparer
        fields_to_check = [
            'name', 'description', 'x_mitre_platforms', 
            'kill_chain_phases', 'x_mitre_is_subtechnique'
        ]
        
        for field in fields_to_check:
            existing_value = existing_pattern.get(field)
            new_value = new_data.get(field)
            
            # Comparaison spéciale pour les listes
            if isinstance(new_value, list) and isinstance(existing_value, list):
                if set(str(x) for x in new_value) != set(str(x) for x in existing_value):
                    self.logger.debug(f"Field {field} differs: {existing_value} vs {new_value}")
                    return True
            elif existing_value != new_value:
                self.logger.debug(f"Field {field} differs: {existing_value} vs {new_value}")
                return True
        
        return False
        
     except Exception as e:
        self.logger.debug(f"Error checking update need: {e}")
        return False

    def _get_updatable_fields(self, attack_pattern_data: Dict) -> Dict:
     updatable_fields = [
        'description', 'confidence', 'x_mitre_platforms', 
        'kill_chain_phases', 'x_opencti_score'
    ]
    
     return {
        key: value for key, value in attack_pattern_data.items() 
        if key in updatable_fields
    }

# ✅ NOUVELLE MÉTHODE : Version avec statistiques pour intrusion sets
    async def _sync_intrusion_sets_with_update_stats(self) -> dict:
     import sqlite3
    
     stats = {"intrusion_sets_created": 0, "intrusion_sets_updated": 0, "intrusion_sets_skipped": 0}
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, aliases, description, techniques, software
                FROM groups
                ORDER BY id
            """)
            
            groups = cursor.fetchall()
            self.logger.info(f"🔄 Processing {len(groups)} intrusion sets...")
            
            for i, group in enumerate(groups):
                group_id, name, aliases, description, techniques, software = group
                
                try:
                    existing = self.opencti_client.intrusion_set.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "mode": "or",
                                    "operator": "eq",
                                    "values": [group_id]
                                }
                            ],
                            "filterGroups": []
                        }
                    )
                    
                    intrusion_set_data = {
                        "name": name,
                        "description": description or f"MITRE ATT&CK group {group_id}",
                        "aliases": json.loads(aliases) if aliases else [],
                        "x_mitre_id": group_id,
                        "confidence": self.opencti_config.get("confidence_level", 3)
                    }
                    
                    if existing and len(existing) > 0:
                        intrusion_set = existing[0]
                        stats["intrusion_sets_skipped"] += 1
                        
                        if self.opencti_config.get("force_refresh", False):
                            try:
                                self.opencti_client.intrusion_set.delete(id=existing[0]["id"])
                                intrusion_set = self.opencti_client.intrusion_set.create(**intrusion_set_data)
                                stats["intrusion_sets_updated"] += 1
                                stats["intrusion_sets_skipped"] -= 1
                            except Exception:
                                pass
                    else:
                        intrusion_set = self.opencti_client.intrusion_set.create(**intrusion_set_data)
                        stats["intrusion_sets_created"] += 1
                    
                    # Progress logging
                    if (i + 1) % 50 == 0:
                        self.logger.info(f"Progress: {i + 1}/{len(groups)} - "
                                       f"Created: {stats['intrusion_sets_created']}, "
                                       f"Skipped: {stats['intrusion_sets_skipped']}")
                    
                except Exception as e:
                    self.logger.debug(f"Error processing group {group_id}: {e}")
                    continue
            
            self.logger.info(f"✅ Intrusion sets final: {stats['intrusion_sets_created']} created, "
                           f"{stats['intrusion_sets_skipped']} skipped, "
                           f"{stats['intrusion_sets_updated']} updated")
                    
     except Exception as e:
        self.logger.error(f"Error in intrusion sets sync: {e}")
    
     return stats

# ✅ NOUVELLE MÉTHODE : Version avec statistiques pour relations
    async def _sync_relationships_with_update_stats(self) -> dict:
     stats = {"relations_created": 0}
    
     try:
        self.logger.info("🔗 Starting relationships sync...")
        
        # Relations parent-enfant (limitées)
        parent_child_count = await self._sync_parent_subtechnique_relations_limited()
        stats["relations_created"] += parent_child_count
        
        # Relations groupe-technique (limitées)
        group_tech_count = await self._sync_group_technique_relations_limited()
        stats["relations_created"] += group_tech_count
        
        self.logger.info(f"✅ Relationships final: {stats['relations_created']} total created")
        
     except Exception as e:
        self.logger.error(f"Error syncing relationships: {e}")
    
     return stats

    async def _sync_parent_subtechnique_relations_limited(self) -> int:
     import sqlite3
    
     created_count = 0
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT parent.id as parent_id, child.id as child_id
                FROM techniques parent
                JOIN techniques child ON child.parent_technique = parent.id
                WHERE parent.is_subtechnique = FALSE 
                AND child.is_subtechnique = TRUE
                LIMIT 50
            """)
            
            relations = cursor.fetchall()
            
            for parent_id, child_id in relations:
                try:
                    parent_ap = self._find_attack_pattern_by_mitre_id(parent_id)
                    child_ap = self._find_attack_pattern_by_mitre_id(child_id)
                    
                    if parent_ap and child_ap:
                        # ✅ CORRECTION : Structure corrigée
                        existing = self.opencti_client.stix_core_relationship.list(
                            filters={
                                "mode": "and",
                                "filters": [
                                    {"key": "fromId", "mode": "or", "operator": "eq", "values": [child_ap["id"]]},
                                    {"key": "toId", "mode": "or", "operator": "eq", "values": [parent_ap["id"]]},
                                    {"key": "relationship_type", "mode": "or", "operator": "eq", "values": ["subtechnique-of"]}
                                ],
                                "filterGroups": []
                            }
                        )
                        
                        if not existing or len(existing) == 0:
                            self.opencti_client.stix_core_relationship.create(
                                fromId=child_ap["id"],
                                toId=parent_ap["id"],
                                relationship_type="subtechnique-of",
                                description=f"{child_id} is a subtechnique of {parent_id}",
                                confidence=90
                            )
                            created_count += 1
                            
                except Exception:
                    continue
                    
     except Exception as e:
        self.logger.warning(f"Error in parent-child relations: {e}")
    
     return created_count
    
    
    async def _sync_group_technique_relations_limited(self) -> int:
     import sqlite3
    
     created_count = 0
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, techniques 
                FROM groups 
                WHERE techniques IS NOT NULL AND techniques != '[]'
                LIMIT 20
            """)
            
            groups = cursor.fetchall()
            self.logger.info(f"Processing technique relations for {len(groups)} groups...")
            
            for group_id, group_name, techniques_json in groups:
                try:
                    techniques = json.loads(techniques_json) if techniques_json else []
                    
                    # Trouver le groupe dans OpenCTI
                    group_opencti = self._find_intrusion_set_by_mitre_id(group_id)
                    if not group_opencti:
                        continue
                    
                    # Créer relations avec techniques (limité à 3 par groupe pour éviter surcharge)
                    for tech_id in techniques[:3]:
                        try:
                            tech_opencti = self._find_attack_pattern_by_mitre_id(tech_id)
                            if tech_opencti:
                                # Vérifier si relation existe déjà
                                existing = self.opencti_client.stix_core_relationship.list(
                                    filters={
                                        "mode": "and",
                                        "filters": [
                                            {"key": "fromId", "mode": "or", "operator": "eq", "values": [group_opencti["id"]]},
                                            {"key": "toId", "mode": "or", "operator": "eq", "values": [tech_opencti["id"]]},
                                            {"key": "relationship_type", "mode": "or", "operator": "eq", "values": ["uses"]}
                                        ],
                                        "filterGroups": []
                                    }
                                )
                                
                                if not existing or len(existing) == 0:
                                    self.opencti_client.stix_core_relationship.create(
                                        fromId=group_opencti["id"],
                                        toId=tech_opencti["id"],
                                        relationship_type="uses",
                                        description=f"Group {group_id} uses technique {tech_id}",
                                        confidence=80,
                                        x_opencti_score=75
                                    )
                                    created_count += 1
                                    self.logger.debug(f"✅ Created relation: {group_id} uses {tech_id}")
                                    
                        except Exception as rel_e:
                            self.logger.debug(f"Failed to create relation {group_id}->{tech_id}: {rel_e}")
                            continue
                            
                except Exception as e:
                    self.logger.warning(f"Failed group relations for {group_id}: {e}")
                    continue
                    
        self.logger.info(f"✅ Group-technique relations: {created_count} created")
        
     except Exception as e:
        self.logger.error(f"Error in group-technique relations: {e}")
    
     return created_count
    
    
    
    async def _cleanup_existing_mitre_data(self):
        try:
             if not self.opencti_config.get("force_refresh", False):
                self.logger.info("⏭️ Skipping cleanup (force_refresh=false)")
                return
             self.logger.info("🗑️ Cleaning up existing MITRE data...")
            # Supprimer les Attack Patterns MITRE existants
             batch_size = 20
             max_deletions = 100
             deleted_count = 0
        
             # Supprimer par petits lots
             for batch in range(0, max_deletions, batch_size):
              if deleted_count >= max_deletions:
                 break
              existing_patterns = self.opencti_client.attack_pattern.list(
                     filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "x_mitre_id",
                            "mode": "or", 
                            "operator": "not_nil",
                            "values": []
                        }
                    ],
                    "filterGroups": []
                }
            )
            
             
             for pattern in existing_patterns[:50]:  # Limiter pour éviter timeout
                try:
                    self.opencti_client.attack_pattern.delete(id=pattern["id"])
                    deleted_count += 1
                    self.logger.debug(f"Deleted: {pattern.get('x_mitre_id')}")
                    await asyncio.sleep(0.1)
                except Exception as e:
                    self.logger.warning(f"Failed to delete {pattern.get('x_mitre_id')}: {e}")
             await asyncio.sleep(1)   
             self.logger.info(f"✅ Cleaned up {deleted_count} attack patterns")
        except Exception as e:
            self.logger.warning(f"Cleanup warning (non-critical): {e}")

    async def _sync_attack_patterns_with_update(self):
     import sqlite3
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, name, description, tactic, platforms, kill_chain_phases,
                       parent_technique, is_subtechnique, last_updated
                FROM techniques
                ORDER BY id
            """)
            
            techniques = cursor.fetchall()
            self.logger.info(f"🔄 Processing {len(techniques)} techniques...")
            
            success_count = 0
            update_count = 0
            skip_count = 0
            error_count = 0
            
            for i, technique in enumerate(techniques):
                tech_id, name, desc, tactic, platforms, kcp, parent, is_sub, updated = technique
                
                try:
                    # Vérifier si existe
                    existing = self.opencti_client.attack_pattern.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "mode": "or",
                                    "operator": "eq",
                                    "values": [tech_id]
                                }
                            ],
                            "filterGroups": []
                        }
                    )
                    
                    if existing and len(existing) > 0:
                        attack_pattern = existing[0]
                        skip_count += 1
                        self.logger.debug(f"✅ EXISTS: {tech_id}")
                        
                        # ✅ CORRECTION : Supprimer et recréer seulement si force_refresh
                        if self.opencti_config.get("force_refresh", False):
                            try:
                                self.opencti_client.attack_pattern.delete(id=existing[0]["id"])
                                
                                attack_pattern_data = self._prepare_enhanced_attack_pattern_data(
                                    tech_id, name, desc, tactic, platforms, kcp, parent, is_sub
                                )
                                
                                attack_pattern = self.opencti_client.attack_pattern.create(**attack_pattern_data)
                                update_count += 1
                                self.logger.debug(f"✅ RECREATED: {tech_id}")
                            except Exception as delete_error:
                                self.logger.warning(f"Cannot delete/recreate {tech_id}: {delete_error}")
                                attack_pattern = existing[0]
                                skip_count += 1
                    else:
                        # ✅ CORRECTION : Créer nouveau et compter
                        attack_pattern_data = self._prepare_enhanced_attack_pattern_data(
                            tech_id, name, desc, tactic, platforms, kcp, parent, is_sub
                        )
                        
                        attack_pattern = self.opencti_client.attack_pattern.create(**attack_pattern_data)
                        success_count += 1
                        self.logger.debug(f"✅ CREATED: {tech_id}")
                    
                    # Gérer les sous-techniques seulement pour les techniques principales
                    if not is_sub and attack_pattern:
                        await self._sync_subtechniques_with_update(tech_id, attack_pattern["id"])
                    
                    # ✅ AJOUT : Progress logging plus fréquent
                    if (i + 1) % 50 == 0:
                        self.logger.info(f"Progress: {i + 1}/{len(techniques)} - Created: {success_count}, Skipped: {skip_count}, Updated: {update_count}")
                        await asyncio.sleep(0.1)  # Petite pause
                    
                except Exception as e:
                    error_count += 1
                    self.logger.error(f"❌ Failed to process {tech_id}: {e}")
                    
                    # ✅ AJOUT : Arrêter si trop d'erreurs consécutives
                    if error_count > 10:
                        self.logger.error("Too many errors, stopping sync")
                        break
                    continue
            
            # ✅ CORRECTION : Log final avec tous les compteurs
            self.logger.info(f"✅ Attack patterns completed: {success_count} created, {skip_count} skipped, {update_count} updated, {error_count} errors")
            
     except Exception as e:
        self.logger.error(f"Error in enhanced sync: {e}")


    async def _sync_subtechniques_with_update(self, parent_id: str, parent_opencti_id: str):
        """Synchronise les sous-techniques avec mise à jour"""
        import sqlite3
        
        try:
            with sqlite3.connect(self.mitre_enricher.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, name, description, tactic, platforms, kill_chain_phases
                    FROM techniques
                    WHERE parent_technique = ? AND is_subtechnique = TRUE
                """, (parent_id,))
                
                subtechniques = cursor.fetchall()
                
                for sub in subtechniques:
                    sub_id, name, desc, tactic, platforms, kcp = sub
                    
                    try:
                        # Préparer données enrichies
                        sub_data = self._prepare_enhanced_attack_pattern_data(
                            sub_id, name, desc, tactic, platforms, kcp, parent_id, True
                        )
                        
                        # Vérifier existence
                        existing = self.opencti_client.attack_pattern.list(
                            filters={
                                "mode": "and",
                                "filters": [
                                    {
                                        "key": "x_mitre_id",
                                        "mode": "or",
                                        "operator": "eq",
                                        "values": [sub_id]
                                    }
                                ],
                                "filterGroups": []
                            }
                        )
                        
                        if existing and len(existing) > 0:
                           sub_pattern = existing[0]
                           self.logger.debug(f"Subtechnique {sub_id} already exists")
    
    # Supprimer et recréer si force_refresh
                           if self.opencti_config.get("force_refresh", False):
                            try:
                             self.opencti_client.attack_pattern.delete(id=existing[0]["id"])
                             sub_pattern = self.opencti_client.attack_pattern.create(**sub_data)
                             self.logger.debug(f"Recreated subtechnique: {sub_id}")
                            except Exception as e:
                             self.logger.warning(f"Cannot recreate subtechnique {sub_id}: {e}")
                             sub_pattern = existing[0]
                           else:
    # Créer la sous-technique
                            sub_pattern = self.opencti_client.attack_pattern.create(**sub_data)
                            self.logger.debug(f"Created subtechnique: {sub_id}")
                    except Exception as e:
                        self.logger.warning(f"Failed subtechnique {sub_id}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error syncing subtechniques: {e}")

    async def _create_or_update_subtechnique_relation(self, sub_id, parent_id, sub_mitre_id, parent_mitre_id):
        """Crée ou met à jour une relation sous-technique"""
        try:
            # Vérifier si relation existe
            existing_relations = self.opencti_client.stix_core_relationship.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "fromId", "mode": "or", "operator": "eq", "values": [sub_id]},
                        {"key": "toId", "mode": "or", "operator": "eq", "values": [parent_id]},
                        {"key": "relationship_type", "mode": "or", "operator": "eq", "values": ["subtechnique-of"]}
                    ],
                    "filterGroups": []
                }
            )
            
            if not existing_relations or len(existing_relations) == 0:
                # Créer nouvelle relation
                self.opencti_client.stix_core_relationship.create(
                    fromId=sub_id,
                    toId=parent_id,
                    relationship_type="subtechnique-of",
                    description=f"{sub_mitre_id} is a subtechnique of {parent_mitre_id}",
                    confidence=90,
                    x_opencti_score=85
                )
                self.logger.debug(f"✅ Created relation: {sub_mitre_id} -> {parent_mitre_id}")
            else:
                self.logger.debug(f"Relation already exists: {sub_mitre_id} -> {parent_mitre_id}")
                
        except Exception as e:
            self.logger.warning(f"Relation creation failed: {e}")
    
    
    async def _sync_intrusion_sets_with_update(self):
     import sqlite3
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, aliases, description, techniques, software
                FROM groups
                ORDER BY id
            """)
            
            groups = cursor.fetchall()
            self.logger.info(f"🔄 Processing {len(groups)} intrusion sets...")
            
            success_count = 0
            update_count = 0
            skip_count = 0
            error_count = 0
            
            for i, group in enumerate(groups):
                group_id, name, aliases, description, techniques, software = group
                
                try:
                    # Vérifier si existe
                    existing = self.opencti_client.intrusion_set.list(
                        filters={
                            "mode": "and",
                            "filters": [
                                {
                                    "key": "x_mitre_id",
                                    "mode": "or",
                                    "operator": "eq",
                                    "values": [group_id]
                                }
                            ],
                            "filterGroups": []
                        }
                    )
                    
                    # Préparer les données
                    intrusion_set_data = {
                        "name": name,
                        "description": description or f"MITRE ATT&CK group {group_id}",
                        "aliases": json.loads(aliases) if aliases else [],
                        "x_mitre_id": group_id,
                        "confidence": self.opencti_config.get("confidence_level", 3)
                    }
                    
                    if existing and len(existing) > 0:
                        intrusion_set = existing[0]
                        skip_count += 1
                        self.logger.debug(f"✅ EXISTS: {group_id}")
                        
                        # Supprimer et recréer si force_refresh
                        if self.opencti_config.get("force_refresh", False):
                            try:
                                self.opencti_client.intrusion_set.delete(id=existing[0]["id"])
                                intrusion_set = self.opencti_client.intrusion_set.create(**intrusion_set_data)
                                update_count += 1
                                self.logger.debug(f"✅ RECREATED: {group_id}")
                            except Exception as delete_error:
                                self.logger.warning(f"Cannot delete/recreate {group_id}: {delete_error}")
                                intrusion_set = existing[0]
                                skip_count += 1
                    else:
                        # Créer nouveau
                        intrusion_set = self.opencti_client.intrusion_set.create(**intrusion_set_data)
                        success_count += 1
                        self.logger.debug(f"✅ CREATED: {group_id}")
                    
                    # Créer les relations avec les techniques (limité pour éviter surcharge)
                    if techniques and intrusion_set:
                        await self._create_group_technique_relations(
                            group_id, intrusion_set["id"], techniques
                        )
                    
                    # Progress logging
                    if (i + 1) % 20 == 0:
                        self.logger.info(f"Progress: {i + 1}/{len(groups)} - Created: {success_count}, Skipped: {skip_count}, Updated: {update_count}")
                        await asyncio.sleep(0.1)
                    
                except Exception as e:
                    error_count += 1
                    self.logger.error(f"❌ Failed to process group {group_id}: {e}")
                    continue
            
            # ✅ CORRECTION : Log final complet
            self.logger.info(f"✅ Intrusion sets completed: {success_count} created, {skip_count} skipped, {update_count} updated, {error_count} errors")
            
     except Exception as e:
        self.logger.error(f"Error in intrusion sets sync: {e}")

    async def _create_group_technique_relations(self, group_id: str, group_opencti_id: str, techniques_json: str):
     try:
        if not techniques_json:
            return
            
        techniques = json.loads(techniques_json) if techniques_json else []
        
        # Limiter à 10 techniques pour éviter surcharge
        for tech_id in techniques[:10]:
            tech_opencti = self._find_attack_pattern_by_mitre_id(tech_id)
            if tech_opencti:
                await self._create_or_update_uses_relation(
                    group_opencti_id, 
                    tech_opencti["id"], 
                    f"Group {group_id} uses technique {tech_id}"
                )
                
     except Exception as e:
        self.logger.warning(f"Failed to create relations for group {group_id}: {e}")

    async def _sync_parent_subtechnique_relations(self):
     import sqlite3
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT parent.id as parent_id, child.id as child_id
                FROM techniques parent
                JOIN techniques child ON child.parent_technique = parent.id
                WHERE parent.is_subtechnique = FALSE 
                AND child.is_subtechnique = TRUE
                LIMIT 50
            """)
            
            relations = cursor.fetchall()
            
            for parent_id, child_id in relations:
                try:
                    # Trouver les Attack Patterns dans OpenCTI
                    parent_ap = self._find_attack_pattern_by_mitre_id(parent_id)
                    child_ap = self._find_attack_pattern_by_mitre_id(child_id)
                    
                    if parent_ap and child_ap:
                        await self._create_or_update_subtechnique_relation(
                            child_ap["id"], parent_ap["id"], child_id, parent_id
                        )
                        
                except Exception as rel_e:
                    self.logger.warning(f"Failed relation {child_id}->{parent_id}: {rel_e}")
                    
     except Exception as e:
        self.logger.error(f"Error syncing parent-subtechnique relations: {e}")

        self.logger.error(f"Error syncing relationships: {e}")


    async def _sync_group_technique_relations(self):
        """Synchronise les relations groupes -> techniques"""
        import sqlite3
        
        try:
            with sqlite3.connect(self.mitre_enricher.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, name, techniques 
                    FROM groups 
                    WHERE techniques IS NOT NULL AND techniques != '[]'
                """)
                
                groups = cursor.fetchall()
                
                for group_id, group_name, techniques_json in groups:
                    try:
                        techniques = json.loads(techniques_json) if techniques_json else []
                        
                        # Trouver le groupe dans OpenCTI
                        group_opencti = self._find_intrusion_set_by_mitre_id(group_id)
                        if not group_opencti:
                            continue
                        
                        # Créer relations avec techniques
                        for tech_id in techniques[:10]:  # Limiter à 10 pour éviter surcharge
                            tech_opencti = self._find_attack_pattern_by_mitre_id(tech_id)
                            if tech_opencti:
                                await self._create_or_update_uses_relation(
                                    group_opencti["id"], tech_opencti["id"], 
                                    f"Group {group_id} uses technique {tech_id}"
                                )
                                
                    except Exception as e:
                        self.logger.warning(f"Failed group relations for {group_id}: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error in group-technique relations: {e}")

    def _find_intrusion_set_by_mitre_id(self, group_id: str) -> Optional[Dict]:
        """Trouve un Intrusion Set par ID MITRE"""
        try:
            groups = self.opencti_client.intrusion_set.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {
                            "key": "x_mitre_id",
                            "mode": "or",
                            "operator": "eq",
                            "values": [group_id]
                        }
                    ],
                    "filterGroups": []
                }
            )
            
            return groups[0] if groups and len(groups) > 0 else None
            
        except Exception as e:
            self.logger.error(f"Error finding intrusion set {group_id}: {e}")
            return None

    async def _create_or_update_uses_relation(self, from_id: str, to_id: str, description: str):
        """Crée ou met à jour une relation 'uses'"""
        try:
            # Vérifier existence
            existing = self.opencti_client.stix_core_relationship.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "fromId", "mode": "or", "operator": "eq", "values": [from_id]},
                        {"key": "toId", "mode": "or", "operator": "eq", "values": [to_id]},
                        {"key": "relationship_type", "mode": "or", "operator": "eq", "values": ["uses"]}
                    ],
                    "filterGroups": []
                }
            )
            
            if not existing or len(existing) == 0:
                self.opencti_client.stix_core_relationship.create(
                    fromId=from_id,
                    toId=to_id,
                    relationship_type="uses",
                    description=description,
                    confidence=80,
                    x_opencti_score=75
                )
                
        except Exception as e:
            if "already exists" not in str(e).lower():
                self.logger.warning(f"Uses relation failed: {e}")
    
    def _prepare_enhanced_attack_pattern_data(self, tech_id, name, desc, tactic, platforms, kcp, parent, is_sub):
        """Prépare des données enrichies pour l'attack pattern"""
        import json
        
        # Kill chain phases améliorées
        kill_chain_phases_data = []
        if kcp:
            try:
                phases = json.loads(kcp)
                kill_chain_phases_data = [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": phase
                } for phase in phases if phase]
            except:
                if tactic:
                    kill_chain_phases_data = [{
                        "kill_chain_name": "mitre-attack", 
                        "phase_name": tactic
                    }]
        
        # Plateformes
        platforms_data = []
        if platforms:
            try:
                platforms_data = json.loads(platforms)
            except:
                platforms_data = []
        
        # ✅ DONNÉES ENRICHIES
        attack_pattern_data = {
            "name": f"{tech_id} - {name}",
            "description": desc or f"MITRE ATT&CK technique {tech_id}",
            "x_mitre_id": tech_id,
            "confidence": self.opencti_config.get("confidence_level", 3),
            "revoked": False,
            "x_opencti_score": 75  # Score par défaut
        }
        
        # ✅ AJOUTS CONDITIONNELS
        if platforms_data:
            attack_pattern_data["x_mitre_platforms"] = platforms_data
            
        if kill_chain_phases_data:
            attack_pattern_data["kill_chain_phases"] = kill_chain_phases_data
        
        # ✅ NOUVEAU: Métadonnées enrichies
        if is_sub and parent:
            attack_pattern_data["x_mitre_is_subtechnique"] = True
            attack_pattern_data["description"] += f" (Subtechnique of {parent})"
        
        # ✅ NOUVEAU: Tags pour classification
        tags = []
        if tactic:
            tags.append(f"tactic:{tactic}")
        if platforms_data:
            tags.extend([f"platform:{p}" for p in platforms_data[:3]])
        
        if tags:
            attack_pattern_data["x_opencti_tags"] = tags
        
        return attack_pattern_data
   
    async def _sync_kill_chains(self):
      try:
        self.logger.info("Checking MITRE kill chain phases...")
        
        # ✅ CORRECT : Utiliser killChainPhases au lieu de killChains
        query = '''
query {
    killChainPhases(
        filters: {
            mode: and,
            filters: [{
                key: "kill_chain_name",
                mode: or,
                operator: eq,
                values: ["mitre-attack"]
            }],
            filterGroups: []
        }
    ) {
        edges {
            node {
                id
                phase_name
                kill_chain_name
            }
        }
    }
}
'''
        
        result = self.opencti_client.query(query)
        
        if result and result.get("data", {}).get("killChainPhases", {}).get("edges"):
            phases = result["data"]["killChainPhases"]["edges"]
            self.logger.info(f"Found {len(phases)} MITRE kill chain phases")
            
            if len(phases) > 0:
                self.logger.info("✅ MITRE kill chain phases already exist in OpenCTI")
            else:
                self.logger.info("No MITRE phases found but will be created automatically")
        else:
            self.logger.info("Kill chain phases will be created automatically by attack patterns")
            
      except Exception as e:
        # Ce n'est pas critique, les kill chains seront créées automatiquement
        self.logger.info(f"Kill chain check completed with note: {e}")
    
    async def _sync_attack_patterns(self):
     import sqlite3
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, description, tactic, platforms, kill_chain_phases
                FROM techniques
                WHERE is_subtechnique = FALSE OR is_subtechnique IS NULL
                ORDER BY id
                LIMIT 400
            """)
            
            techniques = cursor.fetchall()
            self.logger.info(f"Processing {len(techniques)} main techniques...")
            
            success_count = 0
            error_count = 0
            
            for i, technique in enumerate(techniques):
                technique_id, name, description, tactic, platforms, kill_chain_phases = technique
                
                try:
                    # ✅ CORRECTION : Structure filterGroups correcte

                    existing_patterns = self.opencti_client.attack_pattern.list(
    filters={
        "mode": "and",
        "filters": [
            {
                "key": "x_mitre_id",
                "mode": "or",
                "operator": "eq",
                "values": [technique_id]
            }
        ],
        "filterGroups": []
    }
)
                    
                    if existing_patterns and len(existing_patterns) > 0:
                        self.logger.debug(f"Attack pattern {technique_id} already exists")
                        attack_pattern = existing_patterns[0]
                        success_count += 1
                    else:
                        # Préparer les données de l'attack pattern
                        attack_pattern_data = self._prepare_attack_pattern_data(
                            technique_id, name, description, tactic, platforms, kill_chain_phases
                        )
                        
                        attack_pattern = self.opencti_client.attack_pattern.create(**attack_pattern_data)
                        self.logger.debug(f"Created attack pattern: {technique_id}")
                        success_count += 1
                    
                    # Synchroniser les sous-techniques
                    if attack_pattern:
                        await self._sync_subtechniques_safe(technique_id, attack_pattern["id"])
                    
                    # Pause pour éviter la surcharge
                    if i % 10 == 0 and i > 0:
                        await asyncio.sleep(0.2)
                        self.logger.info(f"Progress: {i}/{len(techniques)} techniques processed")
                        
                except Exception as tech_e:
                    error_count += 1
                    self.logger.warning(f"Failed to process technique {technique_id}: {tech_e}")
                    
                    # Arrêter si trop d'erreurs
                    if error_count > 5:
                        self.logger.error("Too many errors, stopping sync")
                        break
                    continue
            
            self.logger.info(f"Attack patterns sync completed: {success_count} success, {error_count} errors")
                    
     except Exception as e:
        self.logger.error(f"Error syncing attack patterns: {e}")
    
    def _prepare_attack_pattern_data(self, technique_id, name, description, tactic, platforms, kill_chain_phases):
   # Préparer les kill chain phases
      kill_chain_phases_data = []
      if kill_chain_phases:
        try:
            phases = json.loads(kill_chain_phases)
            kill_chain_phases_data = [{
                "kill_chain_name": "mitre-attack",
                "phase_name": phase
            } for phase in phases if phase]
        except (json.JSONDecodeError, TypeError):
            if tactic:
                kill_chain_phases_data = [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": tactic
                }]
      elif tactic:
        kill_chain_phases_data = [{
            "kill_chain_name": "mitre-attack",
            "phase_name": tactic
        }]
    
    # Préparer les plateformes
      platforms_data = []
      if platforms:
        try:
            platforms_data = json.loads(platforms)
        except (json.JSONDecodeError, TypeError):
            platforms_data = []
    
    # Créer les données de l'attack pattern
      attack_pattern_data = {
        "name": f"{technique_id} - {name}",
        "description": description or f"MITRE ATT&CK technique {technique_id}",
        "x_mitre_id": technique_id
     }
    
      if platforms_data:
        attack_pattern_data["x_mitre_platforms"] = platforms_data
        
      if kill_chain_phases_data:
        attack_pattern_data["kill_chain_phases"] = kill_chain_phases_data
    
      return attack_pattern_data
    
    async def _sync_subtechniques_safe(self, parent_id: str, parent_opencti_id: str):
      import sqlite3
    
      try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, description, tactic, platforms, kill_chain_phases
                FROM techniques
                WHERE parent_technique = ? AND is_subtechnique = TRUE
                LIMIT 20
            """, (parent_id,))
            
            subtechniques = cursor.fetchall()
            
            for subtechnique in subtechniques:
                sub_id, name, description, tactic, platforms, kill_chain_phases = subtechnique
                
                try:
                    # ✅ CORRECTION : Structure filterGroups correcte
                    existing = self.opencti_client.attack_pattern.list(
    filters={
        "mode": "and",
        "filters": [
            {
                "key": "x_mitre_id",
                "mode": "or",
                "operator": "eq",
                "values": [sub_id]
            }
        ],
        "filterGroups": []
    }
)      
                    if existing and len(existing) > 0:
                        sub_attack_pattern = existing[0]
                        self.logger.debug(f"Subtechnique {sub_id} already exists")
                    else:
                        # Créer la sous-technique
                        sub_attack_pattern_data = self._prepare_attack_pattern_data(
                            sub_id, name, description, tactic, platforms, kill_chain_phases
                        )
                        
                        sub_attack_pattern = self.opencti_client.attack_pattern.create(**sub_attack_pattern_data)
                        self.logger.debug(f"Created subtechnique: {sub_id}")
                    
                    # Créer la relation parent -> sous-technique
                    try:
                        self.opencti_client.stix_core_relationship.create(
                            fromId=sub_attack_pattern["id"],
                            toId=parent_opencti_id,
                            relationship_type="related-to",
                            description=f"Subtechnique relationship: {sub_id} is a subtechnique of {parent_id}",
                            x_opencti_score=80
                        )
                        self.logger.debug(f"Created subtechnique relation: {sub_id} -> {parent_id}")
                        
                    except Exception as rel_e:
                        if "already exists" not in str(rel_e).lower():
                            self.logger.debug(f"Relation for {sub_id} may already exist: {rel_e}")
                            
                except Exception as sub_e:
                    self.logger.warning(f"Failed to process subtechnique {sub_id}: {sub_e}")
                    continue
                    
      except Exception as e:
        self.logger.error(f"Error syncing subtechniques for {parent_id}: {e}")
    
    async def _sync_intrusion_sets(self):
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, aliases, description, techniques, software
                FROM groups
            """)
            
            groups = cursor.fetchall()
            
            for group in groups:
                group_id, name, aliases, description, techniques, software = group
                
                # CORRECTION : Vérifier si existe déjà
                existing = self.opencti_client.intrusion_set.list(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "x_mitre_id", "mode": "or", "operator": "eq", "values": [group_id]}],
                        "filterGroups": []
                    }
                )
                
                if existing and len(existing) > 0:
                    intrusion_set = existing[0]
                else:
                    intrusion_set = self.opencti_client.intrusion_set.create(
                        name=name,
                        description=description or f"MITRE ATT&CK group {group_id}",
                        aliases=json.loads(aliases) if aliases else [],
                        x_mitre_id=group_id
                    )
                
                # AJOUT : Créer les relations avec techniques
                if techniques:
                    technique_list = json.loads(techniques) if techniques else []
                    for tech_id in technique_list:
                        attack_pattern = self._find_attack_pattern_by_mitre_id(tech_id)
                        if attack_pattern:
                            try:
                                self.opencti_client.stix_core_relationship.create(
                                    fromId=intrusion_set["id"],
                                    toId=attack_pattern["id"],
                                    relationship_type="uses",
                                    description=f"Group {group_id} uses technique {tech_id}",
                                    confidence=80
                                )
                            except Exception as rel_e:
                                if "already exists" not in str(rel_e).lower():
                                    self.logger.warning(f"Failed to create relation {group_id}->{tech_id}: {rel_e}")
                
                # AJOUT : Créer les relations avec malwares
                if software:
                    software_list = json.loads(software) if software else []
                    for malware_name in software_list:
                        # Créer ou trouver le malware dans OpenCTI
                        malware = await self._create_or_get_malware(malware_name, group_id)
                        if malware:
                            try:
                                self.opencti_client.stix_core_relationship.create(
                                    fromId=intrusion_set["id"],
                                    toId=malware["id"],
                                    relationship_type="uses",
                                    description=f"Group {group_id} uses malware {malware_name}",
                                    confidence=85
                                )
                            except Exception as rel_e:
                                if "already exists" not in str(rel_e).lower():
                                    self.logger.warning(f"Failed to create malware relation: {rel_e}")
     except Exception as e:
            self.logger.error(f"Error syncing intrusion sets: {e}")

    async def _create_or_get_malware(self, malware_name: str, group_id: str) -> Optional[Dict]:
     try:
        # Chercher si le malware existe déjà
        existing = self.opencti_client.malware.list(
            filters={
                "mode": "and",
                "filters": [{"key": "name", "mode": "or", "operator": "eq", "values": [malware_name]}],
                "filterGroups": []
            }
        )
        
        if existing and len(existing) > 0:
            return existing[0]
        
        # Créer un nouveau malware
        malware = self.opencti_client.malware.create(
            name=malware_name,
            description=f"Malware used by {group_id} according to MITRE ATT&CK",
            is_family=False,
            confidence=self.opencti_config.get("confidence_level", 3)
        )
        
        self.logger.debug(f"Created malware: {malware_name}")
        return malware
        
     except Exception as e:
        self.logger.error(f"Error creating/getting malware {malware_name}: {e}")
        return None
    
    async def _create_mitre_relations(self):
        """Créer les relations entre entités MITRE"""
        # Cette méthode peut être étendue pour créer des relations complexes
        # entre techniques, groupes, logiciels malveillants, etc.
        try:
            self.logger.info("Creating MITRE relations...")
            # Implémentation future des relations complexes
            pass
        except Exception as e:
            self.logger.error(f"Error creating MITRE relations: {e}")

    async def enrich_cve_with_mitre(self, cve_data: Dict) -> Dict:
        """Enrichit un CVE avec les données MITRE ATT&CK et l'envoie vers OpenCTI"""
        try:
            # Mapper le CVE aux techniques MITRE
            technique_mappings = self.mitre_enricher.map_cve_to_techniques(cve_data)
            
            if not technique_mappings:
                return cve_data
            
            # Créer ou récupérer le CVE dans OpenCTI
            vulnerability = self._create_or_get_vulnerability(cve_data)
            
            # Créer les relations CVE -> Attack Patterns
            for technique_id, confidence in technique_mappings:
                technique_details = self.mitre_enricher.get_technique_details(technique_id)
                if technique_details:
                    # Trouver l'Attack Pattern correspondant dans OpenCTI
                    attack_pattern = self._find_attack_pattern_by_mitre_id(technique_id)
                    
                    if attack_pattern:
                        # Créer la relation
                       self.opencti_client.stix_core_relationship.create(
                        fromId=vulnerability["id"],
                        toId=attack_pattern["id"],
                        relationship_type="exploits",
                        confidence=int(confidence * 100),
                        description=f"CVE {cve_data.get('id')} can be exploited using technique {technique_id}",
                        x_opencti_score=int(confidence * 100)
                    )
            
            # Enrichir les données CVE avec les informations MITRE
            cve_data["mitre_techniques"] = [
                {
                    "technique_id": tech_id,
                    "confidence": conf,
                    "technique_name": self.mitre_enricher.get_technique_details(tech_id).name if self.mitre_enricher.get_technique_details(tech_id) else ""
                }
                for tech_id, conf in technique_mappings
            ]
            
            return cve_data
            
        except Exception as e:
            self.logger.error(f"Error enriching CVE with MITRE: {e}")
            return cve_data
    
    async def enrich_ioc_with_mitre(self, ioc_data: Dict) -> Dict:
        """Enrichit un IOC avec les données MITRE ATT&CK"""
        try:
            # Mapper l'IOC aux techniques MITRE
            technique_mappings = self.mitre_enricher.map_ioc_to_techniques(ioc_data)
            
            if not technique_mappings:
                return ioc_data
            
            # Créer ou récupérer l'indicateur dans OpenCTI
            indicator = self._create_or_get_indicator(ioc_data)
            
            # Créer les relations IOC -> Attack Patterns
            for technique_id, confidence in technique_mappings:
                attack_pattern = self._find_attack_pattern_by_mitre_id(technique_id)
                
                if attack_pattern:
                     self.opencti_client.stix_core_relationship.create(
                       fromId=indicator["id"],
                       toId=attack_pattern["id"],
                      relationship_type="indicates",
                      confidence=int(confidence * 100),
                      description=f"IOC indicates usage of technique {technique_id}",
                      x_opencti_score=int(confidence * 100)
                )
            
            # Enrichir les données IOC
            ioc_data["mitre_techniques"] = [
                {
                    "technique_id": tech_id,
                    "confidence": conf
                }
                for tech_id, conf in technique_mappings
            ]
            
            return ioc_data
            
        except Exception as e:
            self.logger.error(f"Error enriching IOC with MITRE: {e}")
            return ioc_data

    def _create_or_get_vulnerability(self, cve_data: Dict) -> Dict:
     try:
        cve_id = cve_data.get("id", "")
        
        # ✅ CORRECTION : Structure filterGroups correcte
        existing = self.opencti_client.vulnerability.list(
    filters={
        "mode": "and",
        "filters": [
            {
                "key": "name",
                "mode": "or",
                "operator": "eq",
                "values": [cve_id]
            }
        ],
        "filterGroups": []
    }
)       
        if existing and len(existing) > 0:
            return existing[0]
        
        # Créer une nouvelle vulnérabilité
        vulnerability = self.opencti_client.vulnerability.create(
            name=cve_id,
            description=cve_data.get("description", f"Vulnerability {cve_id}"),
            x_opencti_score=cve_data.get("cvss_score", 50),
            confidence=self.opencti_config.get("confidence_level", 3)
        )
        
        return vulnerability
        
     except Exception as e:
        self.logger.error(f"Error creating/getting vulnerability: {e}")
        return {}

    def _create_or_get_indicator(self, ioc_data: Dict) -> Dict:
     try:
        ioc_value = ioc_data.get("value", "")
        ioc_type = ioc_data.get("ioc_type", ioc_data.get("type", ""))
        
        # Mapper le type d'IOC au pattern STIX
        stix_pattern = self._map_ioc_to_stix_pattern(ioc_type, ioc_value)
        
        # ✅ CORRECTION : Structure filterGroups correcte
        existing = self.opencti_client.indicator.list(
    filters={
        "mode": "and",  
        "filters": [
            {
                "key": "pattern",
                "mode": "or",
                "operator": "eq", 
                "values": [stix_pattern]
            }
        ],
        "filterGroups": []
    }
)
        
        if existing and len(existing) > 0:
            return existing[0]
        
        # Créer un nouvel indicateur
        indicator = self.opencti_client.indicator.create(
            pattern=stix_pattern,
            pattern_type="stix",
            x_opencti_main_observable_type=ioc_type,
            confidence=self.opencti_config.get("confidence_level", 3)
        )
        
        return indicator
        
     except Exception as e:
        self.logger.error(f"Error creating/getting indicator: {e}")
        return {}

    def _find_attack_pattern_by_mitre_id(self, technique_id: str) -> Optional[Dict]:
     try:
        attack_patterns = self.opencti_client.attack_pattern.list(
            filters={
                "mode": "and",
                "filters": [
                    {
                        "key": "x_mitre_id",
                        "mode": "or",
                        "operator": "eq",
                        "values": [technique_id]
                    }
                ],
                "filterGroups": []
            }
        )
        
        if attack_patterns and len(attack_patterns) > 0:
            return attack_patterns[0]
        
        return None
        
     except Exception as e:
        self.logger.error(f"Error finding attack pattern for {technique_id}: {e}")
        return None


    def _map_ioc_to_stix_pattern(self, ioc_type: str, ioc_value: str) -> str:
        """Convertit un IOC en pattern STIX"""
        type_mappings = {
            "domain": f"[domain-name:value = '{ioc_value}']",
            "ip": f"[ipv4-addr:value = '{ioc_value}']",
            "url": f"[url:value = '{ioc_value}']",
            "email": f"[email-addr:value = '{ioc_value}']",
            "file_hash": f"[file:hashes.MD5 = '{ioc_value}']",
            "registry": f"[windows-registry-key:key = '{ioc_value}']"
        }
        
        return type_mappings.get(ioc_type.lower(), f"[x-custom:value = '{ioc_value}']")

    
    def _check_available_apis(self):
     available_apis = []
    
     apis_to_check = [
        'attack_pattern', 'intrusion_set', 'indicator', 'vulnerability',
        'stix_core_relationship', 'kill_chain', 'kill_chain_phase'
     ]
    
     for api_name in apis_to_check:
        if hasattr(self.opencti_client, api_name):
            api_obj = getattr(self.opencti_client, api_name)
            if hasattr(api_obj, 'create') and hasattr(api_obj, 'list'):
                available_apis.append(api_name)
    
     self.logger.info(f"Available OpenCTI APIs: {available_apis}")
     return available_apis
    
    def _prepare_attack_pattern_data(self, technique_id, name, description, tactic, platforms, kill_chain_phases):
     import json
    
    # Préparer les kill chain phases
     kill_chain_phases_data = []
     if kill_chain_phases:
        try:
            phases = json.loads(kill_chain_phases)
            kill_chain_phases_data = [{
                "kill_chain_name": "mitre-attack",
                "phase_name": phase
            } for phase in phases if phase]
        except (json.JSONDecodeError, TypeError):
            if tactic:
                kill_chain_phases_data = [{
                    "kill_chain_name": "mitre-attack",
                    "phase_name": tactic
                }]
     elif tactic:
        kill_chain_phases_data = [{
            "kill_chain_name": "mitre-attack",
            "phase_name": tactic
        }]
    
    # Préparer les plateformes
     platforms_data = []
     if platforms:
        try:
            platforms_data = json.loads(platforms)
        except (json.JSONDecodeError, TypeError):
            platforms_data = []
    
    # Créer les données de l'attack pattern
     attack_pattern_data = {
        "name": f"{technique_id} - {name}",
        "description": description or f"MITRE ATT&CK technique {technique_id}",
        "x_mitre_id": technique_id
     }
    
     if platforms_data:
        attack_pattern_data["x_mitre_platforms"] = platforms_data
        
     if kill_chain_phases_data:
        attack_pattern_data["kill_chain_phases"] = kill_chain_phases_data
    
     return attack_pattern_data
    

    # Ajouter ces méthodes dans opencti_mitre_connector.py
    async def _sync_malware_technique_relations(self):
     try:
        self.logger.info("🦠 Syncing malware-technique relations...")
        # Cette méthode peut être laissée vide pour l'instant
        # ou implémentée plus tard si vous avez des données malware
        pass
        
     except Exception as e:
        self.logger.warning(f"Malware relations sync warning: {e}")

    async def _sync_relationships_with_update(self):
     try:
        self.logger.info("🔗 Starting relationships sync...")
        
        # 1. Relations parent-enfant (sous-techniques)
        await self._sync_parent_subtechnique_relations_improved()
        
        # 2. Relations groupe-technique
        await self._sync_group_technique_relations_improved()
        
        self.logger.info("✅ Relationships sync completed")
        
     except Exception as e:
        self.logger.error(f"Error syncing relationships: {e}")

    async def _sync_parent_subtechnique_relations_improved(self):
     import sqlite3
     
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT parent.id as parent_id, child.id as child_id
                FROM techniques parent
                JOIN techniques child ON child.parent_technique = parent.id
                WHERE parent.is_subtechnique = FALSE 
                AND child.is_subtechnique = TRUE
                LIMIT 100
            """)
            
            relations = cursor.fetchall()
            self.logger.info(f"Processing {len(relations)} parent-child relations...")
            
            success_count = 0
            skip_count = 0
            
            for parent_id, child_id in relations:
                try:
                    # Trouver les Attack Patterns dans OpenCTI
                    parent_ap = self._find_attack_pattern_by_mitre_id(parent_id)
                    child_ap = self._find_attack_pattern_by_mitre_id(child_id)
                    
                    if parent_ap and child_ap:
                        # Vérifier si relation existe déjà
                        existing_relations = self.opencti_client.stix_core_relationship.list(
                            filters={
                                "mode": "and",
                                "filters": [
                                    {"key": "fromId", "mode": "or", "operator": "eq", "values": [child_ap["id"]]},
                                    {"key": "toId", "mode": "or", "operator": "eq", "values": [parent_ap["id"]]},
                                    {"key": "relationship_type", "mode": "or", "operator": "eq", "values": ["subtechnique-of"]}
                                ],
                                "filterGroups": []
                            }
                        )
                        
                        if not existing_relations or len(existing_relations) == 0:
                            # Créer nouvelle relation
                            self.opencti_client.stix_core_relationship.create(
                                fromId=child_ap["id"],
                                toId=parent_ap["id"],
                                relationship_type="subtechnique-of",
                                description=f"{child_id} is a subtechnique of {parent_id}",
                                confidence=90,
                                x_opencti_score=85
                            )
                            success_count += 1
                            self.logger.debug(f"✅ Created relation: {child_id} -> {parent_id}")
                        else:
                            skip_count += 1
                            self.logger.debug(f"Relation already exists: {child_id} -> {parent_id}")
                    else:
                        self.logger.debug(f"Missing attack patterns for {child_id} -> {parent_id}")
                        
                except Exception as rel_e:
                    self.logger.warning(f"Failed relation {child_id}->{parent_id}: {rel_e}")
            
            self.logger.info(f"✅ Parent-child relations: {success_count} created, {skip_count} skipped")
                    
     except Exception as e:
        self.logger.error(f"Error syncing parent-subtechnique relations: {e}")

    async def _sync_group_technique_relations_improved(self):
     import sqlite3
    
     try:
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, name, techniques 
                FROM groups 
                WHERE techniques IS NOT NULL AND techniques != '[]'
                LIMIT 50
            """)
            
            groups = cursor.fetchall()
            self.logger.info(f"Processing technique relations for {len(groups)} groups...")
            
            total_relations = 0
            success_relations = 0
            
            for group_id, group_name, techniques_json in groups:
                try:
                    techniques = json.loads(techniques_json) if techniques_json else []
                    
                    # Trouver le groupe dans OpenCTI
                    group_opencti = self._find_intrusion_set_by_mitre_id(group_id)
                    if not group_opencti:
                        continue
                    
                    # Créer relations avec techniques (limité à 5 par groupe)
                    for tech_id in techniques[:5]:
                        total_relations += 1
                        tech_opencti = self._find_attack_pattern_by_mitre_id(tech_id)
                        if tech_opencti:
                            created = await self._create_or_update_uses_relation_improved(
                                group_opencti["id"], tech_opencti["id"], 
                                f"Group {group_id} uses technique {tech_id}"
                            )
                            if created:
                                success_relations += 1
                                
                except Exception as e:
                    self.logger.warning(f"Failed group relations for {group_id}: {e}")
            
            self.logger.info(f"✅ Group-technique relations: {success_relations}/{total_relations} created")
                        
     except Exception as e:
        self.logger.error(f"Error in group-technique relations: {e}")

    async def _create_or_update_uses_relation_improved(self, from_id: str, to_id: str, description: str) -> bool:
     try:
        # Vérifier existence
        existing = self.opencti_client.stix_core_relationship.list(
            filters={
                "mode": "and",
                "filters": [
                    {"key": "fromId", "mode": "or", "operator": "eq", "values": [from_id]},
                    {"key": "toId", "mode": "or", "operator": "eq", "values": [to_id]},
                    {"key": "relationship_type", "mode": "or", "operator": "eq", "values": ["uses"]}
                ],
                "filterGroups": []
            }
        )
        
        if not existing or len(existing) == 0:
            self.opencti_client.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type="uses",
                description=description,
                confidence=80,
                x_opencti_score=75
            )
            return True
        else:
            return False  # Relation déjà existante
            
     except Exception as e:
        if "already exists" not in str(e).lower():
            self.logger.warning(f"Uses relation failed: {e}")
        return False
    
    async def create_attack_pattern_relationships(self):
     try:
        import sqlite3
        
        with sqlite3.connect(self.mitre_enricher.db_path) as conn:
            cursor = conn.cursor()
            
            # Récupérer toutes les relations parent-enfant
            cursor.execute("""
                SELECT parent.id as parent_id, child.id as child_id
                FROM techniques parent
                JOIN techniques child ON child.parent_technique = parent.id
                WHERE parent.is_subtechnique = FALSE 
                AND child.is_subtechnique = TRUE
            """)
            
            relations = cursor.fetchall()
            
            for parent_id, child_id in relations:
                try:
                    # Trouver les Attack Patterns dans OpenCTI
                    parent_ap = self._find_attack_pattern_by_mitre_id(parent_id)
                    child_ap = self._find_attack_pattern_by_mitre_id(child_id)
                    
                    if parent_ap and child_ap:
                        # Créer la relation subtechnique-of
                        self.opencti_client.stix_core_relationship.create(
                            fromId=child_ap["id"],
                            toId=parent_ap["id"],
                            relationship_type="subtechnique-of",
                            description=f"{child_id} is a subtechnique of {parent_id}",
                            x_opencti_score=90
                        )
                        
                        self.logger.debug(f"Created subtechnique relation: {child_id} -> {parent_id}")
                        
                except Exception as rel_e:
                    if "already exists" not in str(rel_e).lower():
                        self.logger.warning(f"Failed to create relation {child_id}->{parent_id}: {rel_e}")
                        
     except Exception as e:
        self.logger.error(f"Error creating attack pattern relationships: {e}")

    async def sync_malware_and_tools(self):
     try:
        # Cette méthode nécessiterait d'étendre votre base de données
        # pour inclure les malwares et outils MITRE
        
        malware_data = await self._fetch_mitre_malware()
        tools_data = await self._fetch_mitre_tools()
        
        for malware in malware_data:
            await self._create_malware_in_opencti(malware)
            
        for tool in tools_data:
            await self._create_tool_in_opencti(tool)
            
        self.logger.info("Malware and tools synchronized")
        
     except Exception as e:
        self.logger.error(f"Error syncing malware and tools: {e}")

    async def create_threat_landscape_report(self) -> Dict:
     try:
        # Analyser les techniques les plus utilisées
        query = """
        query {
            attackPatterns(first: 100) {
                edges {
                    node {
                        id
                        name
                        x_mitre_id
                        objectRefsTo {
                            edges {
                                node {
                                    relationship_type
                                    fromType
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        result = self.opencti_client.query(query)
        
        if result and result.get("data"):
            patterns = result["data"]["attackPatterns"]["edges"]
            
            # Analyser les relations pour identifier les techniques populaires
            technique_usage = {}
            
            for pattern in patterns:
                node = pattern["node"]
                mitre_id = node.get("x_mitre_id")
                if mitre_id:
                    relations_count = len(node.get("objectRefsTo", {}).get("edges", []))
                    technique_usage[mitre_id] = {
                        "name": node["name"],
                        "relations_count": relations_count
                    }
            
            # Trier par utilisation
            top_techniques = sorted(
                technique_usage.items(), 
                key=lambda x: x[1]["relations_count"], 
                reverse=True
            )[:15]
            
            return {
                "top_techniques": [
                    {
                        "technique_id": tech_id,
                        "name": data["name"],
                        "usage_count": data["relations_count"]
                    }
                    for tech_id, data in top_techniques
                ],
                "total_techniques_analyzed": len(technique_usage),
                "generated_at": datetime.now().isoformat()
            }
            
     except Exception as e:
        self.logger.error(f"Error creating threat landscape report: {e}")
        return {}

    async def enrich_with_threat_intelligence(self, data: Dict) -> Dict:
     try:
        data_type = data.get("type", "").lower()
        
        if data_type == "vulnerability":
            # Enrichir avec des données CVE externes
            cve_id = data.get("id", "")
            if cve_id.startswith("CVE-"):
                external_data = await self._fetch_external_cve_data(cve_id)
                if external_data:
                    data["external_intelligence"] = external_data
                    
        elif data_type == "indicator":
            # Enrichir avec des IOC de threat feeds
            ioc_value = data.get("value", "")
            threat_feeds_data = await self._check_threat_feeds(ioc_value)
            if threat_feeds_data:
                data["threat_feeds"] = threat_feeds_data
                
        return data
        
     except Exception as e:
        self.logger.error(f"Error in threat intelligence enrichment: {e}")
        return data

    async def _fetch_external_cve_data(self, cve_id: str) -> Optional[Dict]:
     try:
        if not REQUESTS_AVAILABLE:
            return None
            
        # Exemple avec l'API NIST NVD
        nist_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        response = requests.get(nist_url, timeout=10)
        if response.status_code == 200:
            nvd_data = response.json()
            
            if nvd_data.get("vulnerabilities"):
                vuln = nvd_data["vulnerabilities"][0]["cve"]
                return {
                    "source": "NIST NVD",
                    "published_date": vuln.get("published"),
                    "last_modified": vuln.get("lastModified"),
                    "cvss_v3": vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}),
                    "cwe_ids": [w.get("value") for w in vuln.get("weaknesses", [{}])[0].get("description", [])]
                }
                
     except Exception as e:
        self.logger.debug(f"Error fetching external CVE data: {e}")
        return None

    async def create_dashboard_metrics(self) -> Dict:
     try:
        metrics = {}
        
        # Métriques OpenCTI
        opencti_metrics = await self._get_opencti_metrics()
        metrics["opencti"] = opencti_metrics
        
        # Métriques MITRE
        mitre_metrics = self.mitre_enricher.get_attack_statistics()
        metrics["mitre"] = mitre_metrics
        
        # Métriques de performance d'enrichissement
        enrichment_metrics = await self._get_enrichment_performance()
        metrics["enrichment"] = enrichment_metrics
        
        return metrics
        
     except Exception as e:
        self.logger.error(f"Error creating dashboard metrics: {e}")
        return {}

    async def _get_opencti_metrics(self) -> Dict:
     try:
        # Compter les entités par type
        query = """
        query {
            vulnerabilities { pageInfo { globalCount } }
            indicators { pageInfo { globalCount } }
            attackPatterns { pageInfo { globalCount } }
            intrusionSets { pageInfo { globalCount } }
        }
        """
        
        result = self.opencti_client.query(query)
        
        if result and result.get("data"):
            data = result["data"]
            return {
                "vulnerabilities_count": data.get("vulnerabilities", {}).get("pageInfo", {}).get("globalCount", 0),
                "indicators_count": data.get("indicators", {}).get("pageInfo", {}).get("globalCount", 0),
                "attack_patterns_count": data.get("attackPatterns", {}).get("pageInfo", {}).get("globalCount", 0),
                "intrusion_sets_count": data.get("intrusionSets", {}).get("pageInfo", {}).get("globalCount", 0)
            }
            
     except Exception as e:
        self.logger.error(f"Error getting OpenCTI metrics: {e}")
        return {}
# Exemple d'utilisation
if __name__ == "__main__":
    import asyncio
    
    async def main():
        connector = OpenCTIMitreConnector()
        
        # Synchroniser MITRE avec OpenCTI
        await connector.sync_mitre_to_opencti()
        
        # Test d'enrichissement
        test_cve = {
            "id": "CVE-2023-TEST",
            "type": "vulnerability",
            "description": "Test vulnerability with PowerShell execution"
        }
        
        enriched = await connector.enrich_cve_with_mitre(test_cve)
        print(f"Enriched CVE: {enriched}")
    
    asyncio.run(main())