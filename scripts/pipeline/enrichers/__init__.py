# pipeline/enrichers/__init__.py

"""
Module d'enrichissement CTI Project

Ce module contient tous les enrichisseurs pour les données de threat intelligence :
- Base enricher : classe abstraite de base
- MITRE ATT&CK enricher : enrichissement avec le framework MITRE ATT&CK
- OpenCTI connector : connecteur pour la synchronisation avec OpenCTI
- IOC enricher : enrichissement des indicateurs de compromission
- CVE enricher : enrichissement des vulnérabilités
"""

import logging
from typing import Dict, List, Any, Optional

# Configuration du logger pour le module
logger = logging.getLogger(__name__)

# Imports des enrichisseurs
try:
    from .base_enricher import BaseEnricher
    logger.info("BaseEnricher imported successfully")
except ImportError as e:
    logger.error(f"Failed to import BaseEnricher: {e}")
    BaseEnricher = None

try:
    from .mitre_attack_enricher import MitreAttackEnricher, AttackTechnique, AttackGroup
    logger.info("MitreAttackEnricher imported successfully")
except ImportError as e:
    logger.error(f"Failed to import MitreAttackEnricher: {e}")
    MitreAttackEnricher = AttackTechnique = AttackGroup = None

try:
    from .opencti_mitre_connector import OpenCTIMitreConnector
    logger.info("OpenCTIMitreConnector imported successfully")
except ImportError as e:
    logger.error(f"Failed to import OpenCTIMitreConnector: {e}")
    OpenCTIMitreConnector = None

# Version du module
__version__ = "1.0.0"

# Exports publics
__all__ = [
    "BaseEnricher",
    "MitreAttackEnricher", 
    "AttackTechnique",
    "AttackGroup",
    "OpenCTIMitreConnector",
    "EnricherRegistry",
    "create_enricher_pipeline"
]

class EnricherRegistry:
    """Registry pour gérer les enrichisseurs disponibles"""
    
    def __init__(self):
        """Initialise le registry des enrichisseurs"""
        self._enrichers = {}
        self.logger = logging.getLogger(f"{__name__}.EnricherRegistry")
        
    def register(self, name: str, enricher_class: type, config: Optional[Dict] = None):
        """Enregistre un enrichisseur"""
        try:
            if BaseEnricher and not issubclass(enricher_class, BaseEnricher):
                raise ValueError(f"Enricher {name} must inherit from BaseEnricher")
                
            self._enrichers[name] = {
                "class": enricher_class,
                "config": config or {},
                "instance": None
            }
            self.logger.info(f"Registered enricher: {name}")
            
        except Exception as e:
            self.logger.error(f"Failed to register enricher {name}: {e}")
    
    def get_enricher(self, name: str) -> Optional[BaseEnricher]:
        """Récupère une instance d'enrichisseur"""
        try:
            if name not in self._enrichers:
                self.logger.warning(f"Enricher {name} not found in registry")
                return None
                
            enricher_info = self._enrichers[name]
            
            # Créer l'instance si elle n'existe pas
            if enricher_info["instance"] is None:
                config_path = enricher_info["config"].get("config_path", f"config/{name}_config.json")
                enricher_info["instance"] = enricher_info["class"](config_path)
                self.logger.info(f"Created instance for enricher: {name}")
                
            return enricher_info["instance"]
            
        except Exception as e:
            self.logger.error(f"Failed to get enricher {name}: {e}")
            return None
    
    def list_enrichers(self) -> List[str]:
        """Liste tous les enrichisseurs enregistrés"""
        return list(self._enrichers.keys())
    
    def remove_enricher(self, name: str) -> bool:
        """Supprime un enrichisseur du registry"""
        try:
            if name in self._enrichers:
                del self._enrichers[name]
                self.logger.info(f"Removed enricher: {name}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to remove enricher {name}: {e}")
            return False

# Instance globale du registry
registry = EnricherRegistry()

def create_enricher_pipeline(enricher_names: List[str], config: Optional[Dict] = None) -> List[BaseEnricher]:
    """
    Crée un pipeline d'enrichisseurs
    
    Args:
        enricher_names: Liste des noms d'enrichisseurs à utiliser
        config: Configuration optionnelle
        
    Returns:
        Liste des instances d'enrichisseurs
    """
    pipeline = []
    config = config or {}
    
    for name in enricher_names:
        enricher = registry.get_enricher(name)
        if enricher:
            pipeline.append(enricher)
            logger.info(f"Added {name} to pipeline")
        else:
            logger.warning(f"Could not add {name} to pipeline - enricher not found")
    
    return pipeline

def register_default_enrichers():
    """Enregistre les enrichisseurs par défaut"""
    try:
        if MitreAttackEnricher:
            registry.register("mitre_attack", MitreAttackEnricher, {
                "config_path": "config/mitre_config.json"
            })
            
        if OpenCTIMitreConnector:
            registry.register("opencti_mitre", OpenCTIMitreConnector, {
                "config_path": "config/opencti_config.json"
            })
            
        logger.info("Default enrichers registered successfully")
        
    except Exception as e:
        logger.error(f"Failed to register default enrichers: {e}")

# Enregistrer automatiquement les enrichisseurs par défaut
register_default_enrichers()

# Fonctions utilitaires
def validate_enricher_config(config: Dict) -> bool:
    """Valide la configuration d'un enrichisseur"""
    required_fields = ["name", "type", "enabled"]
    
    for field in required_fields:
        if field not in config:
            logger.error(f"Missing required field in enricher config: {field}")
            return False
    
    return True

def load_enricher_configs(config_path: str = "config/enrichers.json") -> Dict:
    """Charge les configurations des enrichisseurs depuis un fichier"""
    import json
    import os
    
    try:
        if not os.path.exists(config_path):
            logger.warning(f"Enricher config file not found: {config_path}")
            return {}
            
        with open(config_path, 'r', encoding='utf-8') as f:
            configs = json.load(f)
            
        logger.info(f"Loaded enricher configs from {config_path}")
        return configs
        
    except Exception as e:
        logger.error(f"Failed to load enricher configs: {e}")
        return {}

def get_enricher_status() -> Dict[str, Dict]:
    """Récupère le statut de tous les enrichisseurs"""
    status = {}
    
    for name in registry.list_enrichers():
        try:
            enricher = registry.get_enricher(name)
            status[name] = {
                "available": enricher is not None,
                "class": registry._enrichers[name]["class"].__name__ if enricher else "Unknown",
                "config": registry._enrichers[name]["config"]
            }
        except Exception as e:
            status[name] = {
                "available": False,
                "error": str(e)
            }
    
    return status

# Message d'initialisation
logger.info(f"CTI Project Enrichers module initialized (version {__version__})")
logger.info(f"Available enrichers: {registry.list_enrichers()}")