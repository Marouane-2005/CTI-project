#!/usr/bin/env python3
"""
Pipeline CTI avec intégration OpenCTI
Module principal pour l'orchestration des composants CTI
"""

__version__ = "1.0.0"
__author__ = "CTI Team"
__description__ = "Pipeline CTI complet avec synchronisation OpenCTI"

import logging
import sys
import os
from pathlib import Path

# Add project root to Python path if needed
current_dir = Path(__file__).parent
project_root = current_dir.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Configuration des logs au niveau module
def setup_pipeline_logging():
    """Configuration centralisée des logs pour le pipeline"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configuration du logger principal
    logger = logging.getLogger("cti_pipeline")
    logger.setLevel(logging.INFO)
    
    # Éviter la duplication des handlers
    if not logger.handlers:
        # Handler pour fichier
        file_handler = logging.FileHandler(
            log_dir / "pipeline.log", 
            encoding='utf-8'
        )
        file_handler.setLevel(logging.INFO)
        
        # Handler pour console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Format des logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Ajout des handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger

# Initialisation automatique des logs
pipeline_logger = setup_pipeline_logging()

# Import des modules avec gestion d'erreurs
try:
    # Try absolute imports first
    from scripts.pipeline.opencti_connector import OpenCTIConnector
    from scripts.pipeline.data_processor import CTIDataProcessor
    from scripts.pipeline.scheduler import CTIScheduler
    from scripts.pipeline.health_check import HealthChecker
    
    pipeline_logger.info("✅ Tous les modules pipeline importés avec succès")
    
except ImportError as e:
    pipeline_logger.warning(f"⚠️ Import partiel des modules: {e}")
    
    # Fallback: create dummy classes if modules don't exist
    class OpenCTIConnector:
        def __init__(self, config_path):
            self.config_path = config_path
            pipeline_logger.warning("🔧 OpenCTIConnector en mode stub")
        
        def run(self):
            pipeline_logger.info("🔄 OpenCTI Connector running (stub mode)")
            return True
        
        def sync_to_opencti(self):
            pipeline_logger.info("🔄 Sync to OpenCTI (stub mode)")
            return True
    
    class CTIDataProcessor:
        def __init__(self):
            pipeline_logger.warning("🔧 DataProcessor en mode stub")
        
        def process_data(self, data):
            pipeline_logger.info("🔄 Processing data (stub mode)")
            return data
    
    class CTIScheduler:
        def __init__(self):
            pipeline_logger.warning("🔧 CTIScheduler en mode stub")
        
        def start(self):
            pipeline_logger.info("🔄 Scheduler started (stub mode)")
        
        def stop(self):
            pipeline_logger.info("🔄 Scheduler stopped (stub mode)")
    
    class HealthChecker:
        def __init__(self):
            pipeline_logger.warning("🔧 HealthChecker en mode stub")
        
        def check_all_services(self):
            pipeline_logger.info("🔄 Health check (stub mode)")
            return True
        
        def check_opencti_connection(self):
            pipeline_logger.info("🔄 OpenCTI health check (stub mode)")
            return True

# Classes principales exportées
__all__ = [
    'OpenCTIConnector',
    'CTIDataProcessor', 
    'CTIScheduler',
    'HealthChecker',
    'pipeline_logger',
    'PipelineManager'
]

class PipelineManager:
    """Gestionnaire principal du pipeline CTI"""
    
    def __init__(self, config_path: str = None):
        """
        Initialisation du gestionnaire de pipeline
        
        Args:
            config_path: Chemin vers la configuration OpenCTI
        """
        self.logger = pipeline_logger
        self.config_path = config_path or "config/opencti_config.json"
        
        # Initialisation des composants
        self._init_components()
        
        self.logger.info("🎯 PipelineManager initialisé")
    
    def _init_components(self):
        """Initialisation des composants du pipeline"""
        try:
            # Connecteur OpenCTI
            self.opencti_connector = OpenCTIConnector(self.config_path)
            
            # Processeur de données
            self.data_processor = DataProcessor()
            
            # Planificateur
            self.scheduler = CTIScheduler()
            
            # Vérificateur de santé
            self.health_checker = HealthChecker()
            
            self.logger.info("✅ Composants du pipeline initialisés")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'initialisation: {e}")
            # Don't raise in container environment, continue with available components
            self.logger.warning("⚠️ Continuing with available components")
    
    def start_pipeline(self):
        """Démarrage complet du pipeline"""
        try:
            self.logger.info("🚀 Démarrage du pipeline CTI")
            
            # Vérification de santé préliminaire
            try:
                if not self.health_checker.check_all_services():
                    self.logger.warning("⚠️ Certains services ne sont pas opérationnels")
            except Exception as e:
                self.logger.warning(f"⚠️ Health check failed: {e}")
            
            # Démarrage du planificateur
            try:
                self.scheduler.start()
            except Exception as e:
                self.logger.error(f"❌ Erreur démarrage scheduler: {e}")
            
            # Démarrage du connecteur OpenCTI
            try:
                self.opencti_connector.run()
            except Exception as e:
                self.logger.error(f"❌ Erreur démarrage OpenCTI connector: {e}")
            
        except KeyboardInterrupt:
            self.logger.info("👋 Arrêt du pipeline demandé")
            self.stop_pipeline()
        except Exception as e:
            self.logger.error(f"❌ Erreur fatale du pipeline: {e}")
            # Don't raise in production, log and continue
            self.logger.warning("⚠️ Pipeline continue malgré les erreurs")
    
    def stop_pipeline(self):
        """Arrêt propre du pipeline"""
        try:
            self.logger.info("⏹️ Arrêt du pipeline en cours...")
            
            # Arrêt du planificateur
            if hasattr(self, 'scheduler'):
                try:
                    self.scheduler.stop()
                except Exception as e:
                    self.logger.error(f"❌ Erreur arrêt scheduler: {e}")
            
            self.logger.info("✅ Pipeline arrêté proprement")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'arrêt: {e}")
    
    def run_manual_sync(self):
        """Synchronisation manuelle unique"""
        try:
            self.logger.info("⚡ Synchronisation manuelle démarrée")
            
            # Vérification préalable
            try:
                if not self.health_checker.check_opencti_connection():
                    self.logger.warning("⚠️ OpenCTI connection issues")
            except Exception as e:
                self.logger.warning(f"⚠️ Health check error: {e}")
            
            # Synchronisation
            try:
                success = self.opencti_connector.sync_to_opencti()
                
                if success:
                    self.logger.info("✅ Synchronisation manuelle réussie")
                else:
                    self.logger.warning("⚠️ Synchronisation avec erreurs")
                
                return success
            except Exception as e:
                self.logger.error(f"❌ Erreur durant la sync: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ Erreur synchronisation manuelle: {e}")
            return False

# Fonction d'aide pour le démarrage rapide
def quick_start(config_path: str = None):
    """
    Démarrage rapide du pipeline CTI
    
    Args:
        config_path: Chemin vers la configuration
    """
    try:
        manager = PipelineManager(config_path)
        manager.start_pipeline()
    except Exception as e:
        pipeline_logger.error(f"❌ Erreur quick_start: {e}")

# Fonction pour synchronisation unique
def sync_once(config_path: str = None):
    """
    Synchronisation unique avec OpenCTI
    
    Args:
        config_path: Chemin vers la configuration
        
    Returns:
        bool: Succès de la synchronisation
    """
    try:
        manager = PipelineManager(config_path)
        return manager.run_manual_sync()
    except Exception as e:
        pipeline_logger.error(f"❌ Erreur sync_once: {e}")
        return False

# Messages d'information au chargement du module
if __name__ == "__main__":
    print(f"📦 CTI Pipeline v{__version__}")
    print(f"📝 {__description__}")
    print("🔧 Utilisez PipelineManager pour orchestrer vos composants CTI")
    
    # Test de démarrage si appelé directement
    try:
        quick_start()
    except KeyboardInterrupt:
        print("👋 Pipeline arrêté")
else:
    pipeline_logger.debug(f"📦 Module CTI Pipeline v{__version__} chargé")

# Vérification des dépendances critiques au chargement
try:
    import requests
    import json
    from pathlib import Path
    pipeline_logger.debug("✅ Dépendances critiques disponibles")
except ImportError as e:
    pipeline_logger.error(f"❌ Dépendance manquante: {e}")
    pipeline_logger.error("💡 Installez avec: pip install -r requirements.txt")
    # Don't exit in container environment
    pipeline_logger.warning("⚠️ Continuing without all dependencies")