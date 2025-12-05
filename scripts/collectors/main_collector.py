#!/usr/bin/env python3
"""
CTI Collector Principal avec correction d'imports
REMPLACEZ COMPLÈTEMENT le contenu de votre scripts/collectors/main_collector.py par ce code
"""

# =============================================================================
# 🔧 SECTION 1: CORRECTION DES IMPORTS (À AJOUTER EN TOUT PREMIER)
# =============================================================================
import os
import sys
from pathlib import Path

def setup_cti_imports():
    """Configuration robuste des imports pour CTI - DOIT ÊTRE EN PREMIER"""
    print("🔧 Configuration des imports CTI...")
    
    # Détection automatique des chemins
    if 'PYTHONPATH' in os.environ and '/app' in os.environ.get('PYTHONPATH', ''):
        # Mode conteneur Docker
        project_root = Path('/app')
    else:
        # Mode développement local
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
    
    # Chemins à ajouter dans l'ordre de priorité
    paths = [
        project_root,
        project_root / 'scripts',
        project_root / 'scripts' / 'utils', 
        project_root / 'scripts' / 'collectors'
    ]
    
    # Ajout au PYTHONPATH
    for path in paths:
        str_path = str(path)
        if str_path not in sys.path:
            sys.path.insert(0, str_path)
    
    # Création des fichiers __init__.py manquants
    init_files = [
        project_root / '__init__.py',
        project_root / 'scripts' / '__init__.py',
        project_root / 'scripts' / 'utils' / '__init__.py',
        project_root / 'scripts' / 'collectors' / '__init__.py',
        project_root / 'scripts' / 'analyzers' / '__init__.py',
        project_root / 'scripts' / 'generators' / '__init__.py'
    ]
    
    for init_file in init_files:
        try:
            init_file.parent.mkdir(parents=True, exist_ok=True)
            init_file.touch(exist_ok=True)
        except:
            pass  # Ignore les erreurs de permissions
    
    print(f"✅ Configuration imports: {len(paths)} chemins configurés")
    return project_root

# APPEL IMMÉDIAT de la configuration (OBLIGATOIRE)
project_root = setup_cti_imports()

# =============================================================================
# 🔧 SECTION 2: IMPORTS AVEC GESTION D'ERREURS ROBUSTE
# =============================================================================

print("📦 Chargement des modules CTI...")

# Import du logger avec fallback
try:
    from scripts.utils.logger import CTILogger
    print("✅ CTILogger importé (scripts.utils)")
except ImportError:
    try:
        from utils.logger import CTILogger  
        print("✅ CTILogger importé (utils)")
    except ImportError:
        try:
            import sys
            sys.path.append('/app/scripts/utils')
            from logger import CTILogger
            print("✅ CTILogger importé (direct)")
        except ImportError as e:
            print(f"❌ CTILogger non disponible: {e}")
            # Logger basique en fallback
            import logging
            class CTILogger:
                def __init__(self, name):
                    self.logger = logging.getLogger(name)
                    self.logger.setLevel(logging.INFO)
                    if not self.logger.handlers:
                        handler = logging.StreamHandler()
                        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                        handler.setFormatter(formatter)
                        self.logger.addHandler(handler)
                
                def info(self, msg): self.logger.info(msg)
                def error(self, msg): self.logger.error(msg)
                def warning(self, msg): self.logger.warning(msg)

# Import du DatabaseManager avec fallback
DatabaseManager = None
database_import_error = None

try:
    from scripts.utils.database import DatabaseManager
    print("✅ DatabaseManager importé (scripts.utils)")
except ImportError as e1:
    database_import_error = str(e1)
    try:
        from utils.database import DatabaseManager
        print("✅ DatabaseManager importé (utils)")
    except ImportError as e2:
        try:
            sys.path.append('/app/scripts/utils')
            from database import DatabaseManager
            print("✅ DatabaseManager importé (direct)")
        except ImportError as e3:
            print(f"❌ DatabaseManager non disponible:")
            print(f"   - scripts.utils.database: {e1}")
            print(f"   - utils.database: {e2}")
            print(f"   - database direct: {e3}")
            DatabaseManager = None

# Import des collectors avec gestion d'erreurs individuelles
collectors_imported = {}

collector_configs = [
    ('scripts.collectors.rss_collector', 'RSSCollector'),
    ('scripts.collectors.otx_collector', 'OTXCollector'), 
    ('scripts.collectors.twitter_collector', 'TwitterCollector'),
    ('scripts.collectors.telegram_collector', 'TelegramCollector'),
    ('scripts.collectors.abuse_ch_collector', 'AbuseCHCollector')
]

for module_path, class_name in collector_configs:
    try:
        module = __import__(module_path, fromlist=[class_name])
        collectors_imported[class_name] = getattr(module, class_name)
        print(f"✅ {class_name} importé avec succès")
    except ImportError as e:
        print(f"❌ Impossible d'importer {class_name}: {e}")
        collectors_imported[class_name] = None

# =============================================================================
# 🔧 SECTION 3: FONCTION DE DIAGNOSTIC COMPLÈTE
# =============================================================================

def diagnose_environment():
    """Diagnostic complet de l'environnement CTI"""
    print("\n" + "="*60)
    print("=== DIAGNOSTIC ENVIRONNEMENT CTI ===")
    print("="*60)
    
    import platform
    print(f"Python version: {platform.python_version()}")
    print(f"Répertoire de travail: {os.getcwd()}")
    print(f"Script path: {__file__}")
    print(f"Script directory: {Path(__file__).parent}")
    
    print(f"\nConfiguration des chemins...")
    utils_path = project_root / 'scripts' / 'utils'
    if utils_path.exists():
        print(f"✅ Structure 1 détectée: utils trouvé dans {utils_path}")
    else:
        print(f"❌ Structure utils non trouvée dans {utils_path}")
    
    print(f"\nChemins Python configurés (sys.path):")
    for i, path in enumerate(sys.path[:10]):
        print(f"  {i}: {path}")
    
    print(f"\nTest des imports après configuration:")
    test_results = [
        ("utils.logger", CTILogger is not None and hasattr(CTILogger, '__module__')),
        ("utils.database", DatabaseManager is not None),
        ("collectors.rss_collector", collectors_imported.get('RSSCollector') is not None),
        ("collectors.otx_collector", collectors_imported.get('OTXCollector') is not None),
        ("collectors.twitter_collector", collectors_imported.get('TwitterCollector') is not None),
        ("collectors.telegram_collector", collectors_imported.get('TelegramCollector') is not None),
        ("collectors.abuse_ch_collector", collectors_imported.get('AbuseCHCollector') is not None)
    ]
    
    for module_name, is_available in test_results:
        status = "✅" if is_available else "❌"
        error_info = ""
        if not is_available and module_name == "utils.database":
            error_info = f": {database_import_error}"
        print(f"  {status} {module_name}{error_info}")
    
    # Exploration détaillée des répertoires
    print(f"\nExploration des répertoires:")
    dirs_to_check = [
        project_root / 'scripts' / 'utils',
        project_root / 'scripts' / 'collectors' / 'utils',
        project_root / 'scripts' / 'collectors' / '..' / 'utils',
        project_root / 'scripts' / 'collectors' / '..' / 'scripts' / 'utils'
    ]
    
    for dir_path in dirs_to_check:
        try:
            resolved_path = dir_path.resolve()
            if resolved_path.exists():
                print(f"\n✅ Répertoire utils trouvé: {resolved_path}")
                files = [f.name for f in resolved_path.iterdir() if f.is_file()]
                for file_name in sorted(files):
                    print(f"    {file_name}")
            else:
                print(f"❌ Répertoire utils non trouvé: {resolved_path}")
        except Exception as e:
            print(f"❌ Erreur exploration {dir_path}: {e}")

# =============================================================================
# 🔧 SECTION 4: LOGIQUE PRINCIPALE DU COLLECTOR
# =============================================================================

class CTIMainCollector:
    """Collector principal CTI avec gestion d'erreurs robuste"""
    
    def __init__(self):
        """Initialisation du collector principal"""
        self.logger = CTILogger("main_collector")
        self.db_manager = None
        self.collectors = {}
        self.is_initialized = False
        
        self._initialize_components()
        self.collector_methods = {
        'OTXCollector': 'collect_recent_pulses',
        'TwitterCollector': 'collect_threat_tweets', 
        'TelegramCollector': 'run_collect',
        'AbuseCHCollector': 'collect_all_feeds',
        'RSSCollector': 'collect_all_feeds'
    }
    def _initialize_components(self):
        """Initialisation des composants avec gestion d'erreurs"""
        try:
            # Initialisation du DatabaseManager si disponible
            if DatabaseManager is not None:
                self.db_manager = DatabaseManager()
                self.logger.info("✅ DatabaseManager initialisé")
            else:
                self.logger.warning("⚠️ DatabaseManager non disponible")
            
            # Initialisation des collectors disponibles
            for collector_name, collector_class in collectors_imported.items():
                if collector_class is not None:
                    try:
                        self.collectors[collector_name] = collector_class()
                        self.logger.info(f"✅ {collector_name} initialisé")
                    except Exception as e:
                        self.logger.error(f"❌ Erreur initialisation {collector_name}: {e}")
                else:
                    self.logger.warning(f"⚠️ {collector_name} non disponible")
            
            self.is_initialized = True
            self.logger.info(f"🎯 CTI Collector initialisé avec {len(self.collectors)} collectors")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'initialisation: {e}")
            import traceback
            traceback.print_exc()
    
    # Remplacez la méthode run_collection_cycle dans votre main_collector.py
    def run_continuous(self):
     import time
    
     self.logger.info("🔄 Mode continu activé")
    
     try:
        while True:
            self.run_collection_cycle()
            
            # Pause entre les cycles (configurable)
            sleep_time = int(os.getenv('COLLECTION_INTERVAL', 3600))  # 1 heure par défaut
            self.logger.info(f"⏰ Pause de {sleep_time} secondes")
            time.sleep(sleep_time)
            
     except KeyboardInterrupt:
        self.logger.info("👋 Arrêt demandé par l'utilisateur")
     except Exception as e:
        self.logger.error(f"❌ Erreur fatale: {e}")
        import traceback
        traceback.print_exc()
    
    def run_collection_cycle(self):
      if not self.is_initialized:
        self.logger.error("❌ Collector non initialisé")
        return False

      self.logger.info("🚀 Début du cycle de collecte")
      success_count = 0

    # Mapping des méthodes correctes
      collector_methods = {
        'RSSCollector': ('collect_all_feeds', {}),
        'OTXCollector': ('collect_recent_pulses', {'days_back': 7}),
        'TwitterCollector': ('collect_threat_tweets', {'days_back': 1, 'max_per_keyword': 1}),
        'TelegramCollector': ('run_collect', {'days_back': 1}),
        'AbuseCHCollector': ('collect_all_feeds', {})
    }

      for collector_name, collector in self.collectors.items():
        try:
            self.logger.info(f"🔄 Exécution de {collector_name}")
            
            if collector_name in collector_methods:
                method_name, params = collector_methods[collector_name]
                
                if hasattr(collector, method_name):
                    method = getattr(collector, method_name)
                    result = method(**params)
                    
                    # Vérifier le succès selon le type de retour
                    if isinstance(result, list):
                        success = len(result) > 0
                        self.logger.info(f"✅ {collector_name}: {len(result)} éléments collectés")
                    else:
                        success = bool(result)
                        self.logger.info(f"✅ {collector_name} terminé")
                    
                    if success:
                        success_count += 1
                else:
                    self.logger.warning(f"⚠️ Méthode {method_name} non trouvée pour {collector_name}")
            else:
                self.logger.warning(f"⚠️ {collector_name} non configuré dans le mapping")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur dans {collector_name}: {e}")

      self.logger.info(f"📊 Cycle terminé: {success_count}/{len(self.collectors)} collectors réussis")
      return success_count > 0

    # À ajouter dans votre main_collector.py existant
    import sys
    import os

    def notify_dashboard(self, indicator_data):
     try:
        # Import du backend dashboard
        dashboard_path = os.path.join(os.path.dirname(__file__), '..', '..', 'dashboard', 'backend')
        sys.path.append(dashboard_path)
        
        from app import broadcast_threat_update
        
        # Formatage pour le dashboard
        dashboard_data = {
            'type': 'new_indicator',
            'source': self.source_name,
            'data': indicator_data,
            'timestamp': datetime.now().isoformat()
        }
        
        # Envoi temps réel
        broadcast_threat_update(dashboard_data)
        
     except Exception as e:
        self.logger.warning(f"Erreur notification dashboard: {e}")

# À intégrer dans vos méthodes de collecte existantes
def process_indicators(self, indicators):
    """Méthode existante à modifier"""
    processed_indicators = []
    
    for indicator in indicators:
        # Votre logique de traitement existante
        processed = self.existing_processing_logic(indicator)
        
        # Nouveau : notification dashboard
        self.notify_dashboard(processed)
        
        processed_indicators.append(processed)
    
    return processed_indicators
# =============================================================================
# 🔧 SECTION 5: POINT D'ENTRÉE PRINCIPAL
# =============================================================================

def main():
    """Point d'entrée principal du collector"""
    
    # Diagnostic si demandé
    if len(sys.argv) > 1 and sys.argv[1] == 'diagnose':
        diagnose_environment()
        return 0
    
    # Mode test rapide
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        print("🧪 Mode test activé")
        collector = CTIMainCollector()
        if collector.is_initialized:
            print("✅ Test d'initialisation réussi")
            return 0
        else:
            print("❌ Test d'initialisation échoué")
            return 1
    
    # Vérification des prérequis critiques
    if DatabaseManager is None:
        print("❌ ERREUR CRITIQUE: DatabaseManager requis mais non disponible")
        print("💡 Solutions possibles:")
        print("   1. Vérifiez que le fichier scripts/utils/database.py existe")
        print("   2. Vérifiez les dépendances Python (psycopg2, sqlalchemy)")
        print("   3. Exécutez 'python -m scripts.collectors.main_collector diagnose'")
        return 1
    
    print("🚀 Démarrage du CTI Collector...")
    
    try:
        # Création et lancement du collector principal
        collector = CTIMainCollector()
        
        if not collector.is_initialized:
            print("❌ Échec de l'initialisation du collector")
            return 1
        
        # Mode d'exécution basé sur les variables d'environnement
        mode = os.getenv('COLLECTOR_MODE', 'continuous').lower()
        
        if mode == 'single':
            # Exécution unique
            print("🔄 Mode exécution unique")
            success = collector.run_collection_cycle()
            return 0 if success else 1
        else:
            # Exécution continue (par défaut)
            print("🔄 Mode exécution continue")
            collector.run_continuous()
            return 0
            
    except Exception as e:
        print(f"❌ Erreur fatale durant l'exécution: {e}")
        import traceback
        traceback.print_exc()
        return 1

# =============================================================================
# 🔧 SECTION 6: EXÉCUTION
# =============================================================================

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)