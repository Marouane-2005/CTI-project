#!/usr/bin/env python3
# pipeline/enrichers/run_mitre_enricher.py

"""
Script principal pour démarrer l'enrichisseur MITRE ATT&CK
Usage: 
    python -m pipeline.enrichers.run_mitre_enricher
    ou
    python pipeline/enrichers/run_mitre_enricher.py
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au PYTHONPATH
current_dir = Path(__file__).parent.parent.parent.absolute()
sys.path.insert(0, str(current_dir))

try:
    from pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher
    from pipeline.enrichers.mitre_postgres_enricher import MitrePostgresEnricher
    from pipeline.enrichers.opencti_mitre_connector import OpenCTIMitreConnector
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running from the correct directory and all dependencies are installed")
    sys.exit(1)

def setup_logging(log_file: str = "/app/logs/mitre_enricher.log") -> logging.Logger:
    """Configure le logging"""
    # Créer le répertoire de logs si nécessaire
    log_dir = Path(log_file).parent
    
    # Créer le répertoire avec gestion d'erreur
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        print(f"✅ Log directory created/verified: {log_dir}")
    except PermissionError as e:
        print(f"❌ Cannot create log directory {log_dir}: {e}")
        # Fallback vers un répertoire temporaire
        import tempfile
        log_dir = Path(tempfile.gettempdir()) / "cti_logs"
        log_dir.mkdir(exist_ok=True)
        log_file = str(log_dir / "mitre_enricher.log")
        print(f"⚠️ Using fallback log directory: {log_file}")
    
    # Configuration du logger
    logger = logging.getLogger("mitre_enricher")
    logger.setLevel(logging.INFO)
    
    # Supprimer les handlers existants
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Handler pour fichier (avec gestion d'erreur)
    try:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Format des logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    except PermissionError:
        print(f"⚠️ Cannot write to log file {log_file}, using console only")
    
    # Handler pour console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def verify_data_directory():
    """Vérifie et prépare le répertoire de données"""
    data_dirs_to_try = [
        os.getenv("MITRE_DATA_DIR", "/app/data"),
        "/app/data",
        "data",
        "/tmp/cti_data",
        os.path.expanduser("~/.cti/data")
    ]
    
    for data_dir in data_dirs_to_try:
        try:
            data_path = Path(data_dir)
            data_path.mkdir(parents=True, exist_ok=True)
            
            # Test d'écriture
            test_file = data_path / "test_write.tmp"
            test_file.write_text("test")
            test_file.unlink()
            
            print(f"✅ Data directory verified: {data_path}")
            os.environ["MITRE_DATA_DIR"] = str(data_path)
            return str(data_path)
            
        except (PermissionError, OSError) as e:
            print(f"⚠️ Cannot use data directory {data_dir}: {e}")
            continue
    
    raise RuntimeError("❌ No writable data directory found!")

async def test_mitre_enricher(enricher: MitreAttackEnricher, logger: logging.Logger):
    """Test l'enrichisseur MITRE"""
    logger.info("🧪 Testing MITRE enrichment capabilities...")
    
    # Test CVE
    test_cve = {
        "id": "CVE-2023-TEST",
        "type": "vulnerability",
        "description": "Test vulnerability with command injection and PowerShell execution capabilities for remote code execution"
    }
    
    enriched_cve = await enricher.enrich(test_cve)
    mitre_data = enriched_cve.get('mitre_attack', {})
    techniques_count = len(mitre_data.get('techniques', []))
    
    logger.info(f"✅ CVE enrichment test: {techniques_count} techniques mapped")
    if techniques_count > 0:
        for technique in mitre_data.get('techniques', [])[:3]:
            logger.info(f"   - {technique.get('technique_id')}: {technique.get('name')} (confidence: {technique.get('confidence'):.2f})")
    
    # Test IOC
    test_ioc = {
        "id": "IOC-TEST-001",
        "type": "indicator",
        "ioc_type": "domain",
        "value": "malicious-powershell-domain.com",
        "hash": "test_hash_123"
    }
    
    enriched_ioc = await enricher.enrich(test_ioc)
    ioc_mitre_data = enriched_ioc.get('mitre_attack', {})
    ioc_techniques_count = len(ioc_mitre_data.get('techniques', []))
    
    logger.info(f"✅ IOC enrichment test: {ioc_techniques_count} techniques mapped")
    if ioc_techniques_count > 0:
        for technique in ioc_mitre_data.get('techniques', [])[:3]:
            logger.info(f"   - {technique.get('technique_id')}: {technique.get('name')} (confidence: {technique.get('confidence'):.2f})")

async def test_opencti_connector(connector: OpenCTIMitreConnector, logger: logging.Logger):
    """Test le connecteur OpenCTI"""
    logger.info("🔗 Testing OpenCTI MITRE connector...")
    
    try:
        # Test d'enrichissement CVE
        test_cve = {
            "id": "CVE-2023-OPENCTI-TEST",
            "type": "vulnerability",
            "description": "Test vulnerability for OpenCTI integration with registry modification and file transfer capabilities"
        }
        
        enriched_cve = await connector.enrich(test_cve)
        logger.info(f"✅ OpenCTI CVE enrichment completed")
        
        # Test d'enrichissement IOC
        test_ioc = {
            "id": "IOC-OPENCTI-TEST-001",
            "type": "indicator",
            "ioc_type": "file_hash",
            "value": "d41d8cd98f00b204e9800998ecf8427e",
            "hash": "opencti_test_hash"
        }
        
        enriched_ioc = await connector.enrich(test_ioc)
        logger.info(f"✅ OpenCTI IOC enrichment completed")
        
    except Exception as e:
        logger.warning(f"⚠️ OpenCTI connector test failed (this is normal if OpenCTI is not configured): {e}")

async def main():
    """Fonction principale"""
    logger = None
    enricher = None
    try:
        # PREMIÈRE ÉTAPE : Vérifier les répertoires AVANT le logging
        print("🔍 Verifying data directory permissions...")
        data_dir = verify_data_directory()
        print(f"✅ Data directory ready: {data_dir}")
        
        # Configuration du logging
        log_file = os.getenv("MITRE_LOG_FILE", "/app/logs/mitre_enricher.log")
        logger = setup_logging(log_file)
        logger.info("🚀 Starting MITRE ATT&CK Enricher...")
        logger.info(f"📁 Using data directory: {data_dir}")
        
        # Initialiser l'enrichisseur MITRE
        try:
           logger.info("📚 Initializing MITRE ATT&CK PostgreSQL Enricher...")
           enricher = MitrePostgresEnricher()
           logger.info("✅ MITRE ATT&CK PostgreSQL Enricher initialized")
        except Exception as e:
          logger.error(f"❌ Failed to initialize MITRE PostgreSQL Enricher: {e}")
            # Fallback vers l'enrichisseur de base si PostgreSQL échoue
          logger.info("📚 Falling back to basic MITRE ATT&CK Enricher...")
          enricher = MitreAttackEnricher()
          logger.info("✅ Basic MITRE ATT&CK Enricher initialized")
        
        if isinstance(enricher, MitrePostgresEnricher):
            logger.info("🔌 Testing PostgreSQL connection...")
            try:
                with enricher.get_db_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("SELECT version();")
                        pg_version = cursor.fetchone()[0]
                        logger.info(f"✅ PostgreSQL connected: {pg_version}")
            except Exception as e:
                logger.error(f"❌ PostgreSQL connection failed: {e}")
                raise

        if os.getenv("MITRE_UPDATE_DATA", "true").lower() == "true":
            logger.info("📥 Updating MITRE ATT&CK data to PostgreSQL...")
            success = await enricher.update_mitre_data()
            
            if success:
                logger.info("✅ MITRE ATT&CK data updated successfully in PostgreSQL")
                
                # ✅ AJOUT : Vérifier les données stockées
                logger.info("📊 Checking stored data in PostgreSQL...")
                with enricher.get_db_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute("SELECT COUNT(*) FROM mitre_techniques")
                        tech_count = cursor.fetchone()[0]
                        cursor.execute("SELECT COUNT(*) FROM mitre_groups")
                        group_count = cursor.fetchone()[0]
                        cursor.execute("SELECT COUNT(*) FROM mitre_software")
                        software_count = cursor.fetchone()[0]
                        
                        logger.info(f"📈 Data stored: {tech_count} techniques, {group_count} groups, {software_count} software")
            else:
                logger.error("❌ Failed to update MITRE ATT&CK data")
        else:
            logger.info("⏭️ Skipping MITRE data update (MITRE_UPDATE_DATA=false)")
        
         # ✅ AJOUT : Test d'enrichissement CVE avec PostgreSQL
        logger.info("🧪 Testing CVE enrichment with PostgreSQL...")
        test_cve = {
            "id": "CVE-2023-TEST-PG",
            "type": "vulnerability",
            "description": "Test vulnerability with command injection and PowerShell execution capabilities for remote code execution",
            "cvss_score": 8.5
        }
        
        enriched_cve = await enricher.enrich_cve(test_cve)
        mitre_techniques = enriched_cve.get('mitre_techniques', [])
        logger.info(f"✅ CVE enrichment test: {len(mitre_techniques)} techniques mapped")
        
        if mitre_techniques:
            for i, tech in enumerate(mitre_techniques[:3]):
                logger.info(f"   {i+1}. {tech.get('id')}: {tech.get('name')} (tactic: {tech.get('tactic')})")
        
        # ✅ AJOUT : Test d'enrichissement IOC avec PostgreSQL  
        logger.info("🧪 Testing IOC enrichment with PostgreSQL...")
        test_ioc = {
            "id": "IOC-TEST-PG-001",
            "type": "indicator",
            "value": "malicious-powershell-domain.com",
            "ioc_type": "domain"
        }
        
        enriched_ioc = await enricher.enrich_ioc(test_ioc)
        ioc_techniques = enriched_ioc.get('mitre_techniques', [])
        logger.info(f"✅ IOC enrichment test: {len(ioc_techniques)} techniques mapped")
        
        if ioc_techniques:
            for i, tech in enumerate(ioc_techniques[:3]):
                logger.info(f"   {i+1}. {tech.get('id')}: {tech.get('name')} (tactic: {tech.get('tactic')})")
         
        
        
        
        
        if os.getenv("OPENCTI_ENABLED", "false").lower() == "true":
          logger.info("🔗 Initializing OpenCTI MITRE connector...")
    
    # Délai d'attente pour OpenCTI
          logger.info("⏳ Waiting for OpenCTI to be fully ready...")
          await asyncio.sleep(30)  # Attendre 30 secondes
    
          max_wait_attempts = 6  # 6 x 10s = 60s maximum
          for wait_attempt in range(max_wait_attempts):
           try:
            # Tester si OpenCTI répond
            import requests
            response = requests.get(f"{os.getenv('OPENCTI_URL', 'http://opencti:8080')}/health", timeout=5)
            if response.status_code == 200:
                logger.info("✅ OpenCTI is responding")
                break
           except Exception:
            if wait_attempt < max_wait_attempts - 1:
                logger.info(f"⏳ OpenCTI not ready yet, waiting... ({wait_attempt + 1}/{max_wait_attempts})")
                await asyncio.sleep(10)
            else:
                logger.warning("⚠️ OpenCTI might not be ready, proceeding anyway...")
                break
    
          opencti_connector = OpenCTIMitreConnector("opencti_mitre_config.json")
            
            # Test de synchronisation avec retry
          if os.getenv("OPENCTI_SYNC", "false").lower() == "true":
                logger.info("🔄 Synchronizing MITRE data to OpenCTI...")
                
                # Retry logic
                max_sync_retries = 3
                for sync_attempt in range(max_sync_retries):
                    sync_success = await opencti_connector.sync_mitre_to_opencti()
                    if sync_success:
                        logger.info("✅ MITRE data synchronized to OpenCTI")
                        break
                    else:
                        if sync_attempt < max_sync_retries - 1:
                            logger.warning(f"Sync failed, retrying... (attempt {sync_attempt + 1}/{max_sync_retries})")
                            await asyncio.sleep(5)
                        else:
                            logger.error("❌ Failed to synchronize MITRE data to OpenCTI after all retries")
            
          await test_opencti_connector(opencti_connector, logger)
        else:
            logger.info("⏭️ OpenCTI integration disabled (OPENCTI_ENABLED=false)")
       
       # Les tests d'enrichissement ont déjà été effectués plus haut
            logger.info("🔗 Enriching MITRE data with relationships...") 
            await enricher.enrich_mitre_relationships()
        
        # Générer des statistiques
        logger.info("📊 Generating MITRE ATT&CK statistics...")
        stats = enricher.get_attack_statistics()
        logger.info(f"📈 Statistics: {stats.get('total_techniques', 0)} total techniques, "
                   f"{stats.get('covered_techniques', 0)} covered, "
                   f"{stats.get('coverage_score', 0)}% coverage")
        
        # Test du connecteur OpenCTI (optionnel)
        if os.getenv("OPENCTI_ENABLED", "false").lower() == "true":
            logger.info("🔗 Initializing OpenCTI MITRE connector...")
            opencti_connector = OpenCTIMitreConnector()
            
            # Test de synchronisation (optionnel)
    
        
        # Mode continu (optionnel)
        if os.getenv("MITRE_CONTINUOUS_MODE", "false").lower() == "true":
            logger.info("🔄 Running in continuous mode...")
            update_interval = int(os.getenv("MITRE_UPDATE_INTERVAL", "3600"))
            
            while True:
                try:
                    await asyncio.sleep(update_interval)
                    logger.info("🔄 Periodic MITRE data update...")
                    await enricher.update_mitre_data()
                    
                    stats = enricher.get_attack_statistics()
                    logger.info(f"📈 Updated statistics: {stats.get('coverage_score', 0)}% coverage")
                    
                except KeyboardInterrupt:
                    logger.info("🛑 Received interrupt signal, stopping continuous mode...")
                    break
        else:
            logger.info("✅ MITRE ATT&CK Enricher completed successfully")
            
    except KeyboardInterrupt:
        if logger:
            logger.info("🛑 Received interrupt signal, shutting down...")
        else:
            print("🛑 Received interrupt signal, shutting down...")
    except Exception as e:
        if logger:
            logger.error(f"❌ Fatal error in MITRE enricher: {e}")
            import traceback
            logger.error(traceback.format_exc())
        else:
            print(f"❌ Fatal error in MITRE enricher: {e}")
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Configuration de l'environnement
    os.environ.setdefault("PYTHONPATH", str(Path(__file__).parent.parent.parent.absolute()))
    os.environ.setdefault("MITRE_FORCE_UPDATE", "false")     # Force la mise à jour
    os.environ.setdefault("OPENCTI_FORCE_REFRESH", "false")  # Force le refresh OpenCTI
    os.environ.setdefault("OPENCTI_CLEANUP_BEFORE_SYNC", "false")  # ✅ NOUVEAU
    # Variables d'environnement corrigées
    os.environ.setdefault("MITRE_UPDATE_DATA", "true")
    os.environ.setdefault("MITRE_CONTINUOUS_MODE", "false")
    os.environ.setdefault("OPENCTI_ENABLED", "true")  # Activer OpenCTI
    os.environ.setdefault("OPENCTI_SYNC", "true")     # Activer la sync
    os.environ.setdefault("OPENCTI_URL", "http://opencti:8080")  # Bonne URL
    os.environ.setdefault("OPENCTI_TOKEN", "dd817c8c-3123-4b18-a3b6-24f4d0ef8f90")
    os.environ.setdefault("MITRE_LOG_FILE", "/app/logs/mitre_enricher.log")
    os.environ.setdefault("MITRE_DATA_DIR", "/app/data")
    
    # Afficher la configuration
    print("🔧 MITRE ATT&CK Enricher Configuration:")
    print(f"   📁 Data directory: {os.getenv('MITRE_DATA_DIR')}")
    print(f"   📝 Log file: {os.getenv('MITRE_LOG_FILE')}")
    print(f"   🔄 Update data: {os.getenv('MITRE_UPDATE_DATA')}")
    print(f"   🌐 Continuous mode: {os.getenv('MITRE_CONTINUOUS_MODE')}")
    print(f"   🔗 OpenCTI enabled: {os.getenv('OPENCTI_ENABLED')}")
    print("")
    
    # Démarrage
    asyncio.run(main())