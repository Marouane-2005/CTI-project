# pipeline/enrichers/mitre_postgres_enricher.py

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import hashlib

# Gestion conditionnelle des imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.getLogger(__name__).warning("requests module not available")

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor, Json
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False
    logging.getLogger(__name__).warning("psycopg2 module not available")

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

class MitrePostgresEnricher(BaseEnricher):
    """Enrichisseur MITRE ATT&CK avec stockage PostgreSQL"""
    
    def __init__(self, config_path: str = "config/mitre_config.json"):
        super().__init__(config_path)
        self._ensure_default_config()
        self.logger = logging.getLogger(__name__)
        
        # Configuration PostgreSQL
        self.db_config = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': int(os.getenv('DB_PORT', 5432)),
            'database': os.getenv('DB_NAME', 'cti_db'),
            'user': os.getenv('DB_USER', 'cti_user'),
            'password': os.getenv('DB_PASSWORD', 'cti_password')
        }
        
        self.base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        
        # Vérifier les dépendances
        if not PSYCOPG2_AVAILABLE:
            self.logger.error("psycopg2 not available. Install with: pip install psycopg2-binary")
            raise ImportError("psycopg2 required for PostgreSQL support")
        
        # Initialiser la base de données
        self._init_database()
    
    def get_db_connection(self):
      try:
        conn = psycopg2.connect(**self.db_config)
        # 🔥 IMPORTANT: S'assurer que autocommit est désactivé pour les transactions
        conn.autocommit = False
        return conn
      except Exception as e:
        self.logger.error(f"Failed to connect to PostgreSQL: {e}")
        raise
    
    def _init_database(self):
        """Initialise les tables PostgreSQL pour MITRE ATT&CK"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Créer les tables (utilise le script SQL de l'artifact précédent)
                    self._create_mitre_tables(cursor)
                    conn.commit()
                    self.logger.info("✅ PostgreSQL tables initialized successfully")
                    
        except Exception as e:
            self.logger.error(f"Error initializing PostgreSQL database: {e}")
            raise
    
    def _create_mitre_tables(self, cursor):
        """Créer toutes les tables MITRE dans PostgreSQL"""
        
        # Table des techniques
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_techniques (
                id VARCHAR(20) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                tactic VARCHAR(100),
                platforms JSONB,
                kill_chain_phases JSONB,
                parent_technique VARCHAR(20),
                is_subtechnique BOOLEAN DEFAULT FALSE,
                external_references JSONB,
                x_mitre_data_sources JSONB,
                x_mitre_detection TEXT,
                x_mitre_version VARCHAR(10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table des groupes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_groups (
                id VARCHAR(20) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                aliases JSONB,
                description TEXT,
                associated_techniques JSONB,
                associated_software JSONB,
                external_references JSONB,
                x_mitre_version VARCHAR(10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table des logiciels
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_software (
                id VARCHAR(20) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                type VARCHAR(50),
                aliases JSONB,
                description TEXT,
                platforms JSONB,
                associated_techniques JSONB,
                associated_groups JSONB,
                external_references JSONB,
                x_mitre_version VARCHAR(10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Table de mapping CVE -> Techniques
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_technique_mapping (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(20) NOT NULL,
                technique_id VARCHAR(20) NOT NULL,
                confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
                mapping_method VARCHAR(50),
                matched_keywords JSONB,
                cvss_score DECIMAL(3,1),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(cve_id, technique_id)
            )
        """)
        
        # Table de mapping IOC -> Techniques
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc_technique_mapping (
                id SERIAL PRIMARY KEY,
                ioc_hash VARCHAR(255) NOT NULL,
                ioc_type VARCHAR(50),
                ioc_value TEXT,
                technique_id VARCHAR(20) NOT NULL,
                confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
                mapping_method VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(ioc_hash, technique_id)
            )
        """)
        
        # Table des relations MITRE
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_relationships (
                id SERIAL PRIMARY KEY,
                source_ref VARCHAR(255) NOT NULL,
                target_ref VARCHAR(255) NOT NULL,
                relationship_type VARCHAR(50) NOT NULL,
                description TEXT,
                source_name VARCHAR(255),
                target_name VARCHAR(255),
                confidence DECIMAL(3,2),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                
                UNIQUE(source_ref, target_ref, relationship_type)
            )
        """)
        
        # Table de log des synchronisations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mitre_sync_log (
                id SERIAL PRIMARY KEY,
                sync_type VARCHAR(50) NOT NULL,
                framework VARCHAR(50),
                total_processed INTEGER DEFAULT 0,
                successful_inserts INTEGER DEFAULT 0,
                successful_updates INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                sync_status VARCHAR(20) DEFAULT 'running',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                error_details TEXT
            )
        """)
        
        # Table de cache pour les enrichissements
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS enrichment_cache (
                id SERIAL PRIMARY KEY,
                data_id VARCHAR(255) NOT NULL,
                data_type VARCHAR(50) NOT NULL,
                enrichment_type VARCHAR(50) NOT NULL,
                enriched_data JSONB,
                confidence_score DECIMAL(3,2),
                techniques_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                
                UNIQUE(data_id, enrichment_type)
            )
        """)
        
        # Créer les index
        self._create_indexes(cursor)
    
    def _create_indexes(self, cursor):
        """Créer les index pour optimiser les performances"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_techniques_tactic ON mitre_techniques(tactic)",
            "CREATE INDEX IF NOT EXISTS idx_techniques_parent ON mitre_techniques(parent_technique)",
            "CREATE INDEX IF NOT EXISTS idx_techniques_subtechnique ON mitre_techniques(is_subtechnique)",
            "CREATE INDEX IF NOT EXISTS idx_cve_mapping_cve ON cve_technique_mapping(cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_cve_mapping_technique ON cve_technique_mapping(technique_id)",
            "CREATE INDEX IF NOT EXISTS idx_cve_mapping_confidence ON cve_technique_mapping(confidence)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_mapping_hash ON ioc_technique_mapping(ioc_hash)",
            "CREATE INDEX IF NOT EXISTS idx_ioc_mapping_technique ON ioc_technique_mapping(technique_id)",
            "CREATE INDEX IF NOT EXISTS idx_relationships_source ON mitre_relationships(source_ref)",
            "CREATE INDEX IF NOT EXISTS idx_relationships_target ON mitre_relationships(target_ref)",
            "CREATE INDEX IF NOT EXISTS idx_enrichment_cache_data_id ON enrichment_cache(data_id)",
            "CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires ON enrichment_cache(expires_at)"
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except Exception as e:
                self.logger.warning(f"Error creating index: {e}")
    
    async def update_mitre_data(self) -> bool:
      if not REQUESTS_AVAILABLE:
        self.logger.error("requests module not available")
        return False
    
    # AJOUT : Log de début
      self.logger.info("🚀 Starting MITRE data update process...")
    
      sync_id = await self._start_sync_log("full_update")
    
      try:
        frameworks = self.config.get("frameworks", ["enterprise-attack"])
        self.logger.info(f"📚 Processing frameworks: {frameworks}")
        
        total_stats = {"techniques": 0, "groups": 0, "software": 0, "relationships": 0, "errors": 0}
        
        for framework in frameworks:
            self.logger.info(f"🔄 Processing framework: {framework}")
            framework_stats = await self._download_and_store_framework(framework)
            self.logger.info(f"📊 Framework {framework} stats: {framework_stats}")
            
            for key in total_stats:
                total_stats[key] += framework_stats.get(key, 0)
        
        # AJOUT : Log des stats finales
        self.logger.info(f"📈 Total stats: {total_stats}")
        
        await self._complete_sync_log(sync_id, total_stats)
        
        # AJOUT : Vérification finale
        with self.get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) FROM mitre_techniques")
                final_count = cursor.fetchone()[0]
                self.logger.info(f"🎯 Final verification: {final_count} techniques in database")
        
        return True
        
      except Exception as e:
        await self._error_sync_log(sync_id, str(e))
        self.logger.error(f"❌ Update failed: {e}")
        import traceback
        self.logger.error(traceback.format_exc())
        return False
    
    async def _start_sync_log(self, sync_type: str) -> int:
        """Démarre un log de synchronisation"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO mitre_sync_log (sync_type, sync_status, started_at)
                        VALUES (%s, 'running', %s)
                        RETURNING id
                    """, (sync_type, datetime.now()))
                    
                    sync_id = cursor.fetchone()[0]
                    conn.commit()
                    return sync_id
                    
        except Exception as e:
            self.logger.error(f"Error starting sync log: {e}")
            return 0
    
    async def _complete_sync_log(self, sync_id: int, stats: Dict):
        """Complète un log de synchronisation"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE mitre_sync_log 
                        SET sync_status = 'completed',
                            completed_at = %s,
                            total_processed = %s,
                            successful_inserts = %s,
                            successful_updates = %s,
                            errors = %s
                        WHERE id = %s
                    """, (
                        datetime.now(),
                        sum([stats.get(k, 0) for k in ["techniques", "groups", "software", "relationships"]]),
                        stats.get("techniques", 0) + stats.get("groups", 0) + stats.get("software", 0),
                        0,  # À implémenter si besoin
                        stats.get("errors", 0),
                        sync_id
                    ))
                    conn.commit()
                    
        except Exception as e:
            self.logger.error(f"Error completing sync log: {e}")
    
    async def _error_sync_log(self, sync_id: int, error_msg: str):
        """Marque un log de synchronisation comme en erreur"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE mitre_sync_log 
                        SET sync_status = 'failed',
                            completed_at = %s,
                            error_details = %s
                        WHERE id = %s
                    """, (datetime.now(), error_msg, sync_id))
                    conn.commit()
                    
        except Exception as e:
            self.logger.error(f"Error updating sync log: {e}")
    
    async def _download_and_store_framework(self, framework: str) -> Dict:
      url = f"{self.base_url}/{framework}/{framework}.json"
      stats = {"techniques": 0, "groups": 0, "software": 0, "relationships": 0, "errors": 0}
    
      try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        # 🔥 VERSION SIMPLE: Une connexion par objet avec autocommit
        for obj in data.get("objects", []):
            try:
                obj_type = obj.get("type")
                
                # Créer une nouvelle connexion pour chaque objet
                conn = psycopg2.connect(**self.db_config)
                conn.autocommit = True  # Commit automatique
                
                try:
                    with conn.cursor() as cursor:
                        if obj_type == "attack-pattern":
                            await self._store_technique_postgres(obj, cursor)
                            stats["techniques"] += 1
                        # ... autres types ...
                finally:
                    conn.close()
                    
            except Exception as obj_e:
                stats["errors"] += 1
                self.logger.error(f"Error processing {obj.get('id')}: {obj_e}")
        
        return stats
        
      except Exception as e:
        self.logger.error(f"Error downloading {framework}: {e}")
        return stats
        
      except Exception as e:
        self.logger.error(f"Error downloading {framework}: {e}")
        stats["errors"] += 1
        return stats
      
      except Exception as e:
    # Le rollback est automatique grâce au context manager
        self.logger.error(f"Transaction rolled back due to error: {e}")
        raise
      except Exception as e:
        self.logger.error(f"Error downloading {framework}: {e}")
        stats["errors"] += 1
        return stats
    
    async def _store_technique_postgres(self, technique_data: Dict, cursor=None):
     try:
        # Extraire l'ID MITRE
        technique_id = ""
        for ref in technique_data.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                break
        
        if not technique_id:
            self.logger.debug(f"⚠️ No MITRE ID found for technique: {technique_data.get('name', 'unknown')}")
            return
        
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
        
        # Préparer les données JSON
        platforms = technique_data.get("x_mitre_platforms", [])
        kill_chain_phases = tactics
        external_refs = technique_data.get("external_references", [])
        data_sources = technique_data.get("x_mitre_data_sources", [])
        detection = technique_data.get("x_mitre_detection", "")
        version = technique_data.get("x_mitre_version", "1.0")
        
        # CORRECTION : Utiliser le cursor passé en paramètre ou créer une connexion
        if cursor is not None:
            cursor.execute("""
                INSERT INTO mitre_techniques 
                (id, name, description, tactic, platforms, kill_chain_phases,
                 parent_technique, is_subtechnique, external_references,
                 x_mitre_data_sources, x_mitre_detection, x_mitre_version, last_updated)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    tactic = EXCLUDED.tactic,
                    platforms = EXCLUDED.platforms,
                    kill_chain_phases = EXCLUDED.kill_chain_phases,
                    external_references = EXCLUDED.external_references,
                    x_mitre_data_sources = EXCLUDED.x_mitre_data_sources,
                    x_mitre_detection = EXCLUDED.x_mitre_detection,
                    x_mitre_version = EXCLUDED.x_mitre_version,
                    last_updated = EXCLUDED.last_updated
            """, (
                technique_id, name, description, 
                tactics[0] if tactics else "",
                Json(platforms), Json(kill_chain_phases),
                parent_technique, is_subtechnique,
                Json(external_refs), Json(data_sources),
                detection, version, datetime.now()
            ))
        else:
            with self.get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO mitre_techniques 
                        (id, name, description, tactic, platforms, kill_chain_phases,
                         parent_technique, is_subtechnique, external_references,
                         x_mitre_data_sources, x_mitre_detection, x_mitre_version, last_updated)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            description = EXCLUDED.description,
                            tactic = EXCLUDED.tactic,
                            platforms = EXCLUDED.platforms,
                            kill_chain_phases = EXCLUDED.kill_chain_phases,
                            external_references = EXCLUDED.external_references,
                            x_mitre_data_sources = EXCLUDED.x_mitre_data_sources,
                            x_mitre_detection = EXCLUDED.x_mitre_detection,
                            x_mitre_version = EXCLUDED.x_mitre_version,
                            last_updated = EXCLUDED.last_updated
                    """, (
                        technique_id, name, description, 
                        tactics[0] if tactics else "",
                        Json(platforms), Json(kill_chain_phases),
                        parent_technique, is_subtechnique,
                        Json(external_refs), Json(data_sources),
                        detection, version, datetime.now()
                    ))
                    conn.commit()
        
        self.logger.debug(f"✅ Stored technique: {technique_id}")
        
     except Exception as e:
        self.logger.error(f"❌ Error storing technique {technique_data.get('name', 'unknown')}: {e}")
        if cursor is not None:
            raise

    
    async def _store_group_postgres(self, group_data: Dict, cursor=None):
     try:
        # Extraire l'ID MITRE
        group_id = ""
        for ref in group_data.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                break
        
        if not group_id:
            self.logger.debug(f"⚠️ No MITRE ID found for group: {group_data.get('name', 'unknown')}")
            return
        
        name = group_data.get("name", "")
        aliases = group_data.get("aliases", [])
        description = group_data.get("description", "")
        external_refs = group_data.get("external_references", [])
        version = group_data.get("x_mitre_version", "1.0")
        
        # CORRECTION : Utiliser le cursor passé en paramètre ou créer une connexion
        if cursor is not None:
            cursor.execute("""
                INSERT INTO mitre_groups 
                (id, name, aliases, description, external_references, x_mitre_version, last_updated)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    aliases = EXCLUDED.aliases,
                    description = EXCLUDED.description,
                    external_references = EXCLUDED.external_references,
                    x_mitre_version = EXCLUDED.x_mitre_version,
                    last_updated = EXCLUDED.last_updated
            """, (
                group_id, name, Json(aliases), description,
                Json(external_refs), version, datetime.now()
            ))
        else:
            with self.get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO mitre_groups 
                        (id, name, aliases, description, external_references, x_mitre_version, last_updated)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            aliases = EXCLUDED.aliases,
                            description = EXCLUDED.description,
                            external_references = EXCLUDED.external_references,
                            x_mitre_version = EXCLUDED.x_mitre_version,
                            last_updated = EXCLUDED.last_updated
                    """, (
                        group_id, name, Json(aliases), description,
                        Json(external_refs), version, datetime.now()
                    ))
                    conn.commit()
        
        self.logger.debug(f"✅ Stored group: {group_id}")
        
     except Exception as e:
        self.logger.error(f"❌ Error storing group {group_data.get('name', 'unknown')}: {e}")
        if cursor is not None:
            raise

    
    async def _store_software_postgres(self, software_data: Dict, cursor=None):
     try:
        # Extraire l'ID MITRE
        software_id = ""
        for ref in software_data.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                software_id = ref.get("external_id", "")
                break
        
        if not software_id:
            self.logger.debug(f"⚠️ No MITRE ID found for software: {software_data.get('name', 'unknown')}")
            return
        
        name = software_data.get("name", "")
        software_type = software_data.get("type", "")
        aliases = software_data.get("x_mitre_aliases", [])
        description = software_data.get("description", "")
        platforms = software_data.get("x_mitre_platforms", [])
        external_refs = software_data.get("external_references", [])
        version = software_data.get("x_mitre_version", "1.0")
        
        # CORRECTION : Utiliser le cursor passé en paramètre ou créer une connexion
        if cursor is not None:
            cursor.execute("""
                INSERT INTO mitre_software 
                (id, name, type, aliases, description, platforms, 
                 external_references, x_mitre_version, last_updated)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    name = EXCLUDED.name,
                    type = EXCLUDED.type,
                    aliases = EXCLUDED.aliases,
                    description = EXCLUDED.description,
                    platforms = EXCLUDED.platforms,
                    external_references = EXCLUDED.external_references,
                    x_mitre_version = EXCLUDED.x_mitre_version,
                    last_updated = EXCLUDED.last_updated
            """, (
                software_id, name, software_type, Json(aliases),
                description, Json(platforms), Json(external_refs),
                version, datetime.now()
            ))
        else:
            with self.get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO mitre_software 
                        (id, name, type, aliases, description, platforms, 
                         external_references, x_mitre_version, last_updated)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            type = EXCLUDED.type,
                            aliases = EXCLUDED.aliases,
                            description = EXCLUDED.description,
                            platforms = EXCLUDED.platforms,
                            external_references = EXCLUDED.external_references,
                            x_mitre_version = EXCLUDED.x_mitre_version,
                            last_updated = EXCLUDED.last_updated
                    """, (
                        software_id, name, software_type, Json(aliases),
                        description, Json(platforms), Json(external_refs),
                        version, datetime.now()
                    ))
                    conn.commit()
        
        self.logger.debug(f"✅ Stored software: {software_id}")
        
     except Exception as e:
        self.logger.error(f"❌ Error storing software {software_data.get('name', 'unknown')}: {e}")
        if cursor is not None:
            raise
    
    async def _store_relationship_postgres(self, relationship_data: Dict, cursor=None):
     try:
        source_ref = relationship_data.get("source_ref", "")
        target_ref = relationship_data.get("target_ref", "")
        relationship_type = relationship_data.get("relationship_type", "")
        description = relationship_data.get("description", "")
        
        if not all([source_ref, target_ref, relationship_type]):
            self.logger.debug(f"⚠️ Incomplete relationship data: {relationship_data.get('id', 'unknown')}")
            return
        
        # CORRECTION : Utiliser le cursor passé en paramètre ou créer une connexion
        if cursor is not None:
            cursor.execute("""
                INSERT INTO mitre_relationships 
                (source_ref, target_ref, relationship_type, description)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (source_ref, target_ref, relationship_type) DO UPDATE SET
                    description = EXCLUDED.description
            """, (source_ref, target_ref, relationship_type, description))
        else:
            with self.get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO mitre_relationships 
                        (source_ref, target_ref, relationship_type, description)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (source_ref, target_ref, relationship_type) DO UPDATE SET
                            description = EXCLUDED.description
                    """, (source_ref, target_ref, relationship_type, description))
                    conn.commit()
        
        self.logger.debug(f"✅ Stored relationship: {source_ref} -> {target_ref} ({relationship_type})")
        
     except Exception as e:
        self.logger.error(f"❌ Error storing relationship {relationship_data.get('id', 'unknown')}: {e}")
        if cursor is not None:
            raise
        # Sinon, on log juste l'erreur sans interrompre le processus
    async def enrich_mitre_relationships(self) -> bool:
      try:
        self.logger.info("🔗 Starting MITRE relationships enrichment...")
        
        with self.get_db_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # 1. Enrichir les techniques avec leurs sous-techniques
                cursor.execute("""
                    UPDATE mitre_techniques t1 
                    SET kill_chain_phases = (
                        SELECT COALESCE(
                            json_agg(DISTINCT elem) FILTER (WHERE elem IS NOT NULL),
                            '[]'::jsonb
                        )
                        FROM (
                            SELECT jsonb_array_elements_text(t1.kill_chain_phases) AS elem
                            UNION
                            SELECT jsonb_array_elements_text(t2.kill_chain_phases) AS elem
                            FROM mitre_techniques t2 
                            WHERE t2.parent_technique = t1.id
                        ) phases
                    )
                    WHERE EXISTS (
                        SELECT 1 FROM mitre_techniques t2 
                        WHERE t2.parent_technique = t1.id
                    )
                """)
                
                updated_techniques = cursor.rowcount
                self.logger.info(f"✅ Updated {updated_techniques} parent techniques with sub-technique data")
                
                # 2. Compter les relations stockées
                cursor.execute("SELECT COUNT(*) FROM mitre_relationships")
                relationships_count = cursor.fetchone()[0]
                self.logger.info(f"📊 Total relationships in database: {relationships_count}")
                
                # 3. Statistiques par type de relation
                cursor.execute("""
                    SELECT relationship_type, COUNT(*) as count
                    FROM mitre_relationships 
                    GROUP BY relationship_type
                    ORDER BY count DESC
                """)
                
                relation_stats = cursor.fetchall()
                self.logger.info("📈 Relationship statistics:")
                for stat in relation_stats:
                    self.logger.info(f"   - {stat['relationship_type']}: {stat['count']}")
                
                conn.commit()
                
        self.logger.info("✅ MITRE relationships enrichment completed")
        return True
        
      except Exception as e:
        self.logger.error(f"❌ Error enriching MITRE relationships: {e}")
        return False

    async def enrich_cve(self, cve_data: Dict) -> Dict:
        """Enrichit un CVE avec les données MITRE ATT&CK"""
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return cve_data
        
        try:
            # Vérifier le cache d'enrichissement
            cached_enrichment = await self._get_cached_enrichment(cve_id, "mitre_attack")
            if cached_enrichment:
                self.logger.debug(f"Using cached MITRE enrichment for {cve_id}")
                return {**cve_data, **cached_enrichment}
            
            # Effectuer l'enrichissement
            techniques = await self._map_cve_to_techniques(cve_data)
            
            if techniques:
                enriched_data = {
                    "mitre_techniques": techniques,
                    "mitre_tactics": list(set([t.get("tactic", "") for t in techniques if t.get("tactic")])),
                    "mitre_enriched_at": datetime.now().isoformat()
                }
                
                # Mettre en cache l'enrichissement
                await self._cache_enrichment(cve_id, "mitre_attack", enriched_data, len(techniques))
                
                self.logger.info(f"✅ Enriched {cve_id} with {len(techniques)} MITRE techniques")
                return {**cve_data, **enriched_data}
            
            return cve_data
            
        except Exception as e:
            self.logger.error(f"Error enriching CVE {cve_id}: {e}")
            return cve_data
    
    def validate_data(self, data: Dict) -> bool:
        """Valide les données d'entrée"""
        try:
            if not isinstance(data, dict):
                return False
                
            if not data.get("id"):
                return False
                
            # Accepter CVE, IOC ou types explicites
            data_type = data.get("type", "").lower()
            data_id = data.get("id", "").lower()
            
            valid_types = ["vulnerability", "indicator", "ioc", "cve"]
            valid_keywords = ["cve", "ioc"]
            
            return (data_type in valid_types or 
                    any(keyword in data_id for keyword in valid_keywords))
                    
        except Exception as e:
            self.logger.error(f"Error validating data: {e}")
            return False
    
    def get_attack_statistics(self) -> Dict[str, Any]:
        """Génère les statistiques MITRE ATT&CK depuis PostgreSQL"""
        try:
            stats = {
                "total_techniques": 0,
                "covered_techniques": 0,
                "coverage_score": 0.0,
                "total_groups": 0,
                "total_software": 0,
                "total_mappings": 0,
                "techniques_by_tactic": {},
                "mapping_methods": {}
            }
            
            with self.get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    # Statistiques des techniques
                    cursor.execute("SELECT COUNT(*) as total FROM mitre_techniques")
                    stats["total_techniques"] = cursor.fetchone()["total"]
                    
                    # Techniques couvertes (avec au moins un mapping CVE ou IOC)
                    cursor.execute("""
                        SELECT COUNT(DISTINCT technique_id) as covered
                        FROM (
                            SELECT technique_id FROM cve_technique_mapping
                            UNION
                            SELECT technique_id FROM ioc_technique_mapping
                        ) covered_techniques
                    """)
                    stats["covered_techniques"] = cursor.fetchone()["covered"]
                    
                    # Score de couverture
                    if stats["total_techniques"] > 0:
                        stats["coverage_score"] = round(
                            (stats["covered_techniques"] / stats["total_techniques"]) * 100, 2
                        )
                    
                    # Statistiques des groupes
                    cursor.execute("SELECT COUNT(*) as total FROM mitre_groups")
                    stats["total_groups"] = cursor.fetchone()["total"]
                    
                    # Statistiques des logiciels
                    cursor.execute("SELECT COUNT(*) as total FROM mitre_software")
                    stats["total_software"] = cursor.fetchone()["total"]
                    
                    # Total des mappings
                    cursor.execute("""
                        SELECT 
                            (SELECT COUNT(*) FROM cve_technique_mapping) +
                            (SELECT COUNT(*) FROM ioc_technique_mapping) as total_mappings
                    """)
                    stats["total_mappings"] = cursor.fetchone()["total_mappings"]
                    
                    # Techniques par tactique
                    cursor.execute("""
                        SELECT tactic, COUNT(*) as count
                        FROM mitre_techniques 
                        WHERE tactic IS NOT NULL AND tactic != ''
                        GROUP BY tactic
                        ORDER BY count DESC
                    """)
                    
                    for row in cursor.fetchall():
                        stats["techniques_by_tactic"][row["tactic"]] = row["count"]
                    
                    # Méthodes de mapping
                    cursor.execute("""
                        SELECT mapping_method, COUNT(*) as count
                        FROM (
                            SELECT mapping_method FROM cve_technique_mapping
                            UNION ALL
                            SELECT mapping_method FROM ioc_technique_mapping
                        ) all_mappings
                        GROUP BY mapping_method
                        ORDER BY count DESC
                    """)
                    
                    for row in cursor.fetchall():
                        stats["mapping_methods"][row["mapping_method"]] = row["count"]
            
            self.logger.debug(f"Generated statistics: {stats}")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error generating MITRE statistics: {e}")
            return {
                "total_techniques": 0,
                "covered_techniques": 0,
                "coverage_score": 0.0,
                "error": str(e)
            }
    
    async def _map_cve_to_techniques(self, cve_data: Dict) -> List[Dict]:
        """Mappe un CVE vers les techniques MITRE ATT&CK"""
        techniques = []
        cve_id = cve_data.get("id", "")
        description = cve_data.get("description", "").lower()
        
        # Mots-clés de mapping simple
        keyword_mappings = {
            "code injection": ["T1059"],
            "sql injection": ["T1059.007"],
            "command injection": ["T1059"],
            "buffer overflow": ["T1055"],
            "privilege escalation": ["T1068"],
            "remote code execution": ["T1059"],
            "cross-site scripting": ["T1059"],
            "file upload": ["T1105"],
            "directory traversal": ["T1083"],
            "authentication bypass": ["T1078"],
            "denial of service": ["T1499"],
            "information disclosure": ["T1005"]
        }
        
        matched_techniques = set()
        matched_keywords = []
        
        # Recherche par mots-clés
        for keyword, technique_ids in keyword_mappings.items():
            if keyword in description:
                matched_techniques.update(technique_ids)
                matched_keywords.append(keyword)
        
        # Récupérer les détails des techniques matchées
        if matched_techniques:
            with self.get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT id, name, description, tactic, platforms, kill_chain_phases
                        FROM mitre_techniques 
                        WHERE id = ANY(%s)
                    """, (list(matched_techniques),))
                    
                    db_techniques = cursor.fetchall()
                    
                    for tech in db_techniques:
                        techniques.append(dict(tech))
                        
                        # Stocker le mapping dans la base
                        await self._store_cve_technique_mapping(
                            cve_id, tech["id"], 0.7, "keyword_based", matched_keywords,
                            cve_data.get("cvss_score")
                        )
        
        return techniques
    
    async def _store_cve_technique_mapping(self, cve_id: str, technique_id: str, 
                                         confidence: float, method: str, 
                                         keywords: List[str], cvss_score: Optional[float]):
        """Stocke un mapping CVE -> Technique"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO cve_technique_mapping 
                        (cve_id, technique_id, confidence, mapping_method, matched_keywords, cvss_score)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (cve_id, technique_id) DO UPDATE SET
                            confidence = EXCLUDED.confidence,
                            mapping_method = EXCLUDED.mapping_method,
                            matched_keywords = EXCLUDED.matched_keywords,
                            cvss_score = EXCLUDED.cvss_score,
                            updated_at = CURRENT_TIMESTAMP
                    """, (cve_id, technique_id, confidence, method, Json(keywords), cvss_score))
                    
        except Exception as e:
            self.logger.error(f"Error storing CVE mapping: {e}")
    
    async def enrich_ioc(self, ioc_data: Dict) -> Dict:
        """Enrichit un IOC avec les données MITRE ATT&CK"""
        ioc_value = ioc_data.get("value", "")
        ioc_type = ioc_data.get("type", "")
        
        if not ioc_value:
            return ioc_data
        
        # Générer un hash pour l'IOC
        ioc_hash = hashlib.sha256(ioc_value.encode()).hexdigest()[:64]
        
        try:
            # Vérifier le cache
            cached_enrichment = await self._get_cached_enrichment(ioc_hash, "mitre_attack")
            if cached_enrichment:
                return {**ioc_data, **cached_enrichment}
            
            # Mapping basé sur le type d'IOC
            techniques = await self._map_ioc_to_techniques(ioc_type, ioc_value, ioc_hash)
            
            if techniques:
                enriched_data = {
                    "mitre_techniques": techniques,
                    "mitre_tactics": list(set([t.get("tactic", "") for t in techniques if t.get("tactic")])),
                    "mitre_enriched_at": datetime.now().isoformat()
                }
                
                await self._cache_enrichment(ioc_hash, "mitre_attack", enriched_data, len(techniques))
                
                self.logger.info(f"✅ Enriched IOC {ioc_value} with {len(techniques)} MITRE techniques")
                return {**ioc_data, **enriched_data}
            
            return ioc_data
            
        except Exception as e:
            self.logger.error(f"Error enriching IOC {ioc_value}: {e}")
            return ioc_data
    
    async def enrich(self, data: Dict) -> Dict:
      try:
        if not self.validate_data(data):
            self.logger.warning(f"Invalid data format for enrichment: {data}")
            return data
        
        data_type = data.get("type", "").lower()
        data_id = data.get("id", "").lower()
        
        # Détection automatique du type
        if data_type == "vulnerability" or "cve" in data_id:
            return await self.enrich_cve(data)
        elif data_type in ["indicator", "ioc"] or any(key in data for key in ["ioc_type", "value", "hash"]):
            return await self.enrich_ioc(data)
        else:
            self.logger.warning(f"Unknown data type for MITRE enrichment: {data_type}")
            return data
            
      except Exception as e:
        self.logger.error(f"Error in main enrich method: {e}")
        return data

    def _ensure_default_config(self):
      default_config = {
        "name": "mitre_postgres_enricher",
        "version": "1.0.0",
        "enabled": True,
        "frameworks": ["enterprise-attack"],
        "update_interval": 3600,
        "cache_ttl": 86400,
        "confidence_threshold": 0.5,
        "max_techniques_per_item": 10,
        "postgres": {
            "enabled": True,
            "auto_create_tables": True,
            "connection_timeout": 30
        }
      } 
      if not hasattr(self, 'config') or not self.config:
        self.config = default_config
        self.logger.info("Using default MITRE PostgreSQL configuration")

    def get_enricher_info(self) -> Dict:
     return {
        "name": "MITRE ATT&CK PostgreSQL Enricher",
        "version": "1.0.0",
        "description": "Enrichit les données CTI avec MITRE ATT&CK en utilisant PostgreSQL",
        "supported_types": ["vulnerability", "indicator", "cve", "ioc"],
        "database": "postgresql",
        "features": [
            "CVE to MITRE techniques mapping",
            "IOC to MITRE techniques mapping", 
            "Caching system",
            "Relationship tracking",
            "Sync logging"
        ]
    }
   
    async def _map_ioc_to_techniques(self, ioc_type: str, ioc_value: str, ioc_hash: str) -> List[Dict]:
        """Mappe un IOC vers les techniques MITRE ATT&CK"""
        techniques = []
        
        # Mapping basé sur le type d'IOC
        type_mappings = {
            "domain": ["T1071.001", "T1090"],  # Web protocols, Proxy
            "ip": ["T1071.001", "T1090"],      # Web protocols, Proxy  
            "url": ["T1071.001", "T1105"],     # Web protocols, Ingress transfer
            "email": ["T1071.003", "T1566"],   # Mail protocols, Phishing
            "file_hash": ["T1105", "T1027"],   # File transfer, Obfuscation
            "registry": ["T1112", "T1547"],    # Registry, Boot autostart
            "mutex": ["T1055", "T1106"],       # Process injection, Native API
            "service": ["T1543", "T1569"]      # Create service, System services
        }
        
        # Mapping basé sur des patterns dans la valeur
        pattern_mappings = {
            "powershell": ["T1059.001"],
            ".ps1": ["T1059.001"],
            "cmd.exe": ["T1059.003"],
            ".bat": ["T1059.003"],
            "rundll32": ["T1218.011"],
            "regsvr32": ["T1218.010"],
            "schtasks": ["T1053.005"],
            "wmic": ["T1047"]
        }
        
        matched_techniques = set()
        
        # Mapping par type
        if ioc_type.lower() in type_mappings:
            matched_techniques.update(type_mappings[ioc_type.lower()])
        
        # Mapping par pattern
        for pattern, tech_ids in pattern_mappings.items():
            if pattern in ioc_value.lower():
                matched_techniques.update(tech_ids)
        
        # Récupérer les détails des techniques depuis la DB
        if matched_techniques:
            with self.get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT id, name, description, tactic, platforms, kill_chain_phases
                        FROM mitre_techniques 
                        WHERE id = ANY(%s)
                    """, (list(matched_techniques),))
                    
                    db_techniques = cursor.fetchall()
                    
                    for tech in db_techniques:
                        confidence = 0.8 if ioc_type.lower() in type_mappings and tech["id"] in type_mappings[ioc_type.lower()] else 0.6
                        
                        techniques.append(dict(tech))
                        
                        # Stocker le mapping
                        await self._store_ioc_technique_mapping(
                            ioc_hash, tech["id"], confidence, 
                            "type_based" if ioc_type.lower() in type_mappings else "pattern_based"
                        )
        
        return techniques
    
    async def _store_ioc_technique_mapping(self, ioc_hash: str, technique_id: str, 
                                         confidence: float, method: str):
        """Stocke un mapping IOC -> Technique"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO ioc_technique_mapping 
                        (ioc_hash, technique_id, confidence, mapping_method)
                        VALUES (%s, %s, %s, %s)
                        ON CONFLICT (ioc_hash, technique_id) DO UPDATE SET
                            confidence = EXCLUDED.confidence,
                            mapping_method = EXCLUDED.mapping_method
                    """, (ioc_hash, technique_id, confidence, method))
                    
        except Exception as e:
            self.logger.error(f"Error storing IOC mapping: {e}")
    
    async def _get_cached_enrichment(self, data_id: str, enrichment_type: str) -> Optional[Dict]:
        """Récupère un enrichissement depuis le cache"""
        try:
            with self.get_db_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT enriched_data, confidence_score, techniques_count
                        FROM enrichment_cache 
                        WHERE data_id = %s AND enrichment_type = %s 
                        AND (expires_at IS NULL OR expires_at > %s)
                    """, (data_id, enrichment_type, datetime.now()))
                    
                    result = cursor.fetchone()
                    if result:
                        return dict(result["enriched_data"])
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting cached enrichment: {e}")
            return None
    
    async def _cache_enrichment(self, data_id: str, enrichment_type: str, 
                              enriched_data: Dict, techniques_count: int):
        """Met en cache un enrichissement"""
        try:
            # Expiration dans 24h par défaut
            from datetime import timedelta
            expires_at = datetime.now() + timedelta(hours=24)
            
            with self.get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO enrichment_cache 
                        (data_id, data_type, enrichment_type, enriched_data, 
                         techniques_count, expires_at)
                        VALUES (%s, 'auto', %s, %s, %s, %s)
                        ON CONFLICT (data_id, enrichment_type) DO UPDATE SET
                            enriched_data = EXCLUDED.enriched_data,
                            techniques_count = EXCLUDED.techniques_count,
                            expires_at = EXCLUDED.expires_at
                    """, (data_id, enrichment_type, Json(enriched_data), 
                          techniques_count, expires_at))
                    
        except Exception as e:
            self.logger.error(f"Error caching enrichment: {e}")
    
