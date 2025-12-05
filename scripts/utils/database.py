"""
Gestionnaire de base de données pour le projet CTI - VERSION DOCKER CORRIGÉE
Support PostgreSQL et Redis avec configuration Docker
"""

import json
import psycopg2
import redis
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
import os
from typing import Dict, List, Optional, Any

class DatabaseManager:
    def __init__(self, config_path=None):
        """Initialise le gestionnaire de base de données"""
        # Configuration Docker-aware avec fallback
        if config_path and os.path.exists(config_path):
            self.config_path = config_path
        else:
            # Essayer différents chemins possibles
            possible_paths = [
                '/app/config/database.json',
                './config/database.json',
                '../config/database.json',
                'config/database.json'
            ]
            self.config_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    self.config_path = path
                    break
            
            if not self.config_path:
                print("⚠️ Aucun fichier database.json trouvé, utilisation des variables d'environnement")
                self.config_path = config_path or '/app/config/database.json'
        self.pg_conn = None
        self.redis_conn = None
        
        # Charger la configuration
        self.load_config()
        
        # Initialiser les connexions
        self.init_postgresql()
        self.init_redis()
        
        # Créer les tables si elles n'existent pas
        self.create_tables()
    
    def load_config(self):
        """Charge la configuration de la base de données avec support Docker"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                print(f"Fichier de configuration {self.config_path} non trouvé, utilisation des variables d'environnement")
                self.config = self.get_docker_config()
        except json.JSONDecodeError:
            print(f"Erreur de format JSON dans {self.config_path}, utilisation des variables d'environnement")
            self.config = self.get_docker_config()
        except Exception as e:
            print(f"Erreur lors du chargement de la configuration : {e}")
            self.config = self.get_docker_config()
    
    def get_docker_config(self):
        """Configuration basée sur les variables d'environnement Docker"""
        return {
            "postgresql": {
                "host": os.getenv("DB_HOST", "cti-postgres"),
                "port": int(os.getenv("DB_PORT", "5432")),
                "database": os.getenv("DB_NAME", "cti_db"),
                "username": os.getenv("DB_USER", "cti_user"),
                "password": os.getenv("DB_PASSWORD", "cti_password")
            },
            "redis": {
                "host": os.getenv("REDIS_HOST", "cti-redis"),
                "port": int(os.getenv("REDIS_PORT", "6379")),
                "db": int(os.getenv("REDIS_DB", "0"))
            }
        }
    
    def get_default_config(self):
        """Configuration par défaut (fallback)"""
        return {
            "postgresql": {
                "host": "localhost",
                "port": 5432,
                "database": "cti_db",
                "username": "cti_user",
                "password": "cti_password"
            },
            "redis": {
                "host": "localhost",
                "port": 6379,
                "db": 0
            }
        }
    
    def init_postgresql(self):
        """Initialise la connexion PostgreSQL avec retry"""
        max_retries = 5
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                pg_config = self.config['postgresql']
                print(f"Tentative de connexion PostgreSQL à {pg_config['host']}:{pg_config['port']} (tentative {attempt + 1}/{max_retries})")
                
                self.pg_conn = psycopg2.connect(
                    host=pg_config['host'],
                    port=pg_config['port'],
                    database=pg_config['database'],
                    user=pg_config['username'],
                    password=pg_config['password'],
                    cursor_factory=RealDictCursor,
                    connect_timeout=10
                )
                self.pg_conn.autocommit = True
                print("✅ Connexion PostgreSQL établie avec succès")
                return
                
            except Exception as e:
                print(f"❌ Erreur connexion PostgreSQL (tentative {attempt + 1}) : {e}")
                if attempt < max_retries - 1:
                    print(f"Retry dans {retry_delay} secondes...")
                    import time
                    time.sleep(retry_delay)
                else:
                    print("❌ Impossible de se connecter à PostgreSQL après toutes les tentatives")
                    self.pg_conn = None
    
    def init_redis(self):
        """Initialise la connexion Redis avec retry"""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                redis_config = self.config['redis']
                print(f"Tentative de connexion Redis à {redis_config['host']}:{redis_config['port']} (tentative {attempt + 1}/{max_retries})")
                
                self.redis_conn = redis.Redis(
                    host=redis_config['host'],
                    port=redis_config['port'],
                    db=redis_config['db'],
                    decode_responses=True,
                    socket_connect_timeout=5,
                    socket_timeout=5
                )
                
                # Test de connexion
                self.redis_conn.ping()
                print("✅ Connexion Redis établie avec succès")
                return
                
            except Exception as e:
                print(f"⚠️ Redis non disponible (tentative {attempt + 1}) : {e}")
                if attempt < max_retries - 1:
                    import time
                    time.sleep(retry_delay)
                else:
                    print("⚠️ Redis non disponible - Le système fonctionnera sans cache")
                    self.redis_conn = None
    
    def create_tables(self):
        """Crée les tables nécessaires"""
        if not self.pg_conn:
            print("❌ Pas de connexion PostgreSQL - Tables non créées")
            return
        
        try:
            cursor = self.pg_conn.cursor()
            
            # Table des sources collectées - AVEC last_seen
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_items (
                    id SERIAL PRIMARY KEY,
                    source_name VARCHAR(100) NOT NULL,
                    source_type VARCHAR(50) NOT NULL,
                    title TEXT,
                    content TEXT,
                    link TEXT,
                    published_date TIMESTAMP,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    category VARCHAR(100),
                    tags TEXT[],
                    hash_id VARCHAR(64) UNIQUE,
                    metadata JSONB
                )
            """)
            
            # Table des IoCs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    id SERIAL PRIMARY KEY,
                    ioc_type VARCHAR(50) NOT NULL,
                    ioc_value TEXT NOT NULL,
                    source_id INTEGER REFERENCES collected_items(id),
                    confidence_score FLOAT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    tags TEXT[],
                    context JSONB
                )
            """)
            
            # Table des CVEs avec colonne renommée
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id SERIAL PRIMARY KEY,
                    cve_id VARCHAR(20) UNIQUE NOT NULL,
                    description TEXT,
                    severity VARCHAR(20),
                    cvss_score FLOAT,
                    published_date TIMESTAMP,
                    modified_date TIMESTAMP,
                    affected_products TEXT[],
                    cve_references TEXT[],
                    source_id INTEGER REFERENCES collected_items(id),
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Table des alertes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id SERIAL PRIMARY KEY,
                    alert_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    source_id INTEGER REFERENCES collected_items(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_resolved BOOLEAN DEFAULT FALSE,
                    resolved_at TIMESTAMP,
                    metadata JSONB
                )
            """)
            
            # Ajouter la colonne last_seen si elle n'existe pas déjà
            cursor.execute("""
                DO $$ 
                BEGIN 
                    BEGIN
                        ALTER TABLE collected_items ADD COLUMN last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
                    EXCEPTION
                        WHEN duplicate_column THEN 
                            -- Column already exists, do nothing
                            NULL;
                    END;
                END $$;
            """)
            
            # Index pour les performances
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_collected_items_source ON collected_items(source_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_collected_items_date ON collected_items(collected_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_collected_items_last_seen ON collected_items(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            
            print("✅ Tables créées avec succès")
            
        except Exception as e:
            print(f"❌ Erreur lors de la création des tables : {e}")
    

    # Ajouter nouvelles tables pour le dashboard
    def create_dashboard_tables(self):
     queries = [
        """
        CREATE TABLE IF NOT EXISTS dashboard_metrics (
            id SERIAL PRIMARY KEY,
            metric_type VARCHAR(50),
            value JSONB,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id SERIAL PRIMARY KEY,
            alert_level VARCHAR(20),
            threat_data JSONB,
            acknowledged BOOLEAN DEFAULT FALSE,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    ]
     for query in queries:
        self.execute_query(query)
     def test_connections(self) -> Dict[str, bool]:
        """Teste les connexions aux bases de données"""
        results = {
            "postgresql": False,
            "redis": False
        }
        
        # Test PostgreSQL
        if self.pg_conn:
            try:
                cursor = self.pg_conn.cursor()
                cursor.execute("SELECT 1")
                results["postgresql"] = True
                print("✅ Test PostgreSQL : OK")
            except Exception as e:
                print(f"❌ Test PostgreSQL : ÉCHEC - {e}")
        else:
            print("❌ Test PostgreSQL : ÉCHEC - Pas de connexion")
        
        # Test Redis
        if self.redis_conn:
            try:
                self.redis_conn.ping()
                results["redis"] = True
                print("✅ Test Redis : OK")
            except Exception as e:
                print(f"❌ Test Redis : ÉCHEC - {e}")
        else:
            print("⚠️ Test Redis : NON CONFIGURÉ")
        
        return results
    
    def save_collected_item(self, item: Dict) -> Optional[int]:
        """Sauvegarde un élément collecté"""
        if not self.pg_conn:
            print("⚠️ Pas de connexion PostgreSQL - Item non sauvegardé")
            return None
        
        try:
            cursor = self.pg_conn.cursor()
            
            # Générer un hash unique pour éviter les doublons
            import hashlib
            hash_content = f"{item.get('source_name', '')}{item.get('title', '')}{item.get('link', '')}"
            hash_id = hashlib.sha256(hash_content.encode()).hexdigest()
            
            query = """
                INSERT INTO collected_items 
                (source_name, source_type, title, content, link, published_date, category, tags, hash_id, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (hash_id) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    metadata = EXCLUDED.metadata,
                    collected_at = CURRENT_TIMESTAMP
                RETURNING id
            """
            
            cursor.execute(query, (
                item.get('source_name'),
                item.get('source_type'),
                item.get('title'),
                item.get('content'),
                item.get('link'),
                item.get('published_date'),
                item.get('category'),
                item.get('tags', []),
                hash_id,
                json.dumps(item.get('metadata', {}))
            ))
            
            result = cursor.fetchone()
            return result['id'] if result else None
            
        except Exception as e:
            print(f"❌ Erreur lors de la sauvegarde : {e}")
            return None
    
    def get_recent_items(self, hours: int = 24, source_name: str = None) -> List[Dict]:
        """Récupère les éléments récents"""
        if not self.pg_conn:
            return []
        
        try:
            cursor = self.pg_conn.cursor()
            
            query = """
                SELECT * FROM collected_items 
                WHERE collected_at >= %s
            """
            params = [datetime.now() - timedelta(hours=hours)]
            
            if source_name:
                query += " AND source_name = %s"
                params.append(source_name)
            
            query += " ORDER BY collected_at DESC"
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            print(f"❌ Erreur lors de la récupération : {e}")
            return []
    
    def save_ioc(self, ioc_data: Dict) -> Optional[int]:
        """Sauvegarde un IoC"""
        if not self.pg_conn:
            return None
        
        try:
            cursor = self.pg_conn.cursor()
            
            query = """
                INSERT INTO iocs 
                (ioc_type, ioc_value, source_id, confidence_score, tags, context)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """
            
            cursor.execute(query, (
                ioc_data.get('type'),
                ioc_data.get('value'),
                ioc_data.get('source_id'),
                ioc_data.get('confidence_score', 0.5),
                ioc_data.get('tags', []),
                json.dumps(ioc_data.get('context', {}))
            ))
            
            result = cursor.fetchone()
            return result['id'] if result else None
            
        except Exception as e:
            print(f"❌ Erreur lors de la sauvegarde IoC : {e}")
            return None
    
    def cache_set(self, key: str, value: Any, expires: int = 3600):
        """Met en cache une valeur dans Redis"""
        if not self.redis_conn:
            return False
        
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            self.redis_conn.setex(key, expires, value)
            return True
        except Exception as e:
            print(f"❌ Erreur cache Redis : {e}")
            return False
    
    def cache_get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache Redis"""
        if not self.redis_conn:
            return None
        
        try:
            value = self.redis_conn.get(key)
            if value:
                try:
                    return json.loads(value)
                except json.JSONDecodeError:
                    return value
            return None
        except Exception as e:
            print(f"❌ Erreur récupération cache : {e}")
            return None
    
    def get_statistics(self) -> Dict:
        """Retourne des statistiques sur la base de données"""
        if not self.pg_conn:
            return {}
        
        try:
            cursor = self.pg_conn.cursor()
            
            stats = {}
            
            # Nombre total d'éléments collectés
            cursor.execute("SELECT COUNT(*) as total FROM collected_items")
            stats['total_items'] = cursor.fetchone()['total']
            
            # Nombre d'éléments par source
            cursor.execute("""
                SELECT source_name, COUNT(*) as count 
                FROM collected_items 
                GROUP BY source_name
                ORDER BY count DESC
            """)
            stats['items_by_source'] = dict(cursor.fetchall())
            
            # Nombre d'IoCs
            cursor.execute("SELECT COUNT(*) as total FROM iocs WHERE is_active = TRUE")
            stats['active_iocs'] = cursor.fetchone()['total']
            
            # Nombre de CVEs
            cursor.execute("SELECT COUNT(*) as total FROM cves")
            stats['total_cves'] = cursor.fetchone()['total']
            
            # Alertes non résolues
            cursor.execute("SELECT COUNT(*) as total FROM alerts WHERE is_resolved = FALSE")
            stats['unresolved_alerts'] = cursor.fetchone()['total']
            
            return stats
            
        except Exception as e:
            print(f"❌ Erreur lors du calcul des statistiques : {e}")
            return {}
    
    # Nouvelles méthodes à ajouter dans votre classe Database existante

    def get_threat_metrics(self):
     try:
        query = """
        SELECT 
            COUNT(*) as total_indicators,
            COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE) as daily_iocs,
            AVG(CAST(risk_score AS FLOAT)) as avg_risk_score,
            COUNT(*) FILTER (WHERE risk_score >= 8) as critical_alerts
        FROM indicators 
        WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
        """
        result = self.execute_query(query)
        return result[0] if result else {}
     except Exception as e:
        self.logger.error(f"Erreur metrics: {e}")
        return {}

    def get_recent_indicators(self, hours=24, limit=50):
     try:
        query = """
        SELECT * FROM indicators 
        WHERE created_at >= NOW() - INTERVAL %s 
        ORDER BY created_at DESC 
        LIMIT %s
        """
        return self.execute_query(query, (f"{hours} hours", limit))
     except Exception as e:
        self.logger.error(f"Erreur recent indicators: {e}")
        return []

    def get_active_alerts(self):
     try:
        query = """
        SELECT * FROM alerts 
        WHERE acknowledged = false 
        ORDER BY created_at DESC
        """
        return self.execute_query(query)
     except Exception as e:
        self.logger.error(f"Erreur active alerts: {e}")
        return []

    def get_mitre_technique_frequency(self, days=30):
     try:
        query = """
        SELECT 
            technique_id,
            technique_name,
            COUNT(*) as frequency
        FROM mitre_techniques mt
        JOIN indicator_mitre im ON mt.id = im.technique_id
        JOIN indicators i ON im.indicator_id = i.id
        WHERE i.created_at >= CURRENT_DATE - INTERVAL %s
        GROUP BY technique_id, technique_name
        ORDER BY frequency DESC
        """
        return self.execute_query(query, (f"{days} days",))
     except Exception as e:
        self.logger.error(f"Erreur MITRE frequency: {e}")
        return []

   
    
    def cleanup_old_data(self, days: int = 30):
        """Nettoie les données anciennes"""
        if not self.pg_conn:
            return
        
        try:
            cursor = self.pg_conn.cursor()
            
            cleanup_date = datetime.now() - timedelta(days=days)
            
            # Supprimer les anciens éléments collectés
            cursor.execute("""
                DELETE FROM collected_items 
                WHERE collected_at < %s
            """, (cleanup_date,))
            
            deleted_count = cursor.rowcount
            print(f"🧹 Suppression de {deleted_count} éléments anciens")
            
        except Exception as e:
            print(f"❌ Erreur lors du nettoyage : {e}")
    
    def close_connections(self):
        """Ferme les connexions"""
        if self.pg_conn:
            self.pg_conn.close()
            print("🔌 Connexion PostgreSQL fermée")
        if self.redis_conn:
            self.redis_conn.close()
            print("🔌 Connexion Redis fermée")
    
    def __del__(self):
        """Destructeur pour fermer les connexions"""
        self.close_connections()


# Script de test pour vérifier les connexions
if __name__ == "__main__":
    print("🔍 Test des connexions de base de données...")
    
    db = DatabaseManager()
    
    # Test des connexions
    results = db.test_connections()
    
    if results["postgresql"]:
        # Test d'insertion
        test_item = {
            'source_name': 'test',
            'source_type': 'manual',
            'title': 'Test Item',
            'content': 'Contenu de test',
            'category': 'test'
        }
        
        item_id = db.save_collected_item(test_item)
        if item_id:
            print(f"✅ Test d'insertion réussi - ID: {item_id}")
        
        # Afficher les statistiques
        stats = db.get_statistics()
        print("📊 Statistiques de la base :")
        for key, value in stats.items():
            print(f"  {key}: {value}")
    
    db.close_connections()
    print("✅ Tests terminés")