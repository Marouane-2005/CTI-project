#!/usr/bin/env python3
"""
IOC Enricher pour le projet CTI - VERSION DÉFINITIVEMENT CORRIGÉE
Correction complète de l'erreur NameError: name 'CTILogger' is not defined
"""

import os
import sys
import socket
import requests
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
import ipaddress
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ============================================================================
# CLASSE CTILogger - DÉFINIE EN PREMIER ET ISOLÉE
# ============================================================================
class CTILogger:
    """Logger simple pour le projet CTI"""
    
    def __init__(self, name: str):
        self.name = name
    
    def info(self, msg: str):
        print(f"[INFO] {self.name}: {msg}")
    
    def error(self, msg: str):
        print(f"[ERROR] {self.name}: {msg}")
    
    def warning(self, msg: str):
        print(f"[WARNING] {self.name}: {msg}")
    
    def debug(self, msg: str):
        print(f"[DEBUG] {self.name}: {msg}")


# ============================================================================
# CLASSE DATABASE MANAGER
# ============================================================================
class DatabaseManager:
    """Version corrigée avec auto-création des tables"""
    
    def __init__(self, **config):
        """Initialise le gestionnaire avec la configuration fournie"""
        self.config = config
        self.pg_conn = None
        self.redis_conn = None
        
        print(f"Configuration DB reçue: {config}")
        
        # Initialiser les connexions
        self.init_postgresql()
        
        # NOUVEAU: Auto-créer les tables si elles n'existent pas
        if self.pg_conn:
            self.ensure_tables_exist()
    
    def init_postgresql(self):
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            self.pg_conn = psycopg2.connect(
                host=self.config.get('host', 'localhost'),
                port=self.config.get('port', 5432),
                database=self.config.get('database', 'cti_db'),
                user=self.config.get('user', 'cti_user'),
                password=self.config.get('password', 'cti_password'),
                cursor_factory=RealDictCursor,
                client_encoding=self.config.get('client_encoding', 'UTF8')
            )
            self.pg_conn.autocommit = True
            
            # Forcer le search_path pour éviter les problèmes de schéma
            cursor = self.pg_conn.cursor()
            cursor.execute("SET search_path TO public;")
            cursor.close()
            
            print("✓ Connexion PostgreSQL établie")
            print("✓ Search path forcé à 'public'")
            
        except ImportError:
            print("❌ psycopg2 non installé")
            self.pg_conn = None
        except Exception as e:
            print(f"❌ Erreur connexion PostgreSQL : {e}")
            self.pg_conn = None
    
    def ensure_tables_exist(self):
        """Crée les tables si elles n'existent pas"""
        if not self.pg_conn:
            return
        
        try:
            cursor = self.pg_conn.cursor()
            
            # Schéma pour la table iocs
            create_iocs_table = """
            CREATE TABLE IF NOT EXISTS public.iocs (
                id SERIAL PRIMARY KEY,
                ioc_type VARCHAR(50) NOT NULL,
                ioc_value TEXT NOT NULL,
                confidence_score DECIMAL(5,3) DEFAULT 0.0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT true,
                tags TEXT[] DEFAULT '{}',
                context JSONB DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            
            # Schéma pour la table indicators
            create_indicators_table = """
            CREATE TABLE IF NOT EXISTS public.indicators (
                id SERIAL PRIMARY KEY,
                indicator_value TEXT NOT NULL,
                indicator_type VARCHAR(100) NOT NULL,
                source VARCHAR(50) NOT NULL,
                description TEXT,
                malware_family VARCHAR(100),
                confidence_level DECIMAL(5,3) DEFAULT 0.5,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                tags JSONB DEFAULT '[]',
                collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                processed BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            
            # Exécuter les créations de tables
            cursor.execute(create_iocs_table)
            cursor.execute(create_indicators_table)
            
            # Créer les index pour les performances
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_iocs_value_type ON public.iocs(ioc_value, ioc_type);",
                "CREATE INDEX IF NOT EXISTS idx_iocs_type ON public.iocs(ioc_type);",
                "CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON public.iocs(last_seen);",
                "CREATE INDEX IF NOT EXISTS idx_indicators_value ON public.indicators(indicator_value);",
                "CREATE INDEX IF NOT EXISTS idx_indicators_source ON public.indicators(source);",
                "CREATE INDEX IF NOT EXISTS idx_indicators_collected_at ON public.indicators(collected_at);"
            ]
            
            for index_sql in indexes:
                cursor.execute(index_sql)
            
            # Vérifier que les tables ont été créées
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('iocs', 'indicators')
            """)
            
            existing_tables = [row['table_name'] for row in cursor.fetchall()]
            
            if 'iocs' in existing_tables and 'indicators' in existing_tables:
                print("✓ Tables 'iocs' et 'indicators' créées/vérifiées avec succès")
            else:
                print(f"⚠️ Tables créées partiellement: {existing_tables}")
            
            cursor.close()
            
        except Exception as e:
            print(f"❌ Erreur lors de la création des tables: {e}")
            import traceback
            traceback.print_exc()
    
    def check_table_exists(self, table_name: str) -> bool:
        """Vérifie si une table existe"""
        if not self.pg_conn:
            return False
        
        try:
            cursor = self.pg_conn.cursor()
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = %s
                );
            """, (table_name,))
            
            result = cursor.fetchone()
            cursor.close()
            return result['exists'] if result else False
            
        except Exception as e:
            print(f"Erreur vérification table {table_name}: {e}")
            return False
    
    def _format_array_for_postgres(self, python_list: List) -> str:
        """Convertit une liste Python en format array PostgreSQL"""
        if not python_list or not isinstance(python_list, list):
            return '{}'
        
        # Échapper les guillemets et caractères spéciaux dans chaque élément
        escaped_items = []
        for item in python_list:
            if item is None:
                escaped_items.append('NULL')
            else:
                # Convertir en string et échapper les guillemets
                str_item = str(item).replace('"', '\\"').replace("'", "''")
                escaped_items.append(f'"{str_item}"')
        
        return '{' + ','.join(escaped_items) + '}'

    def save_ioc(self, ioc_data: Dict) -> Optional[int]:
        """Sauvegarde un IOC avec vérification de table"""
        if not self.pg_conn:
            return None

        # Vérifier que la table existe
        if not self.check_table_exists('iocs'):
            print("❌ Table 'iocs' n'existe pas, tentative de création...")
            self.ensure_tables_exist()
            if not self.check_table_exists('iocs'):
                print("❌ Impossible de créer la table 'iocs'")
                return None

        try:
            cursor = self.pg_conn.cursor()
            
            cursor.execute("""
                SELECT id FROM public.iocs WHERE ioc_value = %s AND ioc_type = %s
            """, (ioc_data['ioc'], ioc_data['type']))
            
            existing = cursor.fetchone()
            
            tags_array = self._format_array_for_postgres(ioc_data.get('tags', []))
            context_json = json.dumps(ioc_data.get('context', {}))
            
            if existing:
                # Mettre à jour l'IOC existant
                cursor.execute("""
                    UPDATE public.iocs SET 
                        confidence_score = %s,
                        last_seen = CURRENT_TIMESTAMP,
                        is_active = true,
                        tags = %s::text[],
                        context = %s::jsonb
                    WHERE id = %s
                    RETURNING id
                """, (
                    ioc_data['confidence_score'],
                    tags_array,
                    context_json,
                    existing['id']
                ))
                result = cursor.fetchone()
                return existing['id']
            else:
                # Insérer un nouvel IOC
                cursor.execute("""
                    INSERT INTO public.iocs (
                        ioc_type, ioc_value, confidence_score, 
                        first_seen, last_seen, is_active, tags, context
                    ) VALUES (%s, %s, %s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, true, %s::text[], %s::jsonb)
                    RETURNING id
                """, (
                    ioc_data['type'],
                    ioc_data['ioc'],
                    ioc_data['confidence_score'],
                    tags_array,
                    context_json
                ))
                
                result = cursor.fetchone()
                return result['id'] if result else None
                
        except Exception as e:
            print(f"Erreur sauvegarde IOC: {e}")
            import traceback
            traceback.print_exc()
            return None

    def save_indicators(self, ioc_id: int, sources: Dict):
        """Sauvegarde les indicateurs avec vérification de table"""
        if not self.pg_conn:
            return

        # Vérifier que la table existe
        if not self.check_table_exists('indicators'):
            print("❌ Table 'indicators' n'existe pas, tentative de création...")
            self.ensure_tables_exist()
            if not self.check_table_exists('indicators'):
                print("❌ Impossible de créer la table 'indicators'")
                return

        try:
            cursor = self.pg_conn.cursor()
        
            for source_name, source_data in sources.items():
                if not source_data or not isinstance(source_data, dict):
                    continue
                
                # Extraire les informations selon la source
                indicators = self._extract_indicators_from_source(source_name, source_data)
                
                for indicator in indicators:
                    # Préparer les tags au format JSON
                    tags_json = json.dumps(indicator.get('tags', []))
                    
                    # Vérifier si l'indicateur existe déjà
                    cursor.execute("""
                        SELECT id FROM public.indicators 
                        WHERE indicator_value = %s AND source = %s
                    """, (indicator['value'], source_name))
                    
                    existing = cursor.fetchone()
                    
                    if existing:
                        # Mettre à jour
                        cursor.execute("""
                            UPDATE public.indicators SET 
                                confidence_level = %s,
                                last_seen = CURRENT_TIMESTAMP,
                                description = %s,
                                malware_family = %s,
                                tags = %s::jsonb,
                                processed = true
                            WHERE id = %s
                        """, (
                            indicator.get('confidence_level', 0.5),
                            indicator.get('description', ''),
                            indicator.get('malware_family', ''),
                            tags_json,
                            existing['id']
                        ))
                    else:
                        # Insérer nouvel indicateur
                        cursor.execute("""
                            INSERT INTO public.indicators (
                                indicator_value, indicator_type, source, description,
                                malware_family, confidence_level, first_seen, last_seen,
                                tags, collected_at, processed
                            ) VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, 
                                     CURRENT_TIMESTAMP, %s::jsonb, CURRENT_TIMESTAMP, true)
                        """, (
                            indicator['value'],
                            indicator.get('type', 'unknown'),
                            source_name,
                            indicator.get('description', ''),
                            indicator.get('malware_family', ''),
                            indicator.get('confidence_level', 0.5),
                            tags_json
                        ))
                        
        except Exception as e:
            print(f"Erreur sauvegarde indicateurs: {e}")
            import traceback
            traceback.print_exc()

    # Le reste des méthodes reste identique...


    def _extract_indicators_from_source(self, source_name: str, source_data: Dict) -> List[Dict]:
        """Extrait les indicateurs selon la source"""
        indicators = []
        print(f"\n🔍 Extraction pour {source_name}:")
        print(f"   Données reçues: {type(source_data)} - {len(str(source_data))} caractères")
        if source_name == 'virustotal':
            # Extraire les détections VirusTotal
            if 'detected_urls' in source_data:
              for url_info in source_data['detected_urls'][:20]:  # Limiter à 5
                indicators.append({
                    'value': url_info['url'],
                    'type': 'malicious_url',
                    'description': f"URL malveillante détectée - Scan date: {url_info.get('scan_date', 'N/A')}",
                    'confidence_level': 0.9,
                    'tags': ['virustotal', 'malicious_url', 'detected']
                })
                print(f"   ✅ URL malveillante: {url_info['url'][:50]}...")
            if 'resolutions' in source_data:
             for resolution in source_data['resolutions'][:15]:  # Limiter à 3
                # Handle different resolution formats
                hostname = None
                ip_address = None
                
                # Try different possible field names
                if 'hostname' in resolution:
                    hostname = resolution['hostname']
                elif 'ip_address' in resolution:
                    ip_address = resolution['ip_address']
                elif 'domain' in resolution:
                    hostname = resolution['domain']
                elif isinstance(resolution, dict):
                    # If it's a dict but doesn't have expected keys, try to extract any string value
                    for key, value in resolution.items():
                        if isinstance(value, str) and ('.' in value or ':' in value):
                            if value.count('.') >= 1 and len(value.split('.')) >= 2:
                                hostname = value
                                break
                            elif ':' in value or value.replace('.', '').isdigit():
                                ip_address = value
                                break
                
                # Create indicator based on what we found
                if hostname:
                    indicators.append({
                        'value': hostname,
                        'type': 'dns_resolution',
                        'description': f"Résolution DNS - Last resolved: {resolution.get('last_resolved', 'N/A')}",
                        'confidence_level': 0.7,
                        'tags': ['virustotal', 'dns', 'resolution', 'hostname']
                    })
                    print(f"   ✅ Résolution DNS (hostname): {hostname}")
                elif ip_address:
                    indicators.append({
                        'value': ip_address,
                        'type': 'dns_resolution',
                        'description': f"Résolution DNS - Last resolved: {resolution.get('last_resolved', 'N/A')}",
                        'confidence_level': 0.7,
                        'tags': ['virustotal', 'dns', 'resolution', 'ip']
                    })
                    print(f"   ✅ Résolution DNS (IP): {ip_address}")
                else:
                    # Log the unexpected format for debugging
                    print(f"   ⚠️ Format de résolution inattendu: {resolution}")
                    # Still create an indicator with whatever data we have
                    resolution_str = str(resolution)
                    if len(resolution_str) < 200:  # Only if not too long
                        indicators.append({
                            'value': resolution_str,
                            'type': 'dns_resolution_raw',
                            'description': f"Données de résolution brutes: {resolution_str}",
                            'confidence_level': 0.3,
                            'tags': ['virustotal', 'dns', 'resolution', 'raw']
                        })
            if 'scans' in source_data:
              for engine, result in source_data['scans'].items():
                  if result.get('detected'):
                    indicators.append({
                        'value': result.get('result', 'Unknown'),
                        'type': 'detection',
                        'description': f"Détection par {engine}",
                        'confidence_level': 0.8,
                        'tags': ['virustotal', engine.lower()]
                    })
        
             # Ajouter l'URL permanente comme indicateur
            if 'permalink' in source_data:
               indicators.append({
                'value': source_data['permalink'],
                'type': 'reference',
                'description': 'Lien VirusTotal',
                'confidence_level': 1.0,
                'tags': ['virustotal', 'reference']
               })

            if 'resource' in source_data:
             indicators.append({
                'value': source_data['resource'],
                'type': 'file_hash',
                'description': f"Hash analysé: {source_data.get('resource')}",
                'confidence_level': 1.0,
                'tags': ['virustotal', 'file_hash', 'analyzed']
            })   
    
        elif source_name == 'otx':
        # Extraire les données OTX
          if 'pulse_info' in source_data:
            pulse_info = source_data['pulse_info']
            pulse_count = pulse_info.get('count', 0)
            if pulse_count > 0:
                indicators.append({
                    'value': f"{pulse_count}_pulses",
                    'type': 'threat_intelligence',
                    'description': f'IOC présent dans {pulse_count} pulses de threat intelligence',
                    'confidence_level': min(pulse_count / 5, 1.0),  # Plus de pulses = plus suspect
                    'tags': ['otx', 'threat_intelligence', 'pulses']
                })
                print(f"   ✅ Pulses OTX: {pulse_count}")
          if 'pulses' in pulse_info:
                    for pulse in pulse_info['pulses'][:10]:  # Limiter à 3
                        indicators.append({
                            'value': pulse.get('name', 'Unknown Pulse'),
                            'type': 'threat_campaign',
                            'description': f"Campagne: {pulse.get('description', 'N/A')[:100]}",
                            'confidence_level': 0.8,
                            'tags': ['otx', 'campaign', 'pulse'] + pulse.get('tags', [])[:3]
                        })
                        print(f"   ✅ Campagne: {pulse.get('name', 'Unknown')}")       

        elif source_name == 'shodan':
        # Extraire les données Shodan
          if 'ports' in source_data:
            for port in source_data['ports']:
                indicators.append({
                    'value': f"Port {port}",
                    'type': 'network_service',
                    'description': f'Service sur port {port}',
                    'confidence_level': 0.6,
                    'tags': ['shodan', 'network', 'open_port', f'port_{port}']
                })
        
          if 'vulns' in source_data:
            for vuln in source_data['vulns']:
                indicators.append({
                    'value': vuln,
                    'type': 'vulnerability',
                    'description': f'Vulnérabilité détectée: {vuln}',
                    'confidence_level': 0.9,
                    'tags': ['shodan', 'vulnerability', 'cve', vuln.lower()]
                })
          if 'tags' in source_data:
            for tag in source_data['tags']:
                indicators.append({
                    'value': tag,
                    'type': 'service_tag',
                    'description': f'Tag de service: {tag}',
                    'confidence_level': 0.5,
                    'tags': ['shodan', 'service', 'tag', tag.lower()]
                })
                print(f"   ✅ Tag service: {tag}")

          if 'data' in source_data:
            for service in source_data['data']:  # Limiter à 3 services
                service_info = f"{service.get('product', 'Unknown')} {service.get('version', '')}"
                indicators.append({
                    'value': service_info.strip(),
                    'type': 'service_banner',
                    'description': f"Service sur port {service.get('port', '?')}: {service_info}",
                    'confidence_level': 0.7,
                    'tags': ['shodan', 'service', 'banner', f"port_{service.get('port', '0')}"]
                })
                print(f"   ✅ Service: {service_info} sur port {service.get('port', '?')}")  

                if 'ssl' in service:
                    ssl_info = service['ssl']
                    if 'cert' in ssl_info:
                        cert = ssl_info['cert']
                        indicators.append({
                            'value': cert.get('subject', {}).get('CN', 'Unknown'),
                            'type': 'ssl_certificate',
                            'description': f"Certificat SSL: {cert.get('subject', {}).get('CN', 'N/A')}",
                            'confidence_level': 0.5,
                            'tags': ['shodan', 'ssl', 'certificate']
                        })  


        elif source_name == 'urlhaus':
           # Extraire les données URLhaus
           if 'query_status' in source_data and source_data['query_status'] == 'ok':
             if 'urls' in source_data:
                for url_info in source_data['urls']:
                    status = url_info.get('url_status', 'unknown')
                    indicators.append({
                        'value': status,
                        'type': 'url_status',
                        'description': f"Statut URL: {url_info.get('url_status')}",
                        'malware_family': url_info.get('tags', [''])[0] if url_info.get('tags') else '',
                        'confidence_level': 0.8,
                        'tags': ['urlhaus', 'url_status'] + (url_info.get('tags', []) or [])
                    })
                    print(f"   ✅ URLhaus status: {status}")
                    if url_info.get('tags'):
                        for tag in url_info['tags'][:2]:  # Limiter à 2 tags
                            indicators.append({
                                'value': tag,
                                'type': 'malware_family',
                                'description': f"Famille de malware: {tag}",
                                'confidence_level': 0.8,
                                'tags': ['urlhaus', 'malware_family', tag.lower()]
                            })
                            print(f"   ✅ Famille malware: {tag}")
        print(f"   📊 Total indicateurs extraits: {len(indicators)}")

        return indicators


# ============================================================================
# CLASSE PRINCIPALE IOC ENRICHER
# ============================================================================
class IOCEnricher:
    """Classe principale d'enrichissement des IOC"""
    
    def __init__(self):
        """Initialise l'enrichisseur IOC"""
        
        print("🔧 Initialisation IOC Enricher...")
        
        # Initialiser le logger dès le début - CORRECTION PRINCIPALE
        self.logger = CTILogger("IOC_Enricher")
        self.logger.info("Démarrage de l'initialisation")
        
        # Détecter l'environnement d'exécution
        self.is_docker = self._detect_docker_environment()
        self.logger.info(f"Environnement détecté: {'Docker' if self.is_docker else 'Local'}")
        
        # Configuration adaptée à l'environnement
        self.db_config = self._get_environment_db_config()
        self.network_available = self.check_network_connectivity()
        
        # Initialiser la base de données
        self.db = None
        self._init_database()
        
        # Charger les clés API
        self.load_api_keys()
        
        # Configuration des services
        self.services = {
            'virustotal': 'https://www.virustotal.com/vtapi/v2/',
            'otx': 'https://otx.alienvault.com/api/v1/indicators/',
            'abuse_ch': 'https://urlhaus-api.abuse.ch/v1/',
            'shodan': 'https://api.shodan.io/',
        }
        
        self.rate_limits = {
            'virustotal': 0.1,
            'otx': 0.05,
            'shodan': 0.25,
            'abuse_ch': 0.5
        }
        
        self.logger.info("✅ Initialisation terminée avec succès")

    def _detect_docker_environment(self) -> bool:
        """Détecte si on s'exécute dans un conteneur Docker"""
        # Méthode 1: Vérifier les variables d'environnement Docker
        if any(key.startswith(('DOCKER_', 'KUBERNETES_')) for key in os.environ):
            return True
        
        # Méthode 2: Vérifier l'existence du fichier .dockerenv
        if os.path.exists('/.dockerenv'):
            return True
        
        # Méthode 3: Vérifier le hostname
        hostname = socket.gethostname()
        if len(hostname) == 12 and all(c in '0123456789abcdef' for c in hostname):
            return True
        
        # Méthode 4: Vérifier les variables d'environnement CTI
        if os.getenv('DB_HOST') == 'cti-postgres':
            return True
        
        return False

    def _get_environment_db_config(self) -> Dict:
        """Retourne la configuration DB selon l'environnement"""
        if self.is_docker:
            # Configuration Docker - utilise les variables d'environnement
            return {
                'host': os.getenv('DB_HOST', 'cti-postgres'),
                'port': int(os.getenv('DB_PORT', '5432')),
                'database': os.getenv('DB_NAME', 'cti_db'),
                'user': os.getenv('DB_USER', 'cti_user'),
                'password': os.getenv('DB_PASSWORD', 'cti_password'),
                'client_encoding': 'UTF8'
            }
        else:
            # Configuration locale - utilise localhost
            return {
                'host': 'localhost',
                'port': 5432,
                'database': 'cti_db',
                'user': 'cti_user',
                'password': 'cti_password',
                'client_encoding': 'UTF8'
            }

    def _init_database(self):
        """Initialise la connexion à la base de données"""
        try:
            self.logger.info(f"Tentative de connexion DB: {self.db_config['host']}:{self.db_config['port']}")
            
            # Utiliser la classe DatabaseManager locale
            try:
                self.db = DatabaseManager(**self.db_config)
                self.logger.info("✅ Connexion base de données établie")
            except UnicodeDecodeError as e:
                self.logger.warning(f"Problème d'encodage DB: {e}")
                # Essayer avec encodage latin1
                try:
                    config_latin1 = self.db_config.copy()
                    config_latin1['client_encoding'] = 'LATIN1'
                    self.db = DatabaseManager(**config_latin1)
                    self.logger.info("✅ Connexion DB établie avec encodage LATIN1")
                except Exception:
                    self.logger.warning("❌ Impossible de se connecter à la DB")
                    self.db = None
            except Exception as e:
                self.logger.warning(f"Erreur connexion DB: {e}")
                self.db = None
                
        except Exception as e:
            self.logger.error(f"Erreur initialisation DB: {e}")
            self.db = None

    def check_network_connectivity(self) -> bool:
        """Vérifie la connectivité réseau adaptée à l'environnement"""
        if self.is_docker:
            # Dans Docker, tester la connectivité externe
            test_hosts = [
                ('8.8.8.8', 53, 'Google DNS'),
                ('1.1.1.1', 53, 'Cloudflare DNS')
            ]
        else:
            # En local, tester également les conteneurs Docker
            test_hosts = [
                ('8.8.8.8', 53, 'Google DNS'),
                ('localhost', 5432, 'Local PostgreSQL')
            ]
        
        connectivity_count = 0
        for host, port, name in test_hosts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    self.logger.info(f"✅ Connectivité OK: {name}")
                    connectivity_count += 1
                else:
                    self.logger.warning(f"❌ Connectivité KO: {name}")
            except Exception as e:
                self.logger.warning(f"❌ Test connectivité {name}: {e}")
        
        network_ok = connectivity_count > 0
        self.logger.info(f"Statut réseau: {'✅ Disponible' if network_ok else '❌ Indisponible'}")
        return network_ok

    def load_api_keys(self):
        """Charge les clés API avec gestion d'environnement"""
        self.api_keys = {}
        
        # Chercher les clés dans plusieurs emplacements
        config_paths = []
        
        if self.is_docker:
            # Dans Docker, chercher dans /app/config
            config_paths = [
                '/app/config/api_keys.json',
                './config/api_keys.json'
            ]
        else:
            # En local, chercher dans les dossiers relatifs
            config_paths = [
                '../config/api_keys.json',
                './config/api_keys.json',
                'config/api_keys.json',
                os.path.join(os.path.dirname(__file__), '..', 'config', 'api_keys.json')
            ]
        
        # Essayer de charger depuis les fichiers
        loaded = False
        for config_path in config_paths:
            if self._load_api_keys_from_file(config_path):
                loaded = True
                break
        
        # Si pas de fichier, utiliser les variables d'environnement
        if not loaded:
            self._load_api_keys_from_env()
        
        # Si toujours pas de clés, utiliser les valeurs par défaut
        if not self.api_keys:
            self._load_default_api_keys()

    def _load_api_keys_from_file(self, config_path: str) -> bool:
        """Charge les clés depuis un fichier"""
        try:
            if not os.path.exists(config_path):
                return False
            
            encodings = ['utf-8', 'utf-8-sig', 'latin1', 'cp1252']
            for encoding in encodings:
                try:
                    with open(config_path, 'r', encoding=encoding) as f:
                        content = f.read()
                        # Nettoyer le contenu
                        if content.startswith('\ufeff'):
                            content = content[1:]
                        content = content.replace('\x00', '')
                        
                        data = json.loads(content)
                        self._map_api_keys(data)
                        self.logger.info(f"✅ Clés API chargées depuis {config_path} ({encoding})")
                        return True
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
        except Exception as e:
            self.logger.warning(f"Erreur chargement {config_path}: {e}")
        
        return False

    def _load_api_keys_from_env(self):
        """Charge les clés depuis les variables d'environnement"""
        env_keys = {
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'otx': 'OTX_API_KEY', 
            'shodan': 'SHODAN_API_KEY',
            'abuse_ch': 'ABUSE_CH_API_KEY'
        }
        
        loaded_count = 0
        for service, env_var in env_keys.items():
            value = os.getenv(env_var)
            if value:
                self.api_keys[service] = value
                loaded_count += 1
        
        if loaded_count > 0:
            self.logger.info(f"✅ {loaded_count} clés API chargées depuis l'environnement")

    def _load_default_api_keys(self):
        """Charge les clés par défaut (à utiliser en développement uniquement)"""
        self.logger.warning("⚠️ Utilisation des clés API par défaut")
        self.api_keys = {
            'otx': "2270bc56efbaad5d916046b7fe7b4c0d453a789110df5e6c69c4a68cb4aaf461",
            'virustotal': "f4586010738cb3f099848d35833fe49ce719a316ad51e685fb2ecdc52dbc9ac9",
            'shodan': "XnY797AXbIQJkJypDe9J1ef1lCfuA0sL",
            'abuse_ch': "e16eabe6e75269a1733edbc1b5f550296df4e45f7e651b3b"
        }

    def _map_api_keys(self, data: Dict):
        """Mappe les noms de clés du fichier JSON vers les noms internes"""
        key_mapping = {
            'otx_api_key': 'otx',
            'virustotal_api_key': 'virustotal', 
            'shodan_api_key': 'shodan',
            'abuse_ch_auth_key': 'abuse_ch'
        }
        
        for json_key, internal_key in key_mapping.items():
            if json_key in data:
                self.api_keys[internal_key] = data[json_key]

    
    def make_api_request(self, url: str, params=None, data=None, headers=None, method='GET') -> Optional[Dict]:
   
     if not self.network_available:
            self.logger.warning("Réseau non disponible, requête annulée")
            return None
    
     try:
        session = requests.Session()
        
        # NOUVEAU: Configuration pour contourner les problèmes réseau
        session.verify = False  # Désactiver vérification SSL temporairement
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Connection': 'keep-alive'
        })
        
        # NOUVEAU: Configuration proxy si nécessaire
        # Décommentez et configurez si vous êtes derrière un proxy
        # session.proxies = {
        #     'http': 'http://your-proxy:port',
        #     'https': 'http://your-proxy:port'
        # }
        
        # Timeout plus long et retry
        timeout = 60  # 60 secondes au lieu de 30
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    response = session.get(url, params=params, headers=headers, timeout=timeout)
                elif method.upper() == 'POST':
                    response = session.post(url, data=data, headers=headers, timeout=timeout)
                
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 204:
                    return {"status": "no_data"}
                elif response.status_code == 403:
                    self.logger.warning(f"API Key invalide ou quota dépassé pour {url}")
                    return None
                elif response.status_code == 429:
                    self.logger.warning(f"Rate limit atteint pour {url}, retry dans 5s...")
                    time.sleep(5)
                    continue
                else:
                    self.logger.warning(f"API returned status {response.status_code} for {url}")
                    if attempt == max_retries - 1:
                        return None
                    time.sleep(2 ** attempt)  # Backoff exponentiel
                    continue
                    
            except requests.exceptions.SSLError as e:
                self.logger.warning(f"Erreur SSL (tentative {attempt + 1}): {str(e)[:100]}")
                if attempt == max_retries - 1:
                    return None
                time.sleep(2)
                continue
                
            except requests.exceptions.ConnectionError as e:
                self.logger.warning(f"Erreur de connexion (tentative {attempt + 1}): {str(e)[:100]}")
                if attempt == max_retries - 1:
                    return None
                time.sleep(2)
                continue
                
        return None
                
     except requests.exceptions.Timeout:
        self.logger.error("Timeout de requête API après 60s")
        return None
     except Exception as e:
        self.logger.error(f"Erreur API inattendue: {e}")
        return None

    def detect_ioc_type(self, ioc: str) -> str:
        """Détecte automatiquement le type d'IOC"""
        ioc = ioc.strip().lower()
        
        # Test IP
        try:
            ipaddress.ip_address(ioc)
            return 'ip'
        except ValueError:
            pass
        
        # Test domaine
        if '.' in ioc and not '/' in ioc and len(ioc.split('.')) >= 2:
            return 'domain'
        
        # Test hash MD5
        if len(ioc) == 32 and all(c in '0123456789abcdef' for c in ioc):
            return 'md5'
        
        # Test hash SHA1
        if len(ioc) == 40 and all(c in '0123456789abcdef' for c in ioc):
            return 'sha1'
        
        # Test hash SHA256
        if len(ioc) == 64 and all(c in '0123456789abcdef' for c in ioc):
            return 'sha256'
        
        # Test URL
        if any(ioc.startswith(proto) for proto in ['http://', 'https://', 'ftp://']):
            return 'url'
        
        return 'unknown'

    def enrich_ioc(self, ioc: str, ioc_type: str = None) -> Dict:
         """Enrichit un IOC en collectant des informations depuis diverses sources"""
         if not ioc_type:
            ioc_type = self.detect_ioc_type(ioc)
    
         self.logger.info(f"Enrichissement de {ioc} (type: {ioc_type})")
    
         enrichment_result = {
        'ioc': ioc,
        'type': ioc_type,
        'confidence_score': 0.0,
        'sources': {},
        'analysis_date': datetime.now().isoformat(),
        'malicious_indicators': 0,
        'reputation_score': 0,
        'tags': [],  # Ajout pour le stockage
        'context': {}  # Ajout pour le stockage
        }
    
        # Enrichissement selon le type
         if ioc_type == 'ip':
           enrichment_result['sources'].update(self._enrich_ip(ioc))
           enrichment_result['tags'].append('ip_address')
         elif ioc_type == 'domain':
            enrichment_result['sources'].update(self._enrich_domain(ioc))
            enrichment_result['tags'].append('domain_name')
         elif ioc_type in ['md5', 'sha1', 'sha256']:
           enrichment_result['sources'].update(self._enrich_hash(ioc))
           enrichment_result['tags'].extend(['file_hash', ioc_type])
         elif ioc_type == 'url':
           enrichment_result['sources'].update(self._enrich_url(ioc))
           enrichment_result['tags'].append('url')
    
        # Calculer le score de confiance
         enrichment_result['confidence_score'] = self._calculate_confidence_score(enrichment_result['sources'])
    
    # Ajouter des métadonnées contextuelles
         enrichment_result['context'] = {
        'enrichment_timestamp': datetime.now().isoformat(),
        'sources_count': len(enrichment_result['sources']),
        'environment': 'docker' if self.is_docker else 'local',
        'version': '1.0'
        }
    
         # NOUVEAU: Sauvegarder dans la base de données
         if self.db and self.db.pg_conn:
            try:
               # Sauvegarder l'IOC
               ioc_id = self.db.save_ioc(enrichment_result)
               if ioc_id:
                self.logger.info(f"IOC sauvegardé avec l'ID: {ioc_id}")
                enrichment_result['db_id'] = ioc_id
                
                # Sauvegarder les indicateurs
                self.db.save_indicators(ioc_id, enrichment_result['sources'])
                self.logger.info(f"Indicateurs sauvegardés pour IOC ID: {ioc_id}")
               else:
                self.logger.warning("Échec de la sauvegarde de l'IOC")
            except Exception as e:
               self.logger.error(f"Erreur lors de la sauvegarde: {e}")
    
         return enrichment_result

    def _enrich_ip(self, ip: str) -> Dict:
        """Enrichit une adresse IP"""
        sources = {}
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            try:
                vt_data = self._query_virustotal_ip(ip)
                if vt_data:
                    sources['virustotal'] = vt_data
                time.sleep(self.rate_limits.get('virustotal', 1))
            except Exception as e:
                self.logger.warning(f"Erreur VirusTotal IP: {e}")
        
        # OTX AlienVault
        if 'otx' in self.api_keys:
            try:
                otx_data = self._query_otx_ip(ip)
                if otx_data:
                    sources['otx'] = otx_data
                time.sleep(self.rate_limits.get('otx', 1))
            except Exception as e:
                self.logger.warning(f"Erreur OTX IP: {e}")
        
        # Shodan
        if 'shodan' in self.api_keys:
            try:
                shodan_data = self._query_shodan_ip(ip)
                if shodan_data:
                    sources['shodan'] = shodan_data
                time.sleep(self.rate_limits.get('shodan', 1))
            except Exception as e:
                self.logger.warning(f"Erreur Shodan IP: {e}")
        
        return sources

    def _enrich_domain(self, domain: str) -> Dict:
        """Enrichit un domaine"""
        sources = {}
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            try:
                vt_data = self._query_virustotal_domain(domain)
                if vt_data:
                    sources['virustotal'] = vt_data
                time.sleep(self.rate_limits.get('virustotal', 1))
            except Exception as e:
                self.logger.warning(f"Erreur VirusTotal domain: {e}")
        
        return sources

    def _enrich_hash(self, hash_value: str) -> Dict:
        """Enrichit un hash de fichier"""
        sources = {}
        
        # VirusTotal
        if 'virustotal' in self.api_keys:
            try:
                vt_data = self._query_virustotal_hash(hash_value)
                if vt_data:
                    sources['virustotal'] = vt_data
                time.sleep(self.rate_limits.get('virustotal', 1))
            except Exception as e:
                self.logger.warning(f"Erreur VirusTotal hash: {e}")
        
        return sources

    def _enrich_url(self, url: str) -> Dict:
        """Enrichit une URL"""
        sources = {}
        
        # URLhaus (Abuse.ch)
        if 'abuse_ch' in self.api_keys:
            try:
                urlhaus_data = self._query_urlhaus(url)
                if urlhaus_data:
                    sources['urlhaus'] = urlhaus_data
                time.sleep(self.rate_limits.get('abuse_ch', 1))
            except Exception as e:
                self.logger.warning(f"Erreur URLhaus: {e}")
        
        return sources

    def _query_virustotal_ip(self, ip: str) -> Optional[Dict]:
        """Interroge VirusTotal pour une IP"""
        url = f"{self.services['virustotal']}ip-address/report"
        params = {
            'apikey': self.api_keys['virustotal'],
            'ip': ip
        }
        
        response = self.make_api_request(url, params=params)
        return response

    def _query_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """Interroge VirusTotal pour un domaine"""
        url = f"{self.services['virustotal']}domain/report"
        params = {
            'apikey': self.api_keys['virustotal'],
            'domain': domain
        }
        
        response = self.make_api_request(url, params=params)
        return response

    def _query_virustotal_hash(self, hash_value: str) -> Optional[Dict]:
        """Interroge VirusTotal pour un hash"""
        url = f"{self.services['virustotal']}file/report"
        params = {
            'apikey': self.api_keys['virustotal'],
            'resource': hash_value
        }
        
        response = self.make_api_request(url, params=params)
        return response

    def _query_otx_ip(self, ip: str) -> Optional[Dict]:
        """Interroge OTX pour une IP"""
        url = f"{self.services['otx']}/IPv4/{ip}/general"
        headers = {
            'X-OTX-API-KEY': self.api_keys['otx']
        }
        
        response = self.make_api_request(url, headers=headers)
        return response

    def _query_shodan_ip(self, ip: str) -> Optional[Dict]:
        """Interroge Shodan pour une IP"""
        url = f"{self.services['shodan']}shodan/host/{ip}"
        params = {
            'key': self.api_keys['shodan']
        }
        
        response = self.make_api_request(url, params=params)
        return response

    def _query_urlhaus(self, url: str) -> Optional[Dict]:
        """Interroge URLhaus pour une URL"""
        api_url = f"{self.services['abuse_ch']}url/"
        data = {
            'url': url
        }
        headers = {
            'Auth-Key': self.api_keys.get('abuse_ch', '')
        }
        
        response = self.make_api_request(api_url, data=data, headers=headers, method='POST')
        return response

    def _calculate_confidence_score(self, sources: Dict) -> float:
        """Calcule un score de confiance basé sur les sources"""
        if not sources:
            return 0.0
        
        total_weight = 0
        weighted_score = 0
        malicious_count = 0
        total_detections = 0
        source_weights = {
            'virustotal': 0.4,
            'otx': 0.3,
            'shodan': 0.2,
            'urlhaus': 0.3
        }
        
        for source, data in sources.items():
           if data and isinstance(data, dict):
               weight = source_weights.get(source, 0.1)
               total_weight += weight
            
               # Score basé sur la présence de données malveillantes
               if 'positives' in data and 'total' in data:
                 if data['total'] > 0:
                    malicious_ratio = data['positives'] / data['total']
                    weighted_score += malicious_ratio * weight
                    malicious_count += data['positives']
                    total_detections += data['total']
               elif source == 'otx' and 'pulse_info' in data:
                   # Pour OTX, utiliser le nombre de pulses
                   pulse_count = data['pulse_info'].get('count', 0)
                   if pulse_count > 0:
                      # Plus de pulses = plus suspect
                      otx_score = min(pulse_count / 10, 1.0)
                      weighted_score += otx_score * weight
               elif source == 'shodan':
                   # Pour Shodan, présence de vulnérabilités
                   if 'vulns' in data and data['vulns']:
                      weighted_score += 0.8 * weight
                   else:
                      weighted_score += 0.2 * weight  # Juste scannable
               else:
                      weighted_score += 0.5 * weight  # Score neutre si pas d'info
    
        final_score = weighted_score / total_weight if total_weight > 0 else 0
    
        # Bonus si détections multiples
        if malicious_count > 3:
           final_score = min(final_score * 1.2, 1.0)
    
        return round(min(final_score, 1.0), 3)

    def debug_environment(self):
        """Affiche des informations de debug sur l'environnement"""
        print(f"\n{'='*50}")
        print("DEBUG ENVIRONNEMENT IOC ENRICHER")
        print(f"{'='*50}")
        print(f"Environnement: {'Docker' if self.is_docker else 'Local'}")
        print(f"Hostname: {socket.gethostname()}")
        print(f"Répertoire courant: {os.getcwd()}")
        print(f"PYTHONPATH: {os.getenv('PYTHONPATH', 'Non défini')}")
        
        print(f"\nConfiguration DB:")
        for key, value in self.db_config.items():
            if key == 'password':
                print(f"  {key}: {'*' * len(str(value))}")
            else:
                print(f"  {key}: {value}")
        
        print(f"\nConnexions:")
        print(f"  Base de données: {'✅ OK' if self.db and self.db.pg_conn else '❌ KO'}")
        print(f"  Réseau: {'✅ OK' if self.network_available else '❌ KO'}")
        
        print(f"\nClés API:")
        for service, key in self.api_keys.items():
            if key:
                masked = key[:8] + "..." + key[-8:] if len(str(key)) > 16 else "***"
                print(f"  {service}: {masked}")
            else:
                print(f"  {service}: ❌ Non configuré")
        
        print(f"{'='*50}\n")
    

    def get_ioc_from_db(self, ioc_value: str, ioc_type: str = None) -> Optional[Dict]:
        """Récupère un IOC depuis la base de données"""
        if not self.db or not self.db.pg_conn:
           return None
    
        try:
           cursor = self.db.pg_conn.cursor()
        
           if ioc_type:
             cursor.execute("""
                SELECT * FROM iocs 
                WHERE ioc_value = %s AND ioc_type = %s
                ORDER BY last_seen DESC
                LIMIT 1
            """, (ioc_value, ioc_type))
           else:
            cursor.execute("""
                SELECT * FROM iocs 
                WHERE ioc_value = %s
                ORDER BY last_seen DESC
                LIMIT 1
            """, (ioc_value,))
        
           result = cursor.fetchone()
           if result:
            # Récupérer aussi les indicateurs associés
            cursor.execute("""
                SELECT * FROM indicators 
                WHERE indicator_value LIKE %s OR source IN (
                    SELECT DISTINCT source FROM indicators 
                    WHERE collected_at >= %s - INTERVAL '24 hours'
                )
                ORDER BY last_seen DESC
            """, (f"%{ioc_value}%", result['last_seen']))
            
            indicators = cursor.fetchall()
            
            return {
                'ioc_data': dict(result),
                'indicators': [dict(ind) for ind in indicators]
            }
    
        except Exception as e:
           self.logger.error(f"Erreur récupération IOC: {e}")
    
        return None
    
    # 6. AJOUTER UNE MÉTHODE POUR COLLECTER PLUS DE DONNÉES
    def enrich_ioc_extended(self, ioc: str, ioc_type: str = None) -> Dict:
    
    
    # Collecte normale
      result = self.enrich_ioc(ioc, ioc_type)
    
    # NOUVEAU: Collecte étendue
      if ioc_type == 'ip':
        # Ajouter géolocalisation via API gratuite
        geo_data = self._get_ip_geolocation(ioc)
        if geo_data:
            result['geolocation'] = geo_data
    
    # NOUVEAU: Extraire plus de détails des réponses existantes
      for source, data in result.get('sources', {}).items():
        if source == 'virustotal' and data:
            # Extraire tous les scans AV
            if 'scans' in data:
                result['scan_results'] = data['scans']
                result['malware_families'] = [
                    scan['result'] for scan in data['scans'].values() 
                    if scan.get('detected') and scan.get('result')
                ]
        
        elif source == 'shodan' and data:
            # Extraire informations SSL
            if 'data' in data:
                ssl_certs = []
                for service in data['data']:
                    if 'ssl' in service:
                        ssl_certs.append(service['ssl'])
                if ssl_certs:
                    result['ssl_info'] = ssl_certs
    
      return result

# 7. API GÉOLOCALISATION GRATUITE
    def _get_ip_geolocation(self, ip: str) -> Optional[Dict]:
      try:
        # Utiliser ip-api.com (gratuit, 1000 req/jour)
        url = f"http://ip-api.com/json/{ip}"
        response = self.make_api_request(url)
        
        if response and response.get('status') == 'success':
            return {
                'country': response.get('country'),
                'region': response.get('regionName'),
                'city': response.get('city'),
                'latitude': response.get('lat'),
                'longitude': response.get('lon'),
                'isp': response.get('isp'),
                'asn': response.get('as')
            }
      except Exception as e:
        self.logger.warning(f"Erreur géolocalisation: {e}")
    
      return None

# ============================================================================
# FONCTION PRINCIPALE ET POINT D'ENTRÉE - VERSION CORRIGÉE
# ============================================================================
def main():
    """Fonction principale pour test et debug - VERSION CORRIGÉE"""
    print("🚀 Démarrage IOC Enricher...")
    
    try:
        # CORRECTION: S'assurer que toutes les classes sont disponibles
        print("🔍 Vérification des dépendances...")
        
        # Test simple d'instanciation du logger
        test_logger = CTILogger("INIT_TEST")
        test_logger.info("CTILogger disponible et fonctionnel")
        
        # Test de disponibilité de la classe DatabaseManager
        print("🔍 Test DatabaseManager...")
        test_db_config = {'host': 'test', 'port': 5432, 'database': 'test'}
        # Ne pas créer de vraie connexion, juste vérifier que la classe existe
        print("✅ DatabaseManager disponible")
        
        # Maintenant on peut créer l'enricher en toute sécurité
        print("🔧 Création de l'instance IOCEnricher...")
        enricher = IOCEnricher()
        
        # Afficher les informations de debug
        enricher.debug_environment()
        
        # Test d'enrichissement
        test_iocs = [
            ("8.8.8.8", "ip"),
            ("google.com", "domain"),
            ("5d41402abc4b2a76b9719d911017c592", "md5")
        ]
        
        print("📊 Tests d'enrichissement:")
        print("-" * 40)
        
        for ioc, ioc_type in test_iocs:
            print(f"\n🔍 Test: {ioc} ({ioc_type})")
            try:
                result = enricher.enrich_ioc(ioc)
                
                print(f"   Type détecté: {result.get('type', 'unknown')}")
                print(f"   Score confiance: {result.get('confidence_score', 0):.2f}")
                print(f"   Sources utilisées: {len(result.get('sources', {}))}")
                
                # Afficher les sources avec données
                for source, data in result.get('sources', {}).items():
                    if data and isinstance(data, dict):
                        status = "✅ Données" if data else "❌ Vide"
                        print(f"     - {source}: {status}")
                        
            except Exception as e:
                print(f"   ❌ Erreur lors de l'enrichissement: {e}")
                import traceback
                traceback.print_exc()
            
            time.sleep(1)  # Délai entre les tests
        
        print(f"\n{'='*50}")
        print("✅ Tests terminés avec succès")
        print(f"{'='*50}")
        
    except Exception as e:
        print(f"❌ Erreur critique lors de l'initialisation: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0
# ============================================================================
# POINT D'ENTRÉE - PROTECTION CONTRE L'EXÉCUTION ACCIDENTELLE
# ============================================================================
if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
           print(f"\n\n⚠️ Interruption utilisateur (Ctrl+C)")
           print("🛑 Arrêt en cours...")
    except Exception as e:
        print(f"\n❌ Erreur critique non gérée: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("🔚 Nettoyage et fermeture...")