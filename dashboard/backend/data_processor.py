# dashboard/backend/data_processor.py
"""
Processeur de données AMÉLIORÉ avec intégration MITRE ATT&CK
Extension de votre data_processor.py existant
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
import asyncpg
import psycopg2
from psycopg2.extras import RealDictCursor
import logging
logger = logging.getLogger(__name__)
class DashboardDataProcessor:
    def __init__(self):
        # Hériter de votre configuration existante
        self.db_config = {
            'host': os.getenv('DB_HOST', 'cti-postgres'),
            'port': int(os.getenv('DB_PORT', 5432)),
            'database': os.getenv('DB_NAME', 'cti_db'),
            'user': os.getenv('DB_USER', 'cti_user'),
            'password': os.getenv('DB_PASSWORD', 'cti_password')
        }
        self.db_connection = None
        self._mock_alerts = []
        self._mock_iocs = []
        self._init_connections()
    
      
    def _init_connections(self):
        """Initialise la connexion PostgreSQL"""
        try:
            import psycopg2
            self.db_connection = psycopg2.connect(**self.db_config)
            print("✅ Enhanced Data Processor - PostgreSQL connected")
        except Exception as e:
            print(f"❌ Enhanced Data Processor - PostgreSQL error: {e}")
            self.db_connection = None

    # ===== NOUVELLES MÉTHODES MITRE ATT&CK =====
    
    
    def get_dashboard_overview(self):
     try:
        if not self.db_connection:
            return self._get_mock_overview()
        
        with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
            # Requêtes pour récupérer les vraies données
            cursor.execute("SELECT COUNT(*) as total_threats FROM threats")
            threats = cursor.fetchone()['total_threats']
            
            cursor.execute("SELECT COUNT(*) as active_alerts FROM alerts WHERE acknowledged = false")
            alerts = cursor.fetchone()['active_alerts']
            
        return {
            'total_threats': threats,
            'active_alerts': alerts,
            'sources_active': 3,  # À adapter selon vos sources
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        }
     except Exception as e:
        return {
            'total_threats': 0,
            'active_alerts': 0, 
            'sources_active': 0,
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

    def _get_mock_overview(self):
     return {
        'total_threats': 0,
        'active_alerts': 0,
        'sources_active': 0,
        'status': 'mock_data',
        'timestamp': datetime.now().isoformat()
    }

    
    
    def get_mitre_techniques_overview(self) -> Dict[str, Any]:
        """Vue d'ensemble des techniques MITRE ATT&CK"""
        if not self.db_connection:
            return self._get_mock_mitre_overview()
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Statistiques générales
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_techniques,
                        COUNT(DISTINCT tactic) as total_tactics,
                        COUNT(CASE WHEN detection_level = 'high' THEN 1 END) as high_detection,
                        COUNT(CASE WHEN mitigation_available = true THEN 1 END) as mitigated_techniques
                    FROM mitre_techniques
                """)
                
                overview = dict(cursor.fetchone())
                
                # Top 10 techniques par fréquence d'usage
                cursor.execute("""
                    SELECT 
                        technique_id,
                        name,
                        tactic,
                        usage_frequency,
                        detection_level,
                        mitigation_available
                    FROM mitre_techniques 
                    ORDER BY usage_frequency DESC 
                    LIMIT 10
                """)
                
                top_techniques = [dict(row) for row in cursor.fetchall()]
                
                # Distribution par tactiques
                cursor.execute("""
                    SELECT 
                        tactic,
                        COUNT(*) as technique_count,
                        AVG(usage_frequency) as avg_frequency
                    FROM mitre_techniques 
                    GROUP BY tactic
                    ORDER BY technique_count DESC
                """)
                
                tactics_distribution = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'overview': overview,
                    'top_techniques': top_techniques,
                    'tactics_distribution': tactics_distribution,
                    'last_updated': datetime.now().isoformat(),
                    'data_source': 'postgresql_mitre'
                }
                
        except Exception as e:
            print(f"Erreur get_mitre_techniques_overview: {e}")
            return self._get_mock_mitre_overview()

    
    def get_recent_indicators(self, hours=24):
        """Mock pour les tests"""
        return []
    
    def count_technique_occurrences(self, technique, hours=1):
        """Mock pour les tests"""
        return 0
    
    def insert_alert(self, alert):
        """Version CORRIGÉE pour insérer une alerte"""
        try:
            if not self.db_connection:
                # Mode mock - stockage en mémoire pour les tests
                
                self._mock_alerts.append(alert)
                return True
            
            with self.db_connection.cursor() as cursor:
                # Vérifier/créer la table alerts
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id VARCHAR(255) PRIMARY KEY,
                        level VARCHAR(50) NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        source VARCHAR(100),
                        indicator_data JSONB,
                        mitre_data JSONB,
                        detection_method VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                
                # Insérer l'alerte avec gestion des conflits
                cursor.execute("""
                    INSERT INTO alerts (
                        id, level, title, description, timestamp, 
                        acknowledged, source, indicator_data, mitre_data, detection_method
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        level = EXCLUDED.level,
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        timestamp = EXCLUDED.timestamp
                """, (
                    alert.get('id', f'alert_{int(datetime.now().timestamp())}'),
                    alert.get('level', 'medium'),
                    alert.get('title', 'Alerte sans titre'),
                    alert.get('description', ''),
                    alert.get('timestamp', datetime.now().isoformat()),
                    alert.get('acknowledged', False),
                    alert.get('source', 'unknown'),
                    json.dumps(alert.get('indicator_data', {})),
                    json.dumps(alert.get('mitre_data', {})),
                    alert.get('detection_method', 'manual')
                ))
                
                # Valider la transaction
                self.db_connection.commit()
                return True
                
        except Exception as e:
            
            if self.db_connection:
                try:
                    self.db_connection.rollback()
                except:
                    pass
            return False
    
    def acknowledge_alert(self, alert_id, user_id='system'):
        """Marquer une alerte comme acquittée"""
        try:
            if not self.db_connection:
                # Mode mock
                for alert in self._mock_alerts:
                    if alert.get('id') == alert_id:
                        alert['acknowledged'] = True
                        alert['acknowledged_by'] = user_id
                        alert['acknowledged_at'] = datetime.now().isoformat()
                        return True
                return False
            
            with self.db_connection.cursor() as cursor:
                cursor.execute("""
                    UPDATE alerts 
                    SET acknowledged = true, 
                        acknowledged_at = CURRENT_TIMESTAMP,
                        acknowledged_by = %s
                    WHERE id = %s
                """, (user_id, alert_id))
                
                rows_affected = cursor.rowcount
                self.db_connection.commit()
                
                if rows_affected > 0:
                   return True
                else:
                    return False
                    
        except Exception as e:
            if self.db_connection:
                try:
                    self.db_connection.rollback()
                except:
                    pass
            return False
    

    def get_alerts_stats(self):
        """Statistiques sur les alertes"""
        try:
            if not self.db_connection:
                # Mode mock
                total = len(self._mock_alerts)
                unacknowledged = len([a for a in self._mock_alerts if not a.get('acknowledged', False)])
                return {
                    'total': total,
                    'unacknowledged': unacknowledged,
                    'acknowledged': total - unacknowledged,
                    'by_level': {'high': 0, 'medium': 0, 'low': 0, 'critical': 0}
                }
            
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Statistiques générales
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total,
                        COUNT(CASE WHEN acknowledged = false THEN 1 END) as unacknowledged,
                        COUNT(CASE WHEN acknowledged = true THEN 1 END) as acknowledged
                    FROM alerts
                """)
                stats = dict(cursor.fetchone())
                
                # Par niveau
                cursor.execute("""
                    SELECT level, COUNT(*) as count
                    FROM alerts
                    GROUP BY level
                """)
                by_level = {row['level']: row['count'] for row in cursor.fetchall()}
                
                stats['by_level'] = by_level
                return stats
                
        except Exception as e:
            return {'total': 0, 'unacknowledged': 0, 'acknowledged': 0, 'by_level': {}}
    
    
    def get_alerts_count(self):
     try:
        if not self.db_connection:
            return {
                'total': 21, 'acknowledged': 1, 'unacknowledged': 20,
                'by_level': {'critical': 5, 'high': 8, 'medium': 6, 'low': 2}
            }
        
        with self.db_connection.cursor() as cursor:
            # Compter le total
            cursor.execute("SELECT COUNT(*) FROM alerts")
            total = cursor.fetchone()[0]
            
            # Compter par statut d'acquittement
            cursor.execute("SELECT acknowledged, COUNT(*) FROM alerts GROUP BY acknowledged")
            ack_counts = cursor.fetchall()
            
            acknowledged = 0
            unacknowledged = 0
            for ack, count in ack_counts:
                if ack:
                    acknowledged += count
                else:
                    unacknowledged += count
            
            # Compter par niveau
            cursor.execute("SELECT level, COUNT(*) FROM alerts GROUP BY level")
            level_counts = {level: count for level, count in cursor.fetchall()}
            
            return {
                'total': total,
                'acknowledged': acknowledged,
                'unacknowledged': unacknowledged,
                'by_level': level_counts
            }
            
     except Exception as e:
        logger.error(f"Erreur get_alerts_count: {e}")
        return {'total': 0, 'acknowledged': 0, 'unacknowledged': 0, 'by_level': {}}

    def get_mitre_threat_actors_data(self) -> Dict[str, Any]:
        """Données des groupes d'acteurs de menaces"""
        if not self.db_connection:
            return {'groups': [], 'total': 0}
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Groupes d'acteurs avec leurs techniques préférées
                cursor.execute("""
                    SELECT 
                        g.group_id,
                        g.name,
                        g.description,
                        g.country_origin,
                        g.first_seen,
                        g.last_activity,
                        COUNT(gt.technique_id) as techniques_count
                    FROM mitre_groups g
                    LEFT JOIN group_techniques gt ON g.group_id = gt.group_id
                    GROUP BY g.group_id, g.name, g.description, g.country_origin, 
                             g.first_seen, g.last_activity
                    ORDER BY g.last_activity DESC NULLS LAST
                    LIMIT 20
                """)
                
                threat_actors = [dict(row) for row in cursor.fetchall()]
                
                # Pour chaque groupe, récupérer ses techniques top
                for actor in threat_actors:
                    cursor.execute("""
                        SELECT 
                            mt.technique_id,
                            mt.name,
                            mt.tactic,
                            gt.confidence_level
                        FROM group_techniques gt
                        JOIN mitre_techniques mt ON gt.technique_id = mt.technique_id
                        WHERE gt.group_id = %s
                        ORDER BY gt.confidence_level DESC
                        LIMIT 5
                    """, (actor['group_id'],))
                    
                    actor['top_techniques'] = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'threat_actors': threat_actors,
                    'total': len(threat_actors),
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"Erreur get_mitre_threat_actors_data: {e}")
            return {'threat_actors': [], 'total': 0}

    def get_mitre_software_analysis(self) -> Dict[str, Any]:
        """Analyse des malwares et outils MITRE"""
        if not self.db_connection:
            return {'software': [], 'total': 0}
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Top malwares/outils avec techniques associées
                cursor.execute("""
                    SELECT 
                        s.software_id,
                        s.name,
                        s.type,
                        s.description,
                        s.platforms,
                        COUNT(st.technique_id) as techniques_count,
                        AVG(st.confidence_level) as avg_confidence
                    FROM mitre_software s
                    LEFT JOIN software_techniques st ON s.software_id = st.software_id
                    GROUP BY s.software_id, s.name, s.type, s.description, s.platforms
                    ORDER BY techniques_count DESC
                    LIMIT 15
                """)
                
                software_list = [dict(row) for row in cursor.fetchall()]
                
                # Statistiques par type
                cursor.execute("""
                    SELECT 
                        type,
                        COUNT(*) as count,
                        AVG(techniques_count) as avg_techniques
                    FROM (
                        SELECT 
                            s.type,
                            COUNT(st.technique_id) as techniques_count
                        FROM mitre_software s
                        LEFT JOIN software_techniques st ON s.software_id = st.software_id
                        GROUP BY s.software_id, s.type
                    ) subq
                    GROUP BY type
                    ORDER BY count DESC
                """)
                
                type_stats = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'software_list': software_list,
                    'type_statistics': type_stats,
                    'total': len(software_list),
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"Erreur get_mitre_software_analysis: {e}")
            return {'software': [], 'total': 0}

    
    # Ajouter ces méthodes dans la classe DashboardDataProcessor:

   

    def get_live_threats(self, hours: int = 1) -> Dict[str, Any]:
     return {
        'threats': [],
        'total': 0,
        'timeframe_hours': hours,
        'timestamp': datetime.now().isoformat()
    }

    def search_indicators(self, params: Dict) -> Dict[str, Any]:
     return {
        'indicators': [],
        'total': 0,
        'search_params': params,
        'timestamp': datetime.now().isoformat()
    }

    # REMPLACER la méthode existante
    
    
    def get_alerts_data(self, acknowledged=None):
        """Version CORRIGÉE pour récupérer les alertes"""
        try:
            if not self.db_connection:
                # Mode mock - retourner les alertes en mémoire
               
                filtered_alerts = self._mock_alerts
                
                if acknowledged is not None:
                    filtered_alerts = [
                        alert for alert in self._mock_alerts 
                        if alert.get('acknowledged', False) == acknowledged
                    ]
                
                return {
                    'alerts': filtered_alerts,
                    'total': len(filtered_alerts),
                    'acknowledged_filter': acknowledged,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'mock_data'
                }
            
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Construction de la requête avec filtre optionnel
                query = "SELECT * FROM alerts"
                params = []
                
                if acknowledged is not None:
                    query += " WHERE acknowledged = %s"
                    params.append(acknowledged)
                
                query += " ORDER BY timestamp DESC, created_at DESC LIMIT 100"
                
                cursor.execute(query, params)
                alerts = [dict(row) for row in cursor.fetchall()]
                
                # Conversion des timestamps pour l'affichage
                for alert in alerts:
                    if alert.get('timestamp'):
                        # S'assurer que le timestamp est une string ISO
                        if hasattr(alert['timestamp'], 'isoformat'):
                            alert['timestamp'] = alert['timestamp'].isoformat()
                    
                    # Décodage JSON des champs si nécessaire
                    if alert.get('indicator_data') and isinstance(alert['indicator_data'], str):
                        try:
                            alert['indicator_data'] = json.loads(alert['indicator_data'])
                        except:
                            pass
                    
                    if alert.get('mitre_data') and isinstance(alert['mitre_data'], str):
                        try:
                            alert['mitre_data'] = json.loads(alert['mitre_data'])
                        except:
                            pass
                
                
                
                return {
                    'alerts': alerts,
                    'total': len(alerts),
                    'acknowledged_filter': acknowledged,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'postgresql'
                }
                
        except Exception as e:
           
            # TOUJOURS retourner une structure valide
            return {
                'alerts': [],
                'total': 0,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'source': 'error'
            }
    
    
    def get_alert_by_id(self, alert_id):
        """Récupérer une alerte spécifique par ID"""
        try:
            if not self.db_connection:
                # Mode mock
                for alert in self._mock_alerts:
                    if alert.get('id') == alert_id:
                        return alert
                return None
            
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
                result = cursor.fetchone()
                
                if result:
                    alert = dict(result)
                    # Conversion des timestamps
                    if alert.get('timestamp') and hasattr(alert['timestamp'], 'isoformat'):
                        alert['timestamp'] = alert['timestamp'].isoformat()
                    return alert
                return None
                
        except Exception as e:
            return None
    
    
    def get_mitre_heatmap_data(self, days=30):
      try:
        return {
            'heatmap': [
                {
                    'technique_id': 'T1566',
                    'technique_name': 'Phishing',
                    'frequency': 5,
                    'tactics': ['initial-access'],
                    'detection_level': 'medium',
                    'risk_score': 6.5
                }
            ],
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        }
      except Exception as e:
        return {'heatmap': [], 'error': str(e)}
    

    def get_threat_landscape_data(self):
     try:
        return {
            'landscape': [
                {'category': 'Malware', 'count': 45, 'severity': 'high'},
                {'category': 'Phishing', 'count': 32, 'severity': 'medium'},
                {'category': 'Ransomware', 'count': 18, 'severity': 'critical'}
            ],
            'summary': {
                'total_categories': 3,
                'highest_risk': 'Ransomware'
            },
            'timestamp': datetime.now().isoformat()
        }
     except Exception as e:
        return {'landscape': [], 'summary': {}, 'error': str(e)}

    def get_metrics_timeline(self, days=7):
     try:
        return {
            'timeline': [
                {
                    'date': (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d'),
                    'threats_detected': 15 + (i * 2),
                    'alerts_generated': 5 + (i % 4),
                    'iocs_processed': 100 + (i * 10)
                } for i in range(days)
            ],
            'metrics': {
                'total_threats': days * 15,
                'avg_daily_alerts': 5,
                'trend': 'stable'
            },
            'timestamp': datetime.now().isoformat()
        }
     except Exception as e:
        return {'timeline': [], 'metrics': {}, 'error': str(e)}

    def get_enhanced_mitre_heatmap_data(self, days: int = 30) -> Dict[str, Any]:
        """Version améliorée de la heatmap MITRE avec données réelles"""
        if not self.db_connection:
            return self._get_mock_mitre_data()
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Techniques avec leurs relations aux incidents récents
                cursor.execute("""
                    SELECT 
                        mt.technique_id,
                        mt.name,
                        mt.tactic,
                        mt.usage_frequency,
                        mt.detection_level,
                        COALESCE(recent_usage.incident_count, 0) as recent_incidents,
                        CASE 
                            WHEN mt.detection_level = 'high' THEN mt.usage_frequency * 0.5
                            WHEN mt.detection_level = 'medium' THEN mt.usage_frequency * 0.7
                            ELSE mt.usage_frequency
                        END as risk_adjusted_frequency
                    FROM mitre_techniques mt
                    LEFT JOIN (
                        SELECT 
                            technique_id,
                            COUNT(*) as incident_count
                        FROM technique_incidents 
                        WHERE incident_date >= CURRENT_DATE - INTERVAL '%s days'
                        GROUP BY technique_id
                    ) recent_usage ON mt.technique_id = recent_usage.technique_id
                    ORDER BY risk_adjusted_frequency DESC
                """, (days,))
                
                techniques = []
                max_frequency = 0
                
                for row in cursor.fetchall():
                    technique = dict(row)
                    frequency = technique.get('risk_adjusted_frequency', 0)
                    max_frequency = max(max_frequency, frequency)
                    
                    techniques.append({
                        'technique_id': technique['technique_id'],
                        'technique_name': technique['name'],
                        'frequency': frequency,
                        'tactics': [technique['tactic']] if technique['tactic'] else [],
                        'detection_level': technique['detection_level'],
                        'recent_incidents': technique['recent_incidents'],
                        'risk_score': self._calculate_technique_risk_score(technique)
                    })
                
                return {
                    'heatmap': techniques,
                    'max_frequency': max_frequency,
                    'total_techniques': len(techniques),
                    'time_period': f"{days} jours",
                    'generated_at': datetime.now().isoformat(),
                    'status': 'postgresql_data'
                }
                
        except Exception as e:
            print(f"Erreur get_enhanced_mitre_heatmap_data: {e}")
            return self._get_mock_mitre_data()

    def get_mitre_coverage_analysis(self) -> Dict[str, Any]:
        """Analyse de couverture MITRE ATT&CK"""
        if not self.db_connection:
            return {'coverage': {}, 'gaps': []}
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Couverture par tactique
                cursor.execute("""
                    SELECT 
                        tactic,
                        COUNT(*) as total_techniques,
                        COUNT(CASE WHEN detection_level = 'high' THEN 1 END) as covered_high,
                        COUNT(CASE WHEN detection_level = 'medium' THEN 1 END) as covered_medium,
                        COUNT(CASE WHEN detection_level = 'low' OR detection_level IS NULL THEN 1 END) as uncovered,
                        ROUND(
                            (COUNT(CASE WHEN detection_level IN ('high', 'medium') THEN 1 END) * 100.0 / COUNT(*)), 2
                        ) as coverage_percentage
                    FROM mitre_techniques
                    GROUP BY tactic
                    ORDER BY coverage_percentage ASC
                """)
                
                tactic_coverage = [dict(row) for row in cursor.fetchall()]
                
                # Techniques critiques non couvertes
                cursor.execute("""
                    SELECT 
                        technique_id,
                        name,
                        tactic,
                        usage_frequency,
                        detection_level
                    FROM mitre_techniques
                    WHERE (detection_level IS NULL OR detection_level = 'low')
                      AND usage_frequency > 3
                    ORDER BY usage_frequency DESC
                    LIMIT 10
                """)
                
                critical_gaps = [dict(row) for row in cursor.fetchall()]
                
                # Statistiques globales
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_techniques,
                        COUNT(CASE WHEN detection_level = 'high' THEN 1 END) as high_coverage,
                        COUNT(CASE WHEN detection_level = 'medium' THEN 1 END) as medium_coverage,
                        COUNT(CASE WHEN detection_level = 'low' OR detection_level IS NULL THEN 1 END) as no_coverage,
                        ROUND(
                            (COUNT(CASE WHEN detection_level IN ('high', 'medium') THEN 1 END) * 100.0 / COUNT(*)), 2
                        ) as overall_coverage
                    FROM mitre_techniques
                """)
                
                global_stats = dict(cursor.fetchone())
                
                return {
                    'tactic_coverage': tactic_coverage,
                    'critical_gaps': critical_gaps,
                    'global_statistics': global_stats,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"Erreur get_mitre_coverage_analysis: {e}")
            return {'coverage': {}, 'gaps': []}

    def search_mitre_techniques(self, search_params: Dict) -> Dict[str, Any]:
        """Recherche avancée dans les techniques MITRE"""
        if not self.db_connection:
            return {'techniques': [], 'total': 0}
        
        try:
            query_parts = []
            query_params = []
            
            base_query = """
                SELECT 
                    mt.technique_id,
                    mt.name,
                    mt.description,
                    mt.tactic,
                    mt.detection_level,
                    mt.mitigation_available,
                    mt.usage_frequency,
                    COALESCE(recent.incident_count, 0) as recent_incidents
                FROM mitre_techniques mt
                LEFT JOIN (
                    SELECT technique_id, COUNT(*) as incident_count
                    FROM technique_incidents 
                    WHERE incident_date >= CURRENT_DATE - INTERVAL '30 days'
                    GROUP BY technique_id
                ) recent ON mt.technique_id = recent.technique_id
                WHERE 1=1
            """
            
            # Filtres de recherche
            if search_params.get('search_term'):
                query_parts.append("(mt.name ILIKE %s OR mt.description ILIKE %s)")
                term = f"%{search_params['search_term']}%"
                query_params.extend([term, term])
            
            if search_params.get('tactic'):
                query_parts.append("mt.tactic = %s")
                query_params.append(search_params['tactic'])
            
            if search_params.get('detection_level'):
                query_parts.append("mt.detection_level = %s")
                query_params.append(search_params['detection_level'])
            
            if search_params.get('min_frequency'):
                query_parts.append("mt.usage_frequency >= %s")
                query_params.append(search_params['min_frequency'])
            
            # Construction de la requête finale
            if query_parts:
                full_query = base_query + " AND " + " AND ".join(query_parts)
            else:
                full_query = base_query
            
            full_query += " ORDER BY mt.usage_frequency DESC LIMIT 50"
            
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(full_query, query_params)
                techniques = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'techniques': techniques,
                    'total': len(techniques),
                    'search_params': search_params,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"Erreur search_mitre_techniques: {e}")
            return {'techniques': [], 'total': 0}

    def get_mitre_timeline_data(self, days: int = 30) -> Dict[str, Any]:
        """Timeline des activités MITRE"""
        if not self.db_connection:
            return {'timeline': [], 'summary': {}}
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Incidents par jour avec techniques associées
                cursor.execute("""
                    SELECT 
                        DATE(ti.incident_date) as date,
                        COUNT(DISTINCT ti.incident_id) as incidents_count,
                        COUNT(ti.technique_id) as techniques_count,
                        COUNT(DISTINCT ti.technique_id) as unique_techniques,
                        string_agg(DISTINCT mt.tactic, ', ') as tactics_involved
                    FROM technique_incidents ti
                    JOIN mitre_techniques mt ON ti.technique_id = mt.technique_id
                    WHERE ti.incident_date >= CURRENT_DATE - INTERVAL '%s days'
                    GROUP BY DATE(ti.incident_date)
                    ORDER BY date DESC
                """, (days,))
                
                timeline = [dict(row) for row in cursor.fetchall()]
                
                # Techniques les plus actives sur la période
                cursor.execute("""
                    SELECT 
                        mt.technique_id,
                        mt.name,
                        mt.tactic,
                        COUNT(*) as incident_count
                    FROM technique_incidents ti
                    JOIN mitre_techniques mt ON ti.technique_id = mt.technique_id
                    WHERE ti.incident_date >= CURRENT_DATE - INTERVAL '%s days'
                    GROUP BY mt.technique_id, mt.name, mt.tactic
                    ORDER BY incident_count DESC
                    LIMIT 10
                """, (days,))
                
                most_active_techniques = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'timeline': timeline,
                    'most_active_techniques': most_active_techniques,
                    'period_days': days,
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            print(f"Erreur get_mitre_timeline_data: {e}")
            return {'timeline': [], 'summary': {}}

    def get_mitre_dashboard_widgets(self) -> Dict[str, Any]:
        """Widgets spécifiques MITRE pour le dashboard"""
        try:
            return {
                'overview': self.get_mitre_techniques_overview(),
                'threat_actors': self.get_mitre_threat_actors_data(),
                'software_analysis': self.get_mitre_software_analysis(),
                'coverage_analysis': self.get_mitre_coverage_analysis(),
                'heatmap_data': self.get_enhanced_mitre_heatmap_data(),
                'timeline_data': self.get_mitre_timeline_data(),
                'generated_at': datetime.now().isoformat(),
                'status': 'success'
            }
        except Exception as e:
            print(f"Erreur get_mitre_dashboard_widgets: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    # ===== MÉTHODES UTILITAIRES =====

    def _calculate_technique_risk_score(self, technique: Dict) -> float:
        """Calcule un score de risque pour une technique"""
        base_score = technique.get('usage_frequency', 0) * 2
        
        # Ajustement selon niveau de détection
        detection_multipliers = {
            'high': 0.3,
            'medium': 0.6,
            'low': 0.9,
            None: 1.0
        }
        
        detection_level = technique.get('detection_level')
        multiplier = detection_multipliers.get(detection_level, 1.0)
        
        # Bonus pour incidents récents
        recent_incidents = technique.get('recent_incidents', 0)
        incident_bonus = min(recent_incidents * 0.5, 3.0)
        
        risk_score = (base_score * multiplier) + incident_bonus
        return round(min(risk_score, 10.0), 2)

    def _get_mock_mitre_overview(self) -> Dict[str, Any]:
        """Données mock pour MITRE overview"""
        return {
            'overview': {
                'total_techniques': 0,
                'total_tactics': 0,
                'high_detection': 0,
                'mitigated_techniques': 0
            },
            'top_techniques': [],
            'tactics_distribution': [],
            'last_updated': datetime.now().isoformat(),
            'data_source': 'mock_data'
        }

    def _get_mock_mitre_data(self) -> Dict[str, Any]:
        """Données mock pour heatmap"""
        return {
            'heatmap': [
                {
                    'technique_id': 'T1055',
                    'technique_name': 'Process Injection',
                    'frequency': 5,
                    'tactics': ['defense-evasion', 'privilege-escalation'],
                    'detection_level': 'medium',
                    'risk_score': 6.5
                }
            ],
            'max_frequency': 5,
            'total_techniques': 1,
            'time_period': '30 jours',
            'generated_at': datetime.now().isoformat(),
            'status': 'mock_data'
        }
    
    def get_detailed_alerts_for_report(self, hours=24):
     try:
        # Récupérer les alertes de base
        base_alerts = self.get_alerts_data()
        alerts = base_alerts.get('alerts', [])
        
        # Enrichir chaque alerte avec des détails supplémentaires
        detailed_alerts = []
        for alert in alerts:
            detailed_alert = self._enrich_alert_for_report(alert)
            detailed_alerts.append(detailed_alert)
        
        return {
            'alerts': detailed_alerts,
            'total': len(detailed_alerts),
            'enriched': True
        }
        
     except Exception as e:
        logger.error(f"Erreur get_detailed_alerts_for_report: {e}")
        return {'alerts': [], 'total': 0, 'error': str(e)}

    def _enrich_alert_for_report(self, alert: Dict) -> Dict:
     try:
        enriched_alert = alert.copy()
        
        # Ajouter des détails techniques si disponibles
        if 'indicator_data' not in enriched_alert:
            enriched_alert['indicator_data'] = self._extract_indicator_from_alert(alert)
        
        # Ajouter l'analyse MITRE si disponible
        if 'mitre_data' not in enriched_alert:
            enriched_alert['mitre_data'] = self._extract_mitre_from_alert(alert)
        
        # Calculer le score de risque
        enriched_alert['calculated_risk'] = self._calculate_alert_risk_detailed(alert)
        
        # Ajouter les actions recommandées
        enriched_alert['recommended_actions'] = self._get_alert_actions(alert)
        
        # Ajouter le contexte temporel
        enriched_alert['time_context'] = self._get_alert_time_context(alert)
        
        return enriched_alert
        
     except Exception as e:
        logger.error(f"Erreur enrichissement alerte {alert.get('id')}: {e}")
        return alert

    def _extract_indicator_from_alert(self, alert: Dict) -> Dict:
    # Chercher dans le titre et la description
     title = alert.get('title', '')
     description = alert.get('description', '')
    
    # Patterns pour différents types d'IOCs
     import re
    
    # IP addresses
     ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
     ip_match = re.search(ip_pattern, f"{title} {description}")
    
    # Domains
     domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'
     domain_match = re.search(domain_pattern, f"{title} {description}")
    
    # File hashes
     hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
     hash_match = re.search(hash_pattern, f"{title} {description}")
    
     if ip_match:
        return {
            'type': 'ip-addr',
            'value': ip_match.group(0),
            'confidence': 80
        }
     elif domain_match:
        return {
            'type': 'domain', 
            'value': domain_match.group(0),
            'confidence': 75
        }
     elif hash_match:
        return {
            'type': 'file-hash',
            'value': hash_match.group(0), 
            'confidence': 90
        }
     else:
        return {'type': 'unknown', 'value': 'N/A', 'confidence': 0}

    def _extract_mitre_from_alert(self, alert: Dict) -> Dict:
     title = alert.get('title', '').lower()
     description = alert.get('description', '').lower()
    
    # Mapping simple des techniques courantes
     technique_mapping = {
        'phishing': ['T1566'],
        'process injection': ['T1055'],
        'application layer protocol': ['T1071'],
        'command and control': ['T1071', 'T1090'],
        'malware': ['T1204', 'T1105'],
        'trojan': ['T1055', 'T1071'],
        'backdoor': ['T1055', 'T1071', 'T1090']
    }
    
     detected_techniques = []
     detected_tactics = []
    
     for keyword, techniques in technique_mapping.items():
        if keyword in f"{title} {description}":
            detected_techniques.extend(techniques)
            
    # Éliminer les doublons
     detected_techniques = list(set(detected_techniques))
    
    # Mapper vers les tactiques
     if detected_techniques:
        detected_tactics = ['Initial Access', 'Execution', 'Command and Control']
    
     return {
        'techniques': detected_techniques,
        'tactics': detected_tactics,
        'analysis': f"Détection de {len(detected_techniques)} technique(s) MITRE ATT&CK" if detected_techniques else "Aucune corrélation MITRE disponible"
    }
    
    def get_recent_iocs(self, hours=24, ioc_type='all', risk_level='all'):
        """MÉTHODE MANQUANTE - Récupère les IOCs récents avec filtres"""
        try:
            if not self.db_connection:
                return self._get_mock_iocs()
            
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Construction de la requête avec filtres
                query = """
                    SELECT 
                        i.id,
                        i.value,
                        i.type,
                        i.source,
                        i.risk_score,
                        i.created_at,
                        i.mitre_techniques,
                        i.enrichments,
                        i.confidence_level
                    FROM indicators i
                    WHERE i.created_at >= NOW() - INTERVAL %s
                """
                params = [f'{hours} hours']
                
                # Filtre par type
                if ioc_type != 'all':
                    query += " AND i.type = %s"
                    params.append(ioc_type)
                
                # Filtre par niveau de risque
                if risk_level != 'all':
                    risk_ranges = {
                        'critical': (8, 10),
                        'high': (6, 8),
                        'medium': (4, 6),
                        'low': (0, 4)
                    }
                    if risk_level in risk_ranges:
                        min_risk, max_risk = risk_ranges[risk_level]
                        query += " AND i.risk_score >= %s AND i.risk_score < %s"
                        params.extend([min_risk, max_risk])
                
                query += " ORDER BY i.created_at DESC LIMIT 100"
                
                cursor.execute(query, params)
                iocs = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'iocs': iocs,
                    'total': len(iocs),
                    'filters': {
                        'hours': hours,
                        'type': ioc_type,
                        'risk_level': risk_level
                    },
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Erreur get_recent_iocs: {e}")
            return self._get_mock_iocs()

    def _get_mock_iocs(self):
        """CORRIGÉ - Données IOCs pour test/développement"""
        return {
            'iocs': [
                {
                    'id': 'ioc_001',
                    'value': '192.168.1.100',
                    'type': 'ip',
                    'source': 'threat_intel',
                    'risk_score': 8.5,
                    'created_at': datetime.now().isoformat(),
                    'mitre_techniques': ['T1055', 'T1071'],
                    'enrichments': {
                        'geolocation': {'country': 'CN'},
                        'reputation': 'malicious'
                    },
                    'confidence_level': 85
                },
                {
                    'id': 'ioc_002', 
                    'value': 'malicious-domain.com',
                    'type': 'domain',
                    'source': 'osint_feed',
                    'risk_score': 7.2,
                    'created_at': (datetime.now() - timedelta(hours=2)).isoformat(),
                    'mitre_techniques': ['T1071'],
                    'enrichments': {
                        'dns_records': ['A', 'MX'],
                        'reputation': 'suspicious'
                    },
                    'confidence_level': 75
                },
                {
                    'id': 'ioc_003',
                    'value': 'http://malicious-site.com/payload',
                    'type': 'url',
                    'source': 'sandbox_analysis',
                    'risk_score': 9.1,
                    'created_at': (datetime.now() - timedelta(minutes=30)).isoformat(),
                    'mitre_techniques': ['T1071', 'T1105'],
                    'enrichments': {
                        'http_status': 200,
                        'content_type': 'application/octet-stream'
                    },
                    'confidence_level': 95
                },
                {
                    'id': 'ioc_004',
                    'value': 'a1b2c3d4e5f6789012345678901234567890abcdef',
                    'type': 'hash',
                    'source': 'malware_analysis',
                    'risk_score': 8.8,
                    'created_at': (datetime.now() - timedelta(hours=1)).isoformat(),
                    'mitre_techniques': ['T1204', 'T1055'],
                    'enrichments': {
                        'file_type': 'PE32',
                        'malware_family': 'Trojan.Generic'
                    },
                    'confidence_level': 90
                }
            ],
            'total': 4,
            'status': 'mock_data'
        }

    def search_iocs(self, search_params):
        """CORRIGÉ - Recherche d'IOCs avec paramètres avancés"""
        try:
            if not self.db_connection:
                # Filtrer les données mock selon les paramètres
                mock_data = self._get_mock_iocs()
                filtered_iocs = mock_data['iocs']
                
                # Appliquer les filtres sur les données mock
                if search_params.get('search_term'):
                    term = search_params['search_term'].lower()
                    filtered_iocs = [
                        ioc for ioc in filtered_iocs 
                        if term in ioc['value'].lower() or term in ioc['source'].lower()
                    ]
                
                if search_params.get('type'):
                    filtered_iocs = [
                        ioc for ioc in filtered_iocs 
                        if ioc['type'] == search_params['type']
                    ]
                
                if search_params.get('min_risk_score'):
                    min_risk = float(search_params['min_risk_score'])
                    filtered_iocs = [
                        ioc for ioc in filtered_iocs 
                        if ioc['risk_score'] >= min_risk
                    ]
                
                return {
                    'iocs': filtered_iocs,
                    'total': len(filtered_iocs),
                    'search_params': search_params
                }
                
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                query = "SELECT * FROM indicators WHERE 1=1"
                params = []
                
                # Filtres de recherche
                if search_params.get('search_term'):
                    query += " AND (value ILIKE %s OR source ILIKE %s)"
                    term = f"%{search_params['search_term']}%"
                    params.extend([term, term])
                
                if search_params.get('type'):
                    query += " AND type = %s"
                    params.append(search_params['type'])
                
                if search_params.get('min_risk_score'):
                    query += " AND risk_score >= %s"
                    params.append(search_params['min_risk_score'])
                
                query += " ORDER BY created_at DESC LIMIT 50"
                
                cursor.execute(query, params)
                iocs = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'iocs': iocs,
                    'total': len(iocs),
                    'search_params': search_params
                }
                
        except Exception as e:
            logger.error(f"Erreur search_iocs: {e}")
            return {'iocs': [], 'total': 0}

    def insert_ioc(self, ioc):
        """CORRIGÉ - Insère un IOC en base de données"""
        try:
            if not self.db_connection:
                logger.info(f"[MOCK] IOC inséré: {ioc['value']}")
                # En mode mock, ajouter à la liste en mémoire
                self._mock_iocs.append(ioc)
                return True
                
            with self.db_connection.cursor() as cursor:
                # Créer la table si elle n'existe pas
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS indicators (
                        id VARCHAR(255) PRIMARY KEY,
                        value TEXT UNIQUE NOT NULL,
                        type VARCHAR(50) NOT NULL,
                        source VARCHAR(100),
                        risk_score FLOAT DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        mitre_techniques JSONB DEFAULT '[]',
                        enrichments JSONB DEFAULT '{}',
                        confidence_level INTEGER DEFAULT 50
                    );
                """)
                
                cursor.execute("""
                    INSERT INTO indicators (
                        id, value, type, source, risk_score, 
                        created_at, mitre_techniques, enrichments, confidence_level
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (value) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        enrichments = EXCLUDED.enrichments,
                        confidence_level = EXCLUDED.confidence_level
                """, (
                    ioc['id'], ioc['value'], ioc['type'], ioc['source'],
                    ioc['risk_score'], ioc.get('created_at', datetime.now().isoformat()),
                    json.dumps(ioc.get('mitre_techniques', [])),
                    json.dumps(ioc.get('enrichments', {})),
                    ioc.get('confidence_level', 50)
                ))
                self.db_connection.commit()
                return True
                
        except Exception as e:
            logger.error(f"Erreur insert_ioc: {e}")
            if self.db_connection:
                try:
                    self.db_connection.rollback()
                except:
                    pass
            return False
class Database:
    def __init__(self):
        # Utiliser la même config que DashboardDataProcessor
        self.db_config = {
            'host': os.getenv('DB_HOST', 'cti-postgres'),
            'port': int(os.getenv('DB_PORT', 5432)),
            'database': os.getenv('DB_NAME', 'cti_db'),
            'user': os.getenv('DB_USER', 'cti_user'),
            'password': os.getenv('DB_PASSWORD', 'cti_password')
        }
        self.db_connection = None
        self._mock_alerts = []  # Initialisation du stockage mock
        self._init_connections()
        self._mock_iocs = []
    def _init_connection(self):
        try:
            import psycopg2
            self.connection = psycopg2.connect(**self.db_config)
        except Exception as e:
            print(f"Database connection error: {e}")
    
    def get_recent_indicators(self, hours=24):
        """Récupère les indicateurs récents"""
        if not self.connection:
            return []
        
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM indicators 
                    WHERE created_at >= NOW() - INTERVAL %s
                    ORDER BY created_at DESC
                """, (f'{hours} hours',))
                return cursor.fetchall()
        except Exception as e:
            print(f"Erreur get_recent_indicators: {e}")
            return []
    

    def get_recent_iocs(self, hours=24, ioc_type='all', risk_level='all'):
     try:
        if not self.db_connection:
            return self._get_mock_iocs()
        
        with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
            # Construction de la requête avec filtres
            query = """
                SELECT 
                    i.id,
                    i.value,
                    i.type,
                    i.source,
                    i.risk_score,
                    i.created_at,
                    i.mitre_techniques,
                    i.enrichments,
                    i.confidence_level
                FROM indicators i
                WHERE i.created_at >= NOW() - INTERVAL %s
            """
            params = [f'{hours} hours']
            
            # Filtre par type
            if ioc_type != 'all':
                query += " AND i.type = %s"
                params.append(ioc_type)
            
            # Filtre par niveau de risque
            if risk_level != 'all':
                risk_ranges = {
                    'critical': (8, 10),
                    'high': (6, 8),
                    'medium': (4, 6),
                    'low': (0, 4)
                }
                if risk_level in risk_ranges:
                    min_risk, max_risk = risk_ranges[risk_level]
                    query += " AND i.risk_score >= %s AND i.risk_score < %s"
                    params.extend([min_risk, max_risk])
            
            query += " ORDER BY i.created_at DESC LIMIT 100"
            
            cursor.execute(query, params)
            iocs = [dict(row) for row in cursor.fetchall()]
            
            return {
                'iocs': iocs,
                'total': len(iocs),
                'filters': {
                    'hours': hours,
                    'type': ioc_type,
                    'risk_level': risk_level
                },
                'timestamp': datetime.now().isoformat()
            }
            
     except Exception as e:
        logger.error(f"Erreur get_recent_iocs: {e}")
        return self._get_mock_iocs()

    def _get_mock_iocs(self):
     return {
        'iocs': [
            {
                'id': 'ioc_001',
                'value': '192.168.1.100',
                'type': 'ip',
                'source': 'threat_intel',
                'risk_score': 8.5,
                'created_at': datetime.now().isoformat(),
                'mitre_techniques': ['T1055', 'T1071'],
                'enrichments': {
                    'geolocation': {'country': 'CN'},
                    'reputation': 'malicious'
                },
                'confidence_level': 85
            },
            {
                'id': 'ioc_002', 
                'value': 'malicious-domain.com',
                'type': 'domain',
                'source': 'osint_feed',
                'risk_score': 7.2,
                'created_at': (datetime.now() - timedelta(hours=2)).isoformat(),
                'mitre_techniques': ['T1071'],
                'enrichments': {
                    'dns_records': ['A', 'MX'],
                    'reputation': 'suspicious'
                },
                'confidence_level': 75
            },
            {
                'id': 'ioc_003',
                'value': 'http://malicious-site.com/payload',
                'type': 'url',
                'source': 'sandbox_analysis',
                'risk_score': 9.1,
                'created_at': (datetime.now() - timedelta(minutes=30)).isoformat(),
                'mitre_techniques': ['T1071', 'T1105'],
                'enrichments': {
                    'http_status': 200,
                    'content_type': 'application/octet-stream'
                },
                'confidence_level': 95
            },
            {
                'id': 'ioc_004',
                'value': 'a1b2c3d4e5f6789012345678901234567890abcdef',
                'type': 'hash',
                'source': 'malware_analysis',
                'risk_score': 8.8,
                'created_at': (datetime.now() - timedelta(hours=1)).isoformat(),
                'mitre_techniques': ['T1204', 'T1055'],
                'enrichments': {
                    'file_type': 'PE32',
                    'malware_family': 'Trojan.Generic'
                },
                'confidence_level': 90
            }
        ],
        'total': 4,
        'status': 'mock_data'
    }

    def search_iocs(self, search_params):
     try:
        if not self.db_connection:
            # Filtrer les données mock selon les paramètres
            mock_data = self._get_mock_iocs()
            filtered_iocs = mock_data['iocs']
            
            # Appliquer les filtres sur les données mock
            if search_params.get('search_term'):
                term = search_params['search_term'].lower()
                filtered_iocs = [
                    ioc for ioc in filtered_iocs 
                    if term in ioc['value'].lower() or term in ioc['source'].lower()
                ]
            
            if search_params.get('type'):
                filtered_iocs = [
                    ioc for ioc in filtered_iocs 
                    if ioc['type'] == search_params['type']
                ]
            
            if search_params.get('min_risk_score'):
                min_risk = float(search_params['min_risk_score'])
                filtered_iocs = [
                    ioc for ioc in filtered_iocs 
                    if ioc['risk_score'] >= min_risk
                ]
            
            return {
                'iocs': filtered_iocs,
                'total': len(filtered_iocs),
                'search_params': search_params
            }
            
        with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
            query = "SELECT * FROM indicators WHERE 1=1"
            params = []
            
            # Filtres de recherche
            if search_params.get('search_term'):
                query += " AND (value ILIKE %s OR source ILIKE %s)"
                term = f"%{search_params['search_term']}%"
                params.extend([term, term])
            
            if search_params.get('type'):
                query += " AND type = %s"
                params.append(search_params['type'])
            
            if search_params.get('min_risk_score'):
                query += " AND risk_score >= %s"
                params.append(search_params['min_risk_score'])
            
            query += " ORDER BY created_at DESC LIMIT 50"
            
            cursor.execute(query, params)
            iocs = [dict(row) for row in cursor.fetchall()]
            
            return {
                'iocs': iocs,
                'total': len(iocs),
                'search_params': search_params
            }
            
     except Exception as e:
        logger.error(f"Erreur search_iocs: {e}")
        return {'iocs': [], 'total': 0}

     def insert_ioc(self, ioc):
      try:
        if not self.db_connection:
            logger.info(f"[MOCK] IOC inséré: {ioc['value']}")
            return True
            
        with self.db_connection.cursor() as cursor:
            # Créer la table si elle n'existe pas
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS indicators (
                    id VARCHAR(255) PRIMARY KEY,
                    value TEXT UNIQUE NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    source VARCHAR(100),
                    risk_score FLOAT DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    mitre_techniques JSONB DEFAULT '[]',
                    enrichments JSONB DEFAULT '{}',
                    confidence_level INTEGER DEFAULT 50
                );
            """)
            
            cursor.execute("""
                INSERT INTO indicators (
                    id, value, type, source, risk_score, 
                    created_at, mitre_techniques, enrichments, confidence_level
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (value) DO UPDATE SET
                    risk_score = EXCLUDED.risk_score,
                    enrichments = EXCLUDED.enrichments,
                    confidence_level = EXCLUDED.confidence_level
            """, (
                ioc['id'], ioc['value'], ioc['type'], ioc['source'],
                ioc['risk_score'], ioc.get('created_at', datetime.now().isoformat()),
                json.dumps(ioc.get('mitre_techniques', [])),
                json.dumps(ioc.get('enrichments', {})),
                ioc.get('confidence_level', 50)
            ))
            self.db_connection.commit()
            return True
            
      except Exception as e:
        logger.error(f"Erreur insert_ioc: {e}")
        if self.db_connection:
            try:
                self.db_connection.rollback()
            except:
                pass
        return False
    def count_technique_occurrences(self, technique, hours=1):
        """Compte les occurrences d'une technique MITRE"""
        if not self.connection:
            return 0
            
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT COUNT(*) FROM technique_incidents 
                    WHERE technique_id = %s 
                    AND incident_date >= NOW() - INTERVAL %s
                """, (technique, f'{hours} hours'))
                return cursor.fetchone()[0]
        except Exception as e:
            print(f"Erreur count_technique_occurrences: {e}")
            return 0