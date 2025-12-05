#!/usr/bin/env python3
"""
Script de vérification CTI Dashboard pour environnement Docker
Utilise les noms de conteneurs au lieu de localhost
"""

import requests
import json
import psycopg2
from psycopg2.extras import RealDictCursor
import os
from datetime import datetime, timedelta
import sys

# Configuration pour environnement Docker
DB_CONFIG = {
    'host': 'cti-postgres',  # Nom du conteneur PostgreSQL
    'port': 5432,
    'database': 'cti_db',
    'user': 'cti_user',
    'password': 'cti_password'
}

DASHBOARD_API_URL = "http://localhost:5001"  # Depuis le conteneur dashboard
OPENCTI_URL = "http://opencti:8080"  # Nom du conteneur OpenCTI
OPENCTI_TOKEN = "dd817c8c-3123-4b18-a3b6-24f4d0ef8f90"

class DockerCTIVerifier:
    def __init__(self):
        self.db_connection = None
        self.verification_results = {}
        
    def connect_to_database(self):
        """Connexion à PostgreSQL via nom de conteneur"""
        try:
            self.db_connection = psycopg2.connect(**DB_CONFIG)
            print("✅ Connexion PostgreSQL (cti-postgres) établie")
            return True
        except Exception as e:
            print(f"❌ Erreur connexion PostgreSQL: {e}")
            return False
    
    def test_dashboard_internal(self):
        """Test API dashboard depuis l'intérieur du conteneur"""
        print("\n🔍 Test API Dashboard (interne)...")
        
        endpoints = [
            "/api/dashboard/overview",
            "/api/dashboard/threats/live",
            "/api/dashboard/alerts"
        ]
        
        results = {}
        
        for endpoint in endpoints:
            try:
                response = requests.get(f"{DASHBOARD_API_URL}{endpoint}", timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    print(f"✅ {endpoint}: OK ({len(data)} clés)")
                    results[endpoint] = {'status': 'success', 'data_keys': list(data.keys()) if isinstance(data, dict) else []}
                else:
                    print(f"⚠️ {endpoint}: Code {response.status_code}")
                    results[endpoint] = {'status': 'error', 'code': response.status_code}
                    
            except Exception as e:
                print(f"❌ {endpoint}: {e}")
                results[endpoint] = {'status': 'error', 'error': str(e)}
        
        return results
    
    def verify_postgresql_tables(self):
        """Vérification détaillée des tables PostgreSQL"""
        print("\n🔍 Vérification tables PostgreSQL...")
        
        if not self.db_connection:
            return {}
        
        results = {}
        
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Vérifier l'existence des tables
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                tables = [row['table_name'] for row in cursor.fetchall()]
                print(f"📊 Tables trouvées: {tables}")
                
                results['available_tables'] = tables
                
                # Vérifier table indicators
                if 'indicators' in tables:
                    cursor.execute("SELECT COUNT(*) as count FROM indicators")
                    iocs_count = cursor.fetchone()['count']
                    print(f"📊 IOCs dans table 'indicators': {iocs_count}")
                    
                    if iocs_count > 0:
                        cursor.execute("""
                            SELECT indicator_type, COUNT(*) as count 
                            FROM indicators 
                            GROUP BY indicator_type 
                            LIMIT 10
                        """)
                        types = {row['indicator_type']: row['count'] for row in cursor.fetchall()}
                        print(f"   Types: {types}")
                        
                        # Données récentes
                        cursor.execute("""
                            SELECT COUNT(*) as count 
                            FROM indicators 
                            WHERE created_at >= NOW() - INTERVAL '24 hours'
                        """)
                        recent = cursor.fetchone()['count']
                        print(f"   Récents (24h): {recent}")
                        
                        results['indicators'] = {
                            'total': iocs_count,
                            'types': types,
                            'recent_24h': recent
                        }
                    else:
                        print("   ⚠️ Table 'indicators' vide")
                        results['indicators'] = {'total': 0, 'empty': True}
                else:
                    print("❌ Table 'indicators' non trouvée")
                    results['indicators'] = {'missing': True}
                
                # Vérifier table vulnerabilities
                if 'vulnerabilities' in tables:
                    cursor.execute("SELECT COUNT(*) as count FROM cves")
                    cves_count = cursor.fetchone()['count']
                    print(f"📊 CVEs dans table 'vulnerabilities': {cves_count}")
                    
                    if cves_count > 0:
                        cursor.execute("""
                            SELECT severity, COUNT(*) as count 
                            FROM vulnerabilities 
                            GROUP BY severity
                        """)
                        severities = {row['severity']: row['count'] for row in cursor.fetchall()}
                        print(f"   Sévérités: {severities}")
                        
                        results['vulnerabilities'] = {
                            'total': cves_count,
                            'severities': severities
                        }
                    else:
                        print("   ⚠️ Table 'vulnerabilities' vide")
                        results['vulnerabilities'] = {'total': 0, 'empty': True}
                else:
                    print("❌ Table 'vulnerabilities' non trouvée")
                    results['vulnerabilities'] = {'missing': True}
                
        except Exception as e:
            print(f"❌ Erreur vérification PostgreSQL: {e}")
            results = {'error': str(e)}
        
        return results
    
    def verify_opencti_docker(self):
        """Vérification OpenCTI via nom de conteneur"""
        print("\n🔍 Vérification OpenCTI (opencti:8080)...")
        
        try:
            headers = {
                'Authorization': f'Bearer {OPENCTI_TOKEN}',
                'Content-Type': 'application/json'
            }
            
            # Test de base
            query = {
                'query': '''
                query {
                    about {
                        version
                    }
                }
                '''
            }
            
            response = requests.post(
                f"{OPENCTI_URL}/graphql",
                json=query,
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and data['data']['about']:
                    version = data['data']['about']['version']
                    print(f"✅ OpenCTI connecté - Version: {version}")
                    
                    # Vérifier données MITRE ATT&CK
                    mitre_query = {
                        'query': '''
                        query {
                            attackPatterns(first: 10) {
                                edges {
                                    node {
                                        id
                                        name
                                        x_mitre_id
                                        kill_chain_phases {
                                            phase_name
                                            kill_chain_name
                                        }
                                    }
                                }
                            }
                        }
                        '''
                    }
                    
                    mitre_response = requests.post(
                        f"{OPENCTI_URL}/graphql",
                        json=mitre_query,
                        headers=headers,
                        timeout=15
                    )
                    
                    if mitre_response.status_code == 200:
                        mitre_data = mitre_response.json()
                        patterns = mitre_data.get('data', {}).get('attackPatterns', {}).get('edges', [])
                        print(f"📊 Techniques MITRE ATT&CK: {len(patterns)}")
                        
                        if patterns:
                            print("   Exemples de techniques:")
                            for pattern in patterns[:3]:
                                node = pattern['node']
                                mitre_id = node.get('x_mitre_id', 'N/A')
                                name = node.get('name', 'Unknown')
                                tactics = [p['phase_name'] for p in node.get('kill_chain_phases', []) 
                                         if p.get('kill_chain_name') == 'mitre-attack']
                                print(f"   - {mitre_id}: {name} ({', '.join(tactics)})")
                        
                        # Vérifier autres entités
                        entities_query = {
                            'query': '''
                            query {
                                indicators(first: 1) {
                                    pageInfo {
                                        globalCount
                                    }
                                }
                                intrusionSets(first: 1) {
                                    pageInfo {
                                        globalCount
                                    }
                                }
                                malwares(first: 1) {
                                    pageInfo {
                                        globalCount
                                    }
                                }
                            }
                            '''
                        }
                        
                        entities_response = requests.post(
                            f"{OPENCTI_URL}/graphql",
                            json=entities_query,
                            headers=headers,
                            timeout=15
                        )
                        
                        if entities_response.status_code == 200:
                            entities_data = entities_response.json()
                            indicators_count = entities_data.get('data', {}).get('indicators', {}).get('pageInfo', {}).get('globalCount', 0)
                            intrusion_sets_count = entities_data.get('data', {}).get('intrusionSets', {}).get('pageInfo', {}).get('globalCount', 0)
                            malware_count = entities_data.get('data', {}).get('malwares', {}).get('pageInfo', {}).get('globalCount', 0)
                            
                            print(f"📊 Indicateurs OpenCTI: {indicators_count}")
                            print(f"📊 Groupes d'acteurs: {intrusion_sets_count}")
                            print(f"📊 Malwares: {malware_count}")
                        
                        return {
                            'status': 'connected',
                            'version': version,
                            'mitre_techniques': len(patterns),
                            'indicators': indicators_count,
                            'intrusion_sets': intrusion_sets_count,
                            'malware': malware_count,
                            'sample_techniques': [p['node'] for p in patterns[:3]]
                        }
                    else:
                        print(f"⚠️ Erreur données MITRE: {mitre_response.status_code}")
                        return {'status': 'connected_no_mitre', 'version': version}
                else:
                    print("⚠️ Réponse OpenCTI invalide")
                    return {'status': 'invalid_response'}
            else:
                print(f"❌ OpenCTI erreur: {response.status_code}")
                print(f"   Réponse: {response.text[:200]}")
                return {'status': 'error', 'code': response.status_code}
                
        except requests.exceptions.ConnectionError:
            print("❌ OpenCTI non accessible (vérifiez que le conteneur 'opencti' est démarré)")
            return {'status': 'connection_error'}
        except Exception as e:
            print(f"❌ Erreur OpenCTI: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def test_data_flow_integration(self):
        """Test du flux de données complet"""
        print("\n🔍 Test flux de données complet...")
        
        try:
            # Test vue d'ensemble
            response = requests.get(f"{DASHBOARD_API_URL}/api/dashboard/overview", timeout=10)
            
            if response.status_code == 200:
                overview = response.json()
                
                print("📊 État des sources de données:")
                data_sources = overview.get('data_sources', {})
                postgresql_connected = data_sources.get('postgresql', False)
                opencti_connected = data_sources.get('opencti', False)
                
                print(f"   🗄️ PostgreSQL: {'✅ Connecté' if postgresql_connected else '❌ Déconnecté'}")
                print(f"   🌐 OpenCTI: {'✅ Connecté' if opencti_connected else '❌ Déconnecté'}")
                
                # Données disponibles
                print("\n📊 Données disponibles dans le dashboard:")
                print(f"   - IOCs aujourd'hui: {overview.get('total_iocs_today', 'N/A')}")
                print(f"   - Total CVEs: {overview.get('total_cves', 'N/A')}")
                print(f"   - Alertes critiques: {overview.get('critical_alerts', 'N/A')}")
                print(f"   - Techniques MITRE: {overview.get('mitre_techniques_count', 'N/A')}")
                print(f"   - Acteurs de menaces: {overview.get('threat_actors_count', 'N/A')}")
                print(f"   - Score risque moyen: {overview.get('risk_score_avg', 'N/A')}")
                print(f"   - Statut: {overview.get('status', 'N/A')}")
                
                return {
                    'integration_working': True,
                    'postgresql_connected': postgresql_connected,
                    'opencti_connected': opencti_connected,
                    'data_summary': overview
                }
            else:
                print(f"❌ Erreur overview: {response.status_code}")
                return {'integration_working': False, 'error': response.status_code}
                
        except Exception as e:
            print(f"❌ Erreur test intégration: {e}")
            return {'integration_working': False, 'error': str(e)}
    
    def generate_docker_report(self):
        """Rapport spécifique environnement Docker"""
        print("\n" + "="*70)
        print("📋 RAPPORT VERIFICATION CTI DASHBOARD - ENVIRONNEMENT DOCKER")
        print("="*70)
        
        # Résumé global
        postgresql_data = self.verification_results.get('postgresql_tables', {})
        opencti_data = self.verification_results.get('opencti_connection', {})
        integration_data = self.verification_results.get('data_integration', {})
        
        postgresql_ok = postgresql_data.get('indicators', {}).get('total', 0) > 0
        opencti_ok = opencti_data.get('status') == 'connected'
        dashboard_ok = integration_data.get('integration_working', False)
        
        print(f"🗄️ PostgreSQL (IOCs/CVEs): {'✅ OK' if postgresql_ok else '❌ Problème'}")
        print(f"🌐 OpenCTI (MITRE ATT&CK): {'✅ OK' if opencti_ok else '❌ Problème'}")
        print(f"📊 Dashboard Integration: {'✅ OK' if dashboard_ok else '❌ Problème'}")
        
        # Diagnostics détaillés
        print(f"\n🔧 DIAGNOSTICS DÉTAILLÉS:")
        
        if not postgresql_ok:
            indicators_info = postgresql_data.get('indicators', {})
            if indicators_info.get('missing'):
                print("❗ Table 'indicators' manquante - vos collectors ne créent pas la table")
            elif indicators_info.get('empty'):
                print("❗ Table 'indicators' vide - vos collectors n'injectent pas de données")
            else:
                print("❗ Problème indéterminé avec PostgreSQL")
        
        if not opencti_ok:
            if opencti_data.get('status') == 'connection_error':
                print("❗ OpenCTI non accessible - vérifiez que le conteneur 'opencti' est démarré")
            elif opencti_data.get('status') == 'error':
                print("❗ Erreur OpenCTI - vérifiez le token et la configuration")
        
        # Actions recommandées
        print(f"\n🔧 ACTIONS RECOMMANDÉES:")
        
        print("1. 📋 Vérifiez les conteneurs Docker:")
        print("   docker ps | grep -E '(cti-postgres|opencti|cti-dashboard)'")
        
        print("\n2. 🗄️ Testez PostgreSQL manuellement:")
        print("   docker exec -it cti-postgres psql -U cti_user -d cti_db -c '\\dt'")
        
        print("\n3. 🌐 Testez OpenCTI manuellement:")
        print("   curl -H 'Authorization: Bearer dd817c8c-3123-4b18-a3b6-24f4d0ef8f90' http://opencti:8080/graphql")
        
        print("\n4. 🚀 Démarrez vos collectors si pas encore fait:")
        print("   python scripts/collectors/main_collector.py")
        
        print("\n5. 📊 Accédez au dashboard web:")
        print("   http://localhost:8080 (frontend)")
        
        # Sauvegarde du rapport
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"docker_cti_verification_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.verification_results, f, indent=2, default=str)
        
        print(f"\n💾 Rapport détaillé sauvegardé: {report_file}")
        
        return {
            'postgresql_ok': postgresql_ok,
            'opencti_ok': opencti_ok,
            'dashboard_ok': dashboard_ok,
            'report_file': report_file
        }
    
    def run_docker_verification(self):
        """Vérification complète pour environnement Docker"""
        print("🐳 Vérification CTI Dashboard - Environnement Docker\n")
        
        # Tests séquentiels
        self.connect_to_database()
        
        self.verification_results['dashboard_api'] = self.test_dashboard_internal()
        self.verification_results['postgresql_tables'] = self.verify_postgresql_tables()
        self.verification_results['opencti_connection'] = self.verify_opencti_docker()
        self.verification_results['data_integration'] = self.test_data_flow_integration()
        
        # Rapport final
        summary = self.generate_docker_report()
        
        # Nettoyage
        if self.db_connection:
            self.db_connection.close()
        
        return summary

def main():
    """Fonction principale pour Docker"""
    verifier = DockerCTIVerifier()
    
    try:
        summary = verifier.run_docker_verification()
        
        # Code de sortie
        if all([summary['postgresql_ok'], summary['opencti_ok'], summary['dashboard_ok']]):
            print("\n🎉 Toutes les vérifications Docker sont OK !")
            sys.exit(0)
        else:
            print("\n⚠️ Des problèmes ont été détectés dans l'environnement Docker.")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n⛔ Vérification interrompue")
        sys.exit(2)
    except Exception as e:
        print(f"\n❌ Erreur critique: {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()