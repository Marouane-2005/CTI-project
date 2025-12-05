#!/usr/bin/env python3
"""
Script de test pour vérifier la détection d'attaques dans le système CTI
Usage: python test_detection.py [--mode MODE] [--verbose]
"""

import asyncio
import json
import time
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
import sys
import os
from datetime import datetime, timedelta
import argparse
import logging
from typing import Dict, List, Any
import threading
import websocket
import hashlib
import random

# Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'cti-postgres'),
    'port': int(os.getenv('DB_PORT', 5432)),
    'database': os.getenv('DB_NAME', 'cti_db'),
    'user': os.getenv('DB_USER', 'cti_user'),
    'password': os.getenv('DB_PASSWORD', 'cti_password')
}

DASHBOARD_API_URL = os.getenv('DASHBOARD_API_URL', 'http://localhost:5001')
WEBSOCKET_URL = os.getenv('WEBSOCKET_URL', 'ws://localhost:5001')

class CTIDetectionTester:
    """Testeur de détection d'attaques CTI"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.db_connection = None
        self.test_results = []
        self.websocket_messages = []
        self.setup_logging()
        
    def setup_logging(self):
        """Configuration du logging"""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - [%(levelname)s] - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        self.logger = logging.getLogger(__name__)
        
    def connect_database(self):
        """Connexion à la base de données"""
        try:
            self.db_connection = psycopg2.connect(**DB_CONFIG)
            self.logger.info("✅ Connexion PostgreSQL établie")
            return True
        except Exception as e:
            self.logger.error(f"❌ Erreur connexion DB: {e}")
            return False
            
    def create_test_indicators(self) -> List[Dict]:
        """Création d'indicateurs de test malveillants"""
        test_iocs = [
            {
                'type': 'ip',
                'value': '192.168.100.200',
                'source': 'test_simulation',
                'threat_level': 'high',
                'description': 'IP de test - Botnet Command & Control',
                'mitre_techniques': ['T1071.001', 'T1041'],
                'tags': ['botnet', 'c2', 'test']
            },
            {
                'type': 'domain',
                'value': 'malicious-test-domain.evil',
                'source': 'test_simulation',
                'threat_level': 'critical',
                'description': 'Domaine de test - Phishing',
                'mitre_techniques': ['T1566.002', 'T1204.001'],
                'tags': ['phishing', 'test']
            },
            {
                'type': 'hash',
                'value': hashlib.md5(f"test_malware_{time.time()}".encode()).hexdigest(),
                'source': 'test_simulation',
                'threat_level': 'high',
                'description': 'Hash de test - Ransomware',
                'mitre_techniques': ['T1486', 'T1083'],
                'tags': ['ransomware', 'test']
            },
            {
                'type': 'email',
                'value': 'attacker@evil-domain.test',
                'source': 'test_simulation',
                'threat_level': 'medium',
                'description': 'Email de test - Spear Phishing',
                'mitre_techniques': ['T1566.001'],
                'tags': ['spear-phishing', 'test']
            },
            {
                'type': 'url',
                'value': 'https://malicious-site.test/payload.exe',
                'source': 'test_simulation',
                'threat_level': 'critical',
                'description': 'URL de test - Malware Download',
                'mitre_techniques': ['T1204.002', 'T1105'],
                'tags': ['malware-download', 'test']
            }
        ]
        
        self.logger.info(f"📝 Générés {len(test_iocs)} indicateurs de test")
        return test_iocs
        
    def inject_test_iocs(self, iocs: List[Dict]) -> bool:
        """Injection des IOCs de test dans la base"""
        if not self.db_connection:
            self.logger.error("❌ Pas de connexion DB")
            return False
            
        try:
            with self.db_connection.cursor() as cursor:
                for ioc in iocs:
                    # Vérifier si l'IOC existe déjà
                    cursor.execute(
                        "SELECT id FROM indicators WHERE value = %s AND source = %s",
                        (ioc['value'], ioc['source'])
                    )
                    
                    if cursor.fetchone():
                        self.logger.debug(f"IOC {ioc['value']} existe déjà")
                        continue
                        
                    # Insérer l'IOC
                    insert_query = """
                        INSERT INTO indicators (
                            type, value, source, threat_level, description, 
                            first_seen, last_seen, confidence, tags, metadata
                        ) VALUES (
                            %s, %s, %s, %s, %s, 
                            %s, %s, %s, %s, %s
                        ) RETURNING id
                    """
                    
                    metadata = {
                        'mitre_techniques': ioc.get('mitre_techniques', []),
                        'test_simulation': True
                    }
                    
                    cursor.execute(insert_query, (
                        ioc['type'],
                        ioc['value'],
                        ioc['source'],
                        ioc['threat_level'],
                        ioc['description'],
                        datetime.now(),
                        datetime.now(),
                        90,  # Confiance élevée pour les tests
                        ioc.get('tags', []),
                        json.dumps(metadata)
                    ))
                    
                    ioc_id = cursor.fetchone()[0]
                    ioc['id'] = ioc_id
                    
                    self.logger.debug(f"✅ IOC injecté: {ioc['value']} (ID: {ioc_id})")
                    
            self.db_connection.commit()
            self.logger.info(f"✅ {len(iocs)} IOCs de test injectés")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erreur injection IOCs: {e}")
            self.db_connection.rollback()
            return False
            
    def test_api_detection(self) -> Dict:
        """Test de détection via l'API dashboard"""
        results = {
            'api_accessible': False,
            'overview_working': False,
            'threats_detected': False,
            'alerts_generated': False,
            'mitre_data_available': False
        }
        
        try:
            # Test connexion API
            response = requests.get(f"{DASHBOARD_API_URL}/api/test", timeout=10)
            if response.status_code == 200:
                results['api_accessible'] = True
                self.logger.info("✅ API dashboard accessible")
            else:
                self.logger.error(f"❌ API non accessible: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur connexion API: {e}")
            
        if not results['api_accessible']:
            return results
            
        try:
            # Test overview
            response = requests.get(f"{DASHBOARD_API_URL}/api/dashboard/overview", timeout=10)
            if response.status_code == 200:
                data = response.json()
                results['overview_working'] = True
                self.logger.info("✅ Dashboard overview fonctionne")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur overview: {e}")
            
        try:
            # Test menaces en temps réel
            response = requests.get(f"{DASHBOARD_API_URL}/api/dashboard/threats/live", timeout=10)
            if response.status_code == 200:
                data = response.json()
                threats_count = len(data.get('threats', []))
                results['threats_detected'] = threats_count > 0
                self.logger.info(f"📊 {threats_count} menaces détectées")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur menaces live: {e}")
            
        try:
            # Test alertes
            response = requests.get(f"{DASHBOARD_API_URL}/api/dashboard/alerts", timeout=10)
            if response.status_code == 200:
                data = response.json()
                alerts_count = len(data.get('alerts', []))
                results['alerts_generated'] = alerts_count > 0
                self.logger.info(f"🚨 {alerts_count} alertes générées")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur alertes: {e}")
            
        try:
            # Test données MITRE
            response = requests.get(f"{DASHBOARD_API_URL}/api/dashboard/mitre/overview", timeout=10)
            if response.status_code == 200:
                data = response.json()
                results['mitre_data_available'] = data.get('overview', {}).get('total_techniques', 0) > 0
                self.logger.info("✅ Données MITRE disponibles")
                
        except Exception as e:
            self.logger.error(f"❌ Erreur MITRE: {e}")
            
        return results
        
    def test_websocket_alerts(self, timeout=30) -> Dict:
        """Test des alertes WebSocket temps réel"""
        results = {
            'websocket_connected': False,
            'real_time_alerts': False,
            'messages_received': 0
        }
        
        def on_message(ws, message):
            try:
                data = json.loads(message)
                self.websocket_messages.append(data)
                self.logger.debug(f"WebSocket message: {data.get('type', 'unknown')}")
            except:
                pass
                
        def on_error(ws, error):
            self.logger.error(f"WebSocket error: {error}")
            
        def on_open(ws):
            results['websocket_connected'] = True
            self.logger.info("✅ WebSocket connecté")
            
            # S'abonner aux alertes
            ws.send(json.dumps({
                'type': 'subscribe',
                'channels': ['threats', 'alerts', 'iocs']
            }))
            
        try:
            ws = websocket.WebSocketApp(
                f"{WEBSOCKET_URL.replace('http://', 'ws://')}/socket.io/?EIO=4&transport=websocket",
                on_message=on_message,
                on_error=on_error,
                on_open=on_open
            )
            
            # Lancer WebSocket dans un thread
            ws_thread = threading.Thread(target=ws.run_forever)
            ws_thread.daemon = True
            ws_thread.start()
            
            # Attendre les messages
            start_time = time.time()
            while (time.time() - start_time) < timeout:
                time.sleep(1)
                if len(self.websocket_messages) > 0:
                    results['real_time_alerts'] = True
                    break
                    
            results['messages_received'] = len(self.websocket_messages)
            ws.close()
            
        except Exception as e:
            self.logger.error(f"❌ Erreur WebSocket: {e}")
            
        return results
        
    def verify_alert_engine(self) -> Dict:
        """Vérification du moteur d'alertes"""
        results = {
            'alert_rules_exist': False,
            'risk_calculation_working': False,
            'mitre_mapping_working': False,
            'total_alerts_generated': 0
        }
        
        if not self.db_connection:
            return results
            
        try:
            with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Vérifier les règles d'alerte
                cursor.execute("SELECT COUNT(*) as count FROM alert_rules WHERE enabled = true")
                rule_count = cursor.fetchone()['count']
                results['alert_rules_exist'] = rule_count > 0
                self.logger.info(f"📋 {rule_count} règles d'alerte actives")
                
                # Vérifier les alertes générées récemment
                cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM alerts 
                    WHERE created_at >= %s
                """, (datetime.now() - timedelta(hours=1),))
                
                recent_alerts = cursor.fetchone()['count']
                results['total_alerts_generated'] = recent_alerts
                
                # Vérifier le mapping MITRE
                cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM indicators i
                    JOIN mitre_techniques mt ON i.metadata->>'mitre_techniques' LIKE '%' || mt.technique_id || '%'
                    WHERE i.source = 'test_simulation'
                """)
                
                mitre_mapped = cursor.fetchone()['count']
                results['mitre_mapping_working'] = mitre_mapped > 0
                
        except Exception as e:
            self.logger.error(f"❌ Erreur vérification moteur alertes: {e}")
            
        return results
        
    def simulate_attack_scenario(self) -> Dict:
        """Simulation d'un scénario d'attaque complet"""
        self.logger.info("🎭 Simulation d'un scénario d'attaque multi-étapes")
        
        # Scénario: Attaque APT avec phishing -> payload -> C2
        attack_chain = [
            {
                'step': 1,
                'name': 'Initial Access - Phishing Email',
                'ioc': {
                    'type': 'email',
                    'value': 'ceo@legitimate-bank.evil',
                    'threat_level': 'high',
                    'mitre_techniques': ['T1566.002'],
                    'description': 'Spear phishing targeting executives'
                }
            },
            {
                'step': 2,
                'name': 'Execution - Malicious Payload',
                'ioc': {
                    'type': 'hash',
                    'value': hashlib.sha256(f"apt_payload_{time.time()}".encode()).hexdigest(),
                    'threat_level': 'critical',
                    'mitre_techniques': ['T1204.002', 'T1059.001'],
                    'description': 'PowerShell-based payload delivery'
                }
            },
            {
                'step': 3,
                'name': 'Command and Control',
                'ioc': {
                    'type': 'domain',
                    'value': 'apt-c2-server.malicious',
                    'threat_level': 'critical',
                    'mitre_techniques': ['T1071.001', 'T1041'],
                    'description': 'APT Command & Control server'
                }
            },
            {
                'step': 4,
                'name': 'Data Exfiltration',
                'ioc': {
                    'type': 'ip',
                    'value': '203.0.113.100',
                    'threat_level': 'critical',
                    'mitre_techniques': ['T1041', 'T1567.002'],
                    'description': 'Data exfiltration endpoint'
                }
            }
        ]
        
        results = {
            'scenario_executed': False,
            'steps_detected': 0,
            'total_steps': len(attack_chain),
            'detection_rate': 0.0,
            'response_time_avg': 0.0
        }
        
        detected_steps = 0
        response_times = []
        
        for step_data in attack_chain:
            step_num = step_data['step']
            step_name = step_data['name']
            ioc = step_data['ioc']
            
            self.logger.info(f"🎯 Étape {step_num}: {step_name}")
            
            # Injection de l'IOC avec timing
            start_time = time.time()
            
            ioc.update({
                'source': 'apt_simulation',
                'tags': ['apt', 'simulation', f'step_{step_num}']
            })
            
            if self.inject_test_iocs([ioc]):
                # Attendre et vérifier la détection
                time.sleep(2)  # Laisser le temps au système de traiter
                
                # Vérifier si des alertes ont été générées
                if self.check_ioc_detection(ioc['value']):
                    detected_steps += 1
                    response_time = time.time() - start_time
                    response_times.append(response_time)
                    self.logger.info(f"✅ Étape {step_num} détectée en {response_time:.2f}s")
                else:
                    self.logger.warning(f"⚠️ Étape {step_num} non détectée")
            else:
                self.logger.error(f"❌ Échec injection étape {step_num}")
                
            # Délai entre les étapes pour simulation réaliste
            time.sleep(3)
            
        results.update({
            'scenario_executed': True,
            'steps_detected': detected_steps,
            'detection_rate': (detected_steps / len(attack_chain)) * 100,
            'response_time_avg': sum(response_times) / len(response_times) if response_times else 0
        })
        
        return results
        
    def check_ioc_detection(self, ioc_value: str) -> bool:
        """Vérifier si un IOC a été détecté et a généré des alertes"""
        if not self.db_connection:
            return False
            
        try:
            with self.db_connection.cursor() as cursor:
                # Chercher l'IOC et les alertes associées
                cursor.execute("""
                    SELECT 
                        i.id,
                        COUNT(a.id) as alert_count
                    FROM indicators i
                    LEFT JOIN alerts a ON a.indicator_id = i.id
                    WHERE i.value = %s
                    GROUP BY i.id
                """, (ioc_value,))
                
                result = cursor.fetchone()
                return result and result[1] > 0
                
        except Exception as e:
            self.logger.error(f"Erreur vérification détection: {e}")
            return False
            
    def cleanup_test_data(self):
        """Nettoyage des données de test"""
        if not self.db_connection:
            return
            
        try:
            with self.db_connection.cursor() as cursor:
                # Supprimer les IOCs de test
                cursor.execute("""
                    DELETE FROM indicators 
                    WHERE source IN ('test_simulation', 'apt_simulation')
                """)
                
                deleted_count = cursor.rowcount
                self.db_connection.commit()
                self.logger.info(f"🧹 {deleted_count} IOCs de test supprimés")
                
        except Exception as e:
            self.logger.error(f"Erreur nettoyage: {e}")
            
    def generate_test_report(self) -> Dict:
        """Génération du rapport de test"""
        report = {
            'test_timestamp': datetime.now().isoformat(),
            'test_duration': '0m 0s',
            'overall_score': 0,
            'categories': {},
            'recommendations': [],
            'summary': ''
        }
        
        # Calculer le score global
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result.get('passed', False))
        
        if total_tests > 0:
            report['overall_score'] = (passed_tests / total_tests) * 100
            
        # Recommandations basées sur les résultats
        if report['overall_score'] < 70:
            report['recommendations'].append("⚠️ Système de détection nécessite des améliorations")
        if report['overall_score'] >= 85:
            report['recommendations'].append("✅ Excellent niveau de détection")
            
        report['summary'] = f"Score global: {report['overall_score']:.1f}% ({passed_tests}/{total_tests} tests réussis)"
        
        return report
        
    def run_comprehensive_test(self, cleanup=True):
        """Exécution complète des tests"""
        self.logger.info("🚀 Démarrage des tests de détection CTI")
        start_time = time.time()
        
        # Connexion DB
        if not self.connect_database():
            self.logger.error("❌ Impossible de se connecter à la base de données")
            return False
            
        try:
            # 1. Test des IOCs basiques
            self.logger.info("\n=== Test 1: Injection d'IOCs malveillants ===")
            test_iocs = self.create_test_indicators()
            if self.inject_test_iocs(test_iocs):
                self.test_results.append({'test': 'ioc_injection', 'passed': True})
            else:
                self.test_results.append({'test': 'ioc_injection', 'passed': False})
                
            # 2. Test API Dashboard
            self.logger.info("\n=== Test 2: API Dashboard ===")
            api_results = self.test_api_detection()
            for key, value in api_results.items():
                self.test_results.append({'test': f'api_{key}', 'passed': value})
                
            # 3. Test moteur d'alertes
            self.logger.info("\n=== Test 3: Moteur d'alertes ===")
            alert_results = self.verify_alert_engine()
            for key, value in alert_results.items():
                if isinstance(value, bool):
                    self.test_results.append({'test': f'alert_{key}', 'passed': value})
                    
            # 4. Test WebSocket (optionnel - peut être lent)
            # self.logger.info("\n=== Test 4: WebSocket temps réel ===")
            # ws_results = self.test_websocket_alerts(timeout=15)
            
            # 5. Simulation d'attaque
            self.logger.info("\n=== Test 5: Simulation d'attaque APT ===")
            attack_results = self.simulate_attack_scenario()
            self.test_results.append({
                'test': 'apt_simulation', 
                'passed': attack_results['detection_rate'] >= 75,
                'details': attack_results
            })
            
            # Génération du rapport
            duration = time.time() - start_time
            report = self.generate_test_report()
            report['test_duration'] = f"{int(duration//60)}m {int(duration%60)}s"
            
            # Affichage des résultats
            self.print_test_results(report)
            
        finally:
            # Nettoyage
            if cleanup:
                self.cleanup_test_data()
                
            if self.db_connection:
                self.db_connection.close()
                
        return True
        
    def print_test_results(self, report: Dict):
        """Affichage formaté des résultats"""
        print("\n" + "="*60)
        print("🛡️  RAPPORT DE TEST - DÉTECTION CTI")
        print("="*60)
        print(f"⏱️  Durée: {report['test_duration']}")
        print(f"📊 Score global: {report['overall_score']:.1f}%")
        print(f"📋 {report['summary']}")
        
        print("\n📈 DÉTAIL DES TESTS:")
        for result in self.test_results:
            status = "✅" if result['passed'] else "❌"
            test_name = result['test'].replace('_', ' ').title()
            print(f"  {status} {test_name}")
            
            if 'details' in result:
                details = result['details']
                if isinstance(details, dict):
                    for key, value in details.items():
                        if isinstance(value, (int, float)):
                            print(f"     • {key}: {value}")
                            
        print("\n💡 RECOMMANDATIONS:")
        for rec in report['recommendations']:
            print(f"  {rec}")
            
        print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(description='Test de détection CTI')
    parser.add_argument('--mode', choices=['quick', 'full'], default='full',
                       help='Mode de test (quick=basique, full=complet)')
    parser.add_argument('--verbose', action='store_true',
                       help='Mode verbeux')
    parser.add_argument('--no-cleanup', action='store_true',
                       help='Ne pas nettoyer les données de test')
    
    args = parser.parse_args()
    
    tester = CTIDetectionTester(verbose=args.verbose)
    
    if args.mode == 'quick':
        # Tests rapides uniquement
        tester.connect_database()
        test_iocs = tester.create_test_indicators()
        success = tester.inject_test_iocs(test_iocs)
        api_results = tester.test_api_detection()
        
        print(f"\n🔍 Test rapide - IOCs injectés: {'✅' if success else '❌'}")
        print(f"🌐 API accessible: {'✅' if api_results['api_accessible'] else '❌'}")
        
        if not args.no_cleanup:
            tester.cleanup_test_data()
    else:
        # Tests complets
        tester.run_comprehensive_test(cleanup=not args.no_cleanup)

if __name__ == "__main__":
    main()