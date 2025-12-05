#!/usr/bin/env python3
"""
Script de test CTI CORRIGÉ pour créer des alertes dans le bon endpoint
Version qui stocke les alertes dans /api/dashboard/alerts
"""

import psycopg2
import requests
import json
import time
import random
from datetime import datetime, timedelta
from psycopg2.extras import RealDictCursor

class CTIDetectionTesterFixed:
    def __init__(self):
        # Configuration base de données
        self.db_config = {
            'host': 'cti-postgres',
            'port': 5432,
            'database': 'cti_db',
            'user': 'cti_user', 
            'password': 'cti_password'
        }
        
        # Configuration API Dashboard
        self.api_url = 'http://localhost:5001'
        
        self.connection = None
        self.connect_db()
    
    def connect_db(self):
        """Connexion à PostgreSQL"""
        try:
            self.connection = psycopg2.connect(**self.db_config)
            print("✅ Connexion DB réussie")
        except Exception as e:
            print(f"❌ Erreur connexion DB: {e}")
    
    def test_api_connection(self):
        """Test connexion API Dashboard"""
        try:
            response = requests.get(f"{self.api_url}/api/test", timeout=5)
            if response.status_code == 200:
                print("✅ API Dashboard accessible")
                return True
            else:
                print(f"⚠️ API Dashboard retourne {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ API Dashboard inaccessible: {e}")
            return False
    
    def create_alerts_directly_in_db(self, alerts):
        """Insérer les alertes directement dans la base de données"""
        if not self.connection:
            print("⚠️ Pas de connexion DB, impossible d'insérer")
            return 0
        
        successful_inserts = 0
        
        try:
            with self.connection.cursor() as cursor:
                # Vérifier si la table alerts existe
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'alerts'
                    );
                """)
                
                table_exists = cursor.fetchone()[0]
                
                if not table_exists:
                    # Créer la table alerts
                    cursor.execute("""
                        CREATE TABLE alerts (
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
                    print("✅ Table 'alerts' créée")
                
                # Insérer chaque alerte
                for alert in alerts:
                    try:
                        cursor.execute("""
                            INSERT INTO alerts (
                                id, level, title, description, timestamp, 
                                acknowledged, source, indicator_data, mitre_data, detection_method
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (id) DO UPDATE SET
                                level = EXCLUDED.level,
                                title = EXCLUDED.title,
                                description = EXCLUDED.description
                        """, (
                            alert['id'],
                            alert['level'],
                            alert['title'],
                            alert['description'],
                            alert['timestamp'],
                            alert['acknowledged'],
                            alert['source'],
                            json.dumps(alert.get('indicator_data', {})),
                            json.dumps(alert.get('mitre_data', {})),
                            alert.get('detection_method', 'test_engine')
                        ))
                        successful_inserts += 1
                        print(f"  ✅ Alerte insérée: {alert['title'][:50]}...")
                    except Exception as e:
                        print(f"  ❌ Erreur insertion alerte: {e}")
                
                # Valider les changements
                self.connection.commit()
                print(f"✅ {successful_inserts} alertes insérées en base")
                
        except Exception as e:
            print(f"❌ Erreur création alertes DB: {e}")
            if self.connection:
                self.connection.rollback()
        
        return successful_inserts
    
    def send_alerts_via_api(self, alerts):
        """Envoyer les alertes via l'API REST"""
        successful_sends = 0
        
        for i, alert in enumerate(alerts, 1):
            try:
                # Essayer plusieurs endpoints
                endpoints_to_try = [
                    '/api/dashboard/alerts',
                    '/api/dashboard/alerts/create'
                ]
                
                alert_sent = False
                
                for endpoint in endpoints_to_try:
                    try:
                        response = requests.post(
                            f"{self.api_url}{endpoint}",
                            json=alert,
                            headers={"Content-Type": "application/json"},
                            timeout=10
                        )
                        
                        if response.status_code in [200, 201]:
                            print(f"  ✅ Alerte {i} envoyée via {endpoint}: {alert['title'][:40]}...")
                            successful_sends += 1
                            alert_sent = True
                            break
                        else:
                            print(f"  ⚠️ Endpoint {endpoint} retourne {response.status_code}")
                    
                    except Exception as endpoint_error:
                        print(f"  ❌ Erreur {endpoint}: {endpoint_error}")
                
                if not alert_sent:
                    print(f"  ❌ Échec envoi alerte {i} via API")
                
                time.sleep(0.2)  # Pause entre envois
                
            except Exception as e:
                print(f"❌ Erreur générale envoi alerte {i}: {e}")
        
        return successful_sends
    
    def verify_alerts_in_dashboard(self):
        """Vérifier que les alertes sont bien dans le dashboard"""
        try:
            response = requests.get(f"{self.api_url}/api/dashboard/alerts", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                alerts = data.get('alerts', [])
                total = len(alerts)
                
                print(f"✅ Vérification: {total} alerte(s) dans le dashboard")
                
                # Afficher les alertes récentes
                recent_alerts = sorted(alerts, key=lambda x: x.get('timestamp', ''), reverse=True)[:5]
                
                for i, alert in enumerate(recent_alerts, 1):
                    status_icon = "🔴" if not alert.get('acknowledged', False) else "🟢"
                    level = alert.get('level', 'unknown').upper()
                    title = alert.get('title', 'Sans titre')[:50]
                    timestamp = alert.get('timestamp', 'N/A')[:19]  # Format datetime
                    
                    print(f"  [{i}] {status_icon} {level} - {title} ({timestamp})")
                
                return total
            else:
                print(f"❌ Erreur vérification alertes: Status {response.status_code}")
                return 0
                
        except Exception as e:
            print(f"❌ Erreur vérification dashboard: {e}")
            return 0
    
    def generate_test_alerts(self):
        """Générer des alertes de test réalistes"""
        alerts = []
        
        # Alertes basées sur indicateurs
        indicators = [
            {
                'value': '192.168.100.50',
                'type': 'ip',
                'confidence': 95,
                'malware_family': 'apt28',
                'tags': ['apt', 'c2-server', 'malicious']
            },
            {
                'value': 'malware-download.evil',
                'type': 'domain', 
                'confidence': 88,
                'malware_family': 'emotet',
                'tags': ['phishing', 'trojan', 'campaign']
            },
            {
                'value': 'c4f3e2d1a098b7654321fedcba0987654321abcd',
                'type': 'hash',
                'confidence': 92,
                'malware_family': 'ransomware',
                'tags': ['malware', 'encryption', 'backdoor']
            }
        ]
        
        for i, indicator in enumerate(indicators, 1):
            risk_score = self.calculate_indicator_risk_score(indicator)
            level = self.risk_score_to_alert_level(risk_score)
            
            alert = {
                'id': f'test_indicator_alert_{i}_{int(datetime.now().timestamp())}',
                'level': level,
                'title': f'IOC Détecté: {indicator["type"].upper()} - {indicator["value"]}',
                'description': f'Indicateur malveillant détecté avec score de risque {risk_score:.1f}/10. '
                             f'Famille: {indicator["malware_family"]}. Confiance: {indicator["confidence"]}%.',
                'timestamp': datetime.now().isoformat(),
                'acknowledged': False,
                'source': 'test_detection_engine',
                'indicator_data': indicator,
                'detection_method': 'signature_analysis'
            }
            alerts.append(alert)
        
        # Alertes MITRE ATT&CK
        mitre_techniques = [
            {'id': 'T1566', 'name': 'Phishing', 'tactic': 'initial-access'},
            {'id': 'T1055', 'name': 'Process Injection', 'tactic': 'defense-evasion'},
            {'id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'command-and-control'}
        ]
        
        for i, technique in enumerate(mitre_techniques, 4):
            alert = {
                'id': f'test_mitre_alert_{i}_{int(datetime.now().timestamp())}',
                'level': random.choice(['high', 'critical', 'medium']),
                'title': f'Technique MITRE: {technique["name"]} ({technique["id"]})',
                'description': f'Activité suspecte détectée utilisant la technique {technique["id"]} - '
                             f'{technique["name"]}. Tactique: {technique["tactic"]}',
                'timestamp': datetime.now().isoformat(),
                'acknowledged': False,
                'source': 'mitre_detection_engine',
                'mitre_data': technique,
                'detection_method': 'behavioral_analysis'
            }
            alerts.append(alert)
        
        return alerts
    
    def calculate_indicator_risk_score(self, indicator):
        """Calcule le score de risque d'un indicateur"""
        base_score = 5.0
        
        # Bonus confiance
        confidence = indicator.get('confidence', 50)
        if confidence > 90:
            base_score += 3.0
        elif confidence > 80:
            base_score += 2.0
        elif confidence > 70:
            base_score += 1.0
        
        # Bonus famille malware
        malware_family = indicator.get('malware_family', '').lower()
        high_risk_families = ['apt28', 'apt29', 'emotet', 'ransomware', 'fancy_bear']
        if any(family in malware_family for family in high_risk_families):
            base_score += 2.5
        
        # Bonus tags
        tags = indicator.get('tags', [])
        dangerous_tags = ['apt', 'trojan', 'backdoor', 'c2', 'malware', 'ransomware']
        tag_bonus = sum(0.5 for tag in dangerous_tags if tag in tags)
        base_score += min(tag_bonus, 2.0)
        
        return round(min(base_score, 10.0), 1)
    
    def risk_score_to_alert_level(self, score):
        """Convertit le score de risque en niveau d'alerte"""
        if score >= 8.5:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 5.0:
            return 'medium'
        else:
            return 'low'
    
    def run_complete_test(self):
        """Test complet avec insertion directe en base"""
        print("🚀 === TEST CTI DÉTECTION CORRIGÉ ===")
        print(f"⏰ Démarré à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 1. Vérification API
        if not self.test_api_connection():
            print("❌ Test arrêté - API inaccessible")
            return
        
        # 2. Générer alertes
        print("\n📊 Phase 1: Génération des alertes de test")
        alerts = self.generate_test_alerts()
        print(f"✅ {len(alerts)} alertes générées")
        
        # 3. Compter les alertes actuelles
        print(f"\n🔍 Phase 2: Vérification état initial")
        initial_count = self.verify_alerts_in_dashboard()
        
        # 4. Insérer en base ET via API
        print(f"\n💾 Phase 3: Insertion des alertes")
        
        # Méthode 1: Insertion directe en base
        db_inserts = self.create_alerts_directly_in_db(alerts)
        
        # Méthode 2: Envoi via API (en parallèle)
        api_sends = self.send_alerts_via_api(alerts[:2])  # Test avec 2 alertes seulement
        
        # 5. Vérification finale
        print(f"\n🔍 Phase 4: Vérification finale")
        time.sleep(2)  # Laisser le temps à l'API de traiter
        final_count = self.verify_alerts_in_dashboard()
        
        # 6. Résultats
        print(f"\n📊 === RÉSULTATS FINAUX ===")
        print(f"✅ Alertes générées: {len(alerts)}")
        print(f"✅ Insertions DB réussies: {db_inserts}")
        print(f"✅ Envois API réussis: {api_sends}")
        print(f"📈 Alertes avant test: {initial_count}")
        print(f"📈 Alertes après test: {final_count}")
        print(f"📈 Nouvelles alertes créées: {final_count - initial_count}")
        
        if final_count > initial_count:
            print(f"\n🎉 TEST RÉUSSI!")
            print(f"✅ {final_count - initial_count} nouvelles alertes visibles dans le dashboard")
            print(f"🌐 Vérifiez: http://localhost:8083/api/dashboard/alerts")
            print(f"🖥️ Dashboard Web: http://localhost:8083")
        else:
            print(f"\n⚠️ TEST PARTIELLEMENT RÉUSSI")
            print(f"Les alertes ont été générées mais peuvent ne pas être visibles")
            print(f"Vérifiez les logs du backend et la structure de la base")
        
        print(f"⏱️ Test terminé à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Point d'entrée principal"""
    print("🔧 CTI Detection Tester - Version Corrigée pour Dashboard")
    print("=" * 60)
    
    tester = CTIDetectionTesterFixed()
    
    try:
        tester.run_complete_test()
    except KeyboardInterrupt:
        print("\n⏹️ Test interrompu par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if tester.connection:
            tester.connection.close()
            print("🔌 Connexion DB fermée")

if __name__ == "__main__":
    main()