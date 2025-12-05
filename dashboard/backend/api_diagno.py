#!/usr/bin/env python3
"""
Script de diagnostic pour identifier pourquoi les alertes ne sont pas visibles
dans l'API malgré leur présence en base de données
"""

import psycopg2
import requests
import json
import traceback
from datetime import datetime
from psycopg2.extras import RealDictCursor

class CTIDiagnostic:
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
    
    def check_database_alerts(self):
        """Vérifier les alertes directement en base"""
        print("\n🔍 === DIAGNOSTIC BASE DE DONNÉES ===")
        
        if not self.connection:
            print("❌ Pas de connexion DB")
            return
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Vérifier si la table existe
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'alerts'
                    );
                """)
                
                table_exists = cursor.fetchone()[0]
                print(f"📋 Table 'alerts' existe: {table_exists}")
                
                if not table_exists:
                    print("❌ La table 'alerts' n'existe pas!")
                    return
                
                # Compter les alertes
                cursor.execute("SELECT COUNT(*) as total FROM alerts;")
                total_count = cursor.fetchone()['total']
                print(f"📊 Total alertes en DB: {total_count}")
                
                # Afficher la structure de la table
                cursor.execute("""
                    SELECT column_name, data_type, is_nullable 
                    FROM information_schema.columns 
                    WHERE table_name = 'alerts'
                    ORDER BY ordinal_position;
                """)
                
                columns = cursor.fetchall()
                print(f"\n📋 Structure de la table 'alerts':")
                for col in columns:
                    print(f"  - {col['column_name']}: {col['data_type']} ({'NULL' if col['is_nullable'] == 'YES' else 'NOT NULL'})")
                
                # Afficher quelques alertes récentes
                cursor.execute("""
                    SELECT id, level, title, description, timestamp, acknowledged, source
                    FROM alerts 
                    ORDER BY timestamp DESC 
                    LIMIT 5;
                """)
                
                alerts = cursor.fetchall()
                print(f"\n📨 Dernières alertes en DB:")
                for i, alert in enumerate(alerts, 1):
                    status = "🟢" if alert['acknowledged'] else "🔴"
                    print(f"  [{i}] {status} {alert['level'].upper()} - {alert['title'][:50]}")
                    print(f"      ID: {alert['id']}")
                    print(f"      Source: {alert['source']}")
                    print(f"      Timestamp: {alert['timestamp']}")
                    print()
                
        except Exception as e:
            print(f"❌ Erreur diagnostic DB: {e}")
            traceback.print_exc()
    
    def check_api_responses(self):
        """Tester différents endpoints API"""
        print("\n🌐 === DIAGNOSTIC API ===")
        
        endpoints_to_test = [
            '/api/test',
            '/api/dashboard/alerts',
            '/api/dashboard/alerts/create',
            '/api/alerts',
            '/health'
        ]
        
        for endpoint in endpoints_to_test:
            try:
                print(f"\n🔗 Test endpoint: {endpoint}")
                
                # Test GET
                response = requests.get(f"{self.api_url}{endpoint}", timeout=10)
                print(f"   GET {response.status_code}: {response.reason}")
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if endpoint == '/api/dashboard/alerts':
                            alerts_count = len(data.get('alerts', []))
                            print(f"   📊 Alertes retournées: {alerts_count}")
                            
                            # Afficher les alertes de l'API
                            alerts = data.get('alerts', [])
                            for i, alert in enumerate(alerts[:3], 1):
                                print(f"      [{i}] {alert.get('level', 'N/A')} - {alert.get('title', 'N/A')[:40]}")
                        else:
                            print(f"   📄 Réponse: {str(data)[:100]}...")
                    except:
                        print(f"   📄 Réponse (text): {response.text[:200]}...")
                else:
                    print(f"   ❌ Erreur: {response.text[:200]}")
                    
            except Exception as e:
                print(f"   ❌ Exception: {e}")
    
    def test_alert_creation_via_api(self):
        """Tester la création d'une alerte via API"""
        print("\n📝 === TEST CRÉATION ALERTE VIA API ===")
        
        test_alert = {
            'id': f'diagnostic_test_{int(datetime.now().timestamp())}',
            'level': 'medium',
            'title': 'Test Diagnostic CTI',
            'description': 'Alerte de test créée par le script de diagnostic',
            'timestamp': datetime.now().isoformat(),
            'acknowledged': False,
            'source': 'diagnostic_script'
        }
        
        endpoints_to_try = [
            '/api/dashboard/alerts',
            '/api/dashboard/alerts/create',
            '/api/alerts'
        ]
        
        for endpoint in endpoints_to_try:
            try:
                print(f"\n🚀 Tentative POST sur: {endpoint}")
                
                response = requests.post(
                    f"{self.api_url}{endpoint}",
                    json=test_alert,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                print(f"   Status: {response.status_code}")
                print(f"   Réponse: {response.text[:300]}")
                
                if response.status_code in [200, 201]:
                    print(f"   ✅ Succès sur {endpoint}")
                    break
                else:
                    print(f"   ❌ Échec sur {endpoint}")
                    
            except Exception as e:
                print(f"   ❌ Exception sur {endpoint}: {e}")
    
    def compare_db_vs_api(self):
        """Comparer le nombre d'alertes entre DB et API"""
        print("\n⚖️ === COMPARAISON DB vs API ===")
        
        # Compter en DB
        db_count = 0
        if self.connection:
            try:
                with self.connection.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM alerts;")
                    db_count = cursor.fetchone()[0]
            except Exception as e:
                print(f"❌ Erreur comptage DB: {e}")
        
        # Compter via API
        api_count = 0
        try:
            response = requests.get(f"{self.api_url}/api/dashboard/alerts", timeout=10)
            if response.status_code == 200:
                data = response.json()
                api_count = len(data.get('alerts', []))
        except Exception as e:
            print(f"❌ Erreur comptage API: {e}")
        
        print(f"📊 Alertes en DB: {db_count}")
        print(f"🌐 Alertes via API: {api_count}")
        print(f"📈 Différence: {db_count - api_count}")
        
        if db_count > api_count:
            print("⚠️ Il y a plus d'alertes en DB que retournées par l'API!")
            print("🔍 Causes possibles:")
            print("   - Problème de requête SQL dans l'API")
            print("   - Filtrage des alertes dans l'API")
            print("   - Problème de connexion DB dans l'API")
            print("   - Cache ou problème de synchronisation")
        elif db_count == api_count:
            print("✅ Les comptes correspondent!")
        else:
            print("🤔 Plus d'alertes via API qu'en DB (étrange...)")
    
    def check_api_logs(self):
        """Suggestions pour vérifier les logs de l'API"""
        print("\n📜 === VÉRIFICATION DES LOGS ===")
        print("Pour identifier le problème, vérifiez les logs du backend:")
        print()
        print("🐳 Logs Docker du backend:")
        print("   docker logs cti-dashboard-backend")
        print()
        print("🐳 Logs en temps réel:")
        print("   docker logs -f cti-dashboard-backend")
        print()
        print("🔍 Rechercher les erreurs SQL:")
        print("   docker logs cti-dashboard-backend 2>&1 | grep -i error")
        print()
        print("🔍 Rechercher les requêtes alerts:")
        print("   docker logs cti-dashboard-backend 2>&1 | grep -i alert")
    
    def suggest_fixes(self):
        """Suggestions de solutions"""
        print("\n💡 === SUGGESTIONS DE CORRECTION ===")
        print()
        print("1. 🔄 Redémarrer le backend:")
        print("   docker restart cti-dashboard-backend")
        print()
        print("2. 🔍 Vérifier la configuration de l'API:")
        print("   - Variables d'environnement de DB")
        print("   - Configuration des endpoints")
        print("   - Requêtes SQL dans le code")
        print()
        print("3. 🔧 Vérifier la requête SQL de l'API:")
        print("   - Assurer que l'API utilise la bonne table")
        print("   - Vérifier les filtres appliqués")
        print("   - Tester la requête manuellement")
        print()
        print("4. 📊 Synchroniser manuellement:")
        print("   - Redémarrer PostgreSQL")
        print("   - Vérifier les permissions")
        print("   - Recréer les index si nécessaire")
    
    def run_full_diagnostic(self):
        """Exécuter le diagnostic complet"""
        print("🔧 CTI DIAGNOSTIC - Analyse des problèmes d'alertes")
        print("=" * 60)
        print(f"⏰ Démarré à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # 1. Diagnostic base de données
            self.check_database_alerts()
            
            # 2. Diagnostic API
            self.check_api_responses()
            
            # 3. Comparaison
            self.compare_db_vs_api()
            
            # 4. Test création
            self.test_alert_creation_via_api()
            
            # 5. Suggestions
            self.check_api_logs()
            self.suggest_fixes()
            
        except Exception as e:
            print(f"❌ Erreur durant le diagnostic: {e}")
            traceback.print_exc()
        
        print(f"\n⏱️ Diagnostic terminé à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    """Point d'entrée principal"""
    diagnostic = CTIDiagnostic()
    
    try:
        diagnostic.run_full_diagnostic()
    except KeyboardInterrupt:
        print("\n⏹️ Diagnostic interrompu par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        traceback.print_exc()
    finally:
        if diagnostic.connection:
            diagnostic.connection.close()
            print("🔌 Connexion DB fermée")

if __name__ == "__main__":
    main()