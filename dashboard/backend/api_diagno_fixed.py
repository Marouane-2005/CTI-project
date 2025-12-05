#!/usr/bin/env python3
"""
Diagnostic CTI Dashboard - Version corrigée
Analyse les problèmes d'alertes et de routage API
"""

import psycopg2
from psycopg2.extras import RealDictCursor
import requests
import json
from datetime import datetime
import traceback

def connect_to_db():
    """Connexion à PostgreSQL"""
    try:
        connection = psycopg2.connect(
            host='postgres',
            database='cti_db',
            user='cti_user',
            password='cti_password',
            port='5432'
        )
        print("✅ Connexion DB réussie")
        return connection
    except Exception as e:
        print(f"❌ Erreur connexion DB: {e}")
        return None

def check_database_alerts(connection):
    """Diagnostic approfondi de la base de données"""
    print("\n🔍 === DIAGNOSTIC BASE DE DONNÉES ===")
    
    try:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            # 1. Vérifier l'existence de la table alerts
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'alerts'
                );
            """)
            table_exists = cursor.fetchone()['exists']  # FIX: Utiliser la clé 'exists'
            print(f"📊 Table 'alerts' existe: {table_exists}")
            
            if not table_exists:
                print("❌ Table 'alerts' n'existe pas!")
                return 0, []
            
            # 2. Structure de la table
            cursor.execute("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns 
                WHERE table_name = 'alerts'
                ORDER BY ordinal_position;
            """)
            columns = cursor.fetchall()
            print(f"🏗️ Structure table alerts ({len(columns)} colonnes):")
            for col in columns:
                print(f"   - {col['column_name']}: {col['data_type']} ({'NULL' if col['is_nullable'] == 'YES' else 'NOT NULL'})")
            
            # 3. Compter les alertes totales
            cursor.execute("SELECT COUNT(*) as total FROM alerts;")
            total_count = cursor.fetchone()['total']
            print(f"📈 Total alertes en DB: {total_count}")
            
            # 4. Compter par statut d'acquittement
            cursor.execute("""
                SELECT 
                    acknowledged,
                    COUNT(*) as count
                FROM alerts 
                GROUP BY acknowledged;
            """)
            status_counts = cursor.fetchall()
            print("📊 Répartition par statut:")
            for status in status_counts:
                ack_status = "Acquittées" if status['acknowledged'] else "Non acquittées"
                print(f"   - {ack_status}: {status['count']}")
            
            # 5. Compter par niveau de criticité
            cursor.execute("""
                SELECT 
                    level,
                    COUNT(*) as count
                FROM alerts 
                GROUP BY level
                ORDER BY 
                    CASE level 
                        WHEN 'critical' THEN 1 
                        WHEN 'high' THEN 2 
                        WHEN 'medium' THEN 3 
                        WHEN 'low' THEN 4 
                        ELSE 5 
                    END;
            """)
            level_counts = cursor.fetchall()
            print("🚨 Répartition par niveau:")
            for level in level_counts:
                print(f"   - {level['level']}: {level['count']}")
            
            # 6. Alertes les plus récentes
            cursor.execute("""
                SELECT id, title, level, acknowledged, created_at
                FROM alerts 
                ORDER BY created_at DESC 
                LIMIT 5;
            """)
            recent_alerts = cursor.fetchall()
            print(f"⏰ 5 alertes les plus récentes:")
            for alert in recent_alerts:
                ack_icon = "✅" if alert['acknowledged'] else "❌"
                print(f"   {ack_icon} [{alert['level']}] {alert['title']} ({alert['created_at']})")
            
            return total_count, recent_alerts
            
    except Exception as e:
        print(f"❌ Erreur diagnostic DB: {e}")
        traceback.print_exc()
        return 0, []

def check_api_endpoints():
    """Test des endpoints API avec les bonnes méthodes HTTP"""
    print("\n🌐 === DIAGNOSTIC API ===")
    
    base_url = "http://localhost:5001"
    
    # Tests GET
    get_endpoints = [
        ("/api/test", "Test de connectivité"),
        ("/api/dashboard/overview", "Vue d'ensemble"),
        ("/api/dashboard/alerts", "Liste des alertes"),
        ("/api/dashboard/alerts/count", "Compteur d'alertes"),
        ("/api/dashboard/alerts/recent", "Alertes récentes"),
        ("/", "Page d'accueil")
    ]
    
    api_results = {}
    
    for endpoint, description in get_endpoints:
        try:
            print(f"🔗 Test GET: {endpoint} ({description})")
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            print(f"   ✅ Status: {response.status_code}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    # Analyser les données spécifiques
                    if endpoint == "/api/dashboard/alerts":
                        alerts_count = len(data.get('alerts', []))
                        api_results['alerts_count'] = alerts_count
                        print(f"   📊 Alertes retournées: {alerts_count}")
                        
                        if alerts_count > 0:
                            for i, alert in enumerate(data['alerts'][:3], 1):
                                print(f"      [{i}] {alert.get('level', 'unknown')} - {alert.get('title', 'Sans titre')}")
                    
                    elif endpoint == "/api/test":
                        modules = data.get('modules_available', {})
                        print(f"   🔧 Modules disponibles:")
                        for module, status in modules.items():
                            icon = "✅" if status else "❌"
                            print(f"      {icon} {module}: {status}")
                            
                except json.JSONDecodeError:
                    print(f"   ⚠️ Réponse non-JSON: {response.text[:100]}")
            else:
                print(f"   ❌ Erreur: {response.status_code} - {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Erreur de connexion: {e}")
    
    return api_results

def test_post_endpoints():
    """Test des endpoints POST pour la création d'alertes"""
    print("\n📝 === TEST ENDPOINTS POST ===")
    
    base_url = "http://localhost:5001"
    
    # Données de test pour créer une alerte
    test_alert = {
        "title": "Test Alert - Diagnostic",
        "level": "high",
        "description": "Alerte créée lors du diagnostic système",
        "source": "diagnostic_script"
    }
    
    # Endpoints à tester
    post_endpoints = [
        "/api/dashboard/alerts",
        "/api/dashboard/alerts/create"
    ]
    
    for endpoint in post_endpoints:
        try:
            print(f"🚀 Test POST: {endpoint}")
            response = requests.post(
                f"{base_url}{endpoint}", 
                json=test_alert,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code in [200, 201]:
                try:
                    data = response.json()
                    print(f"   ✅ Succès: {data.get('message', 'Alerte créée')}")
                    if 'alert' in data:
                        alert = data['alert']
                        print(f"      ID: {alert.get('id')}")
                        print(f"      Titre: {alert.get('title')}")
                except json.JSONDecodeError:
                    print(f"   ✅ Succès mais réponse non-JSON")
            else:
                try:
                    error_data = response.json()
                    print(f"   ❌ Erreur: {error_data}")
                except:
                    print(f"   ❌ Erreur: {response.text}")
                    
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Erreur connexion: {e}")

def test_api_data_consistency(db_count):
    """Compare les données DB vs API"""
    print(f"\n⚖️ === TEST COHÉRENCE DONNÉES ===")
    
    try:
        # Test de l'endpoint alerts
        response = requests.get("http://localhost:5001/api/dashboard/alerts", timeout=5)
        
        if response.status_code == 200:
            api_data = response.json()
            api_count = len(api_data.get('alerts', []))
            
            print(f"📊 Alertes en DB: {db_count}")
            print(f"🌐 Alertes via API: {api_count}")
            print(f"📈 Différence: {abs(db_count - api_count)}")
            
            if db_count != api_count:
                print("⚠️ INCOHÉRENCE DÉTECTÉE!")
                print("🔍 Causes possibles:")
                print("   - L'API utilise des données mock au lieu de la DB")
                print("   - Problème de connexion DB dans l'API")
                print("   - Filtrage différent entre DB et API")
                print("   - Cache non synchronisé")
                
                # Test de vérification
                print("\n🔍 Test de vérification:")
                test_response = requests.get("http://localhost:5001/api/test", timeout=5)
                if test_response.status_code == 200:
                    test_data = test_response.json()
                    db_status = test_data.get('modules_available', {}).get('database', False)
                    print(f"   DB Status dans /api/test: {db_status}")
                    
                    if not db_status:
                        print("   ❌ L'API n'a pas de connexion DB active!")
                        print("   💡 L'API utilise probablement des données mock")
            else:
                print("✅ Données cohérentes entre DB et API")
                
        else:
            print(f"❌ Impossible de tester la cohérence: API error {response.status_code}")
            
    except Exception as e:
        print(f"❌ Erreur test cohérence: {e}")

def check_websocket_connection():
    """Test de la connexion WebSocket"""
    print(f"\n🔌 === TEST WEBSOCKET ===")
    
    try:
        # Test simple de connexion WebSocket
        import socketio
        
        sio = socketio.SimpleClient()
        
        print("🔗 Tentative de connexion WebSocket...")
        sio.connect('http://localhost:5001', timeout=5)
        print("✅ WebSocket connecté!")
        
        # Test d'émission
        sio.emit('test_connection', {'source': 'diagnostic'})
        print("📤 Message test envoyé")
        
        sio.disconnect()
        print("🔌 WebSocket déconnecté")
        
    except ImportError:
        print("⚠️ python-socketio non disponible pour test WebSocket")
    except Exception as e:
        print(f"❌ Erreur WebSocket: {e}")

def provide_solutions(db_count, api_results):
    """Fournit des solutions basées sur les résultats du diagnostic"""
    print(f"\n💡 === SOLUTIONS RECOMMANDÉES ===")
    
    api_alerts_count = api_results.get('alerts_count', 0)
    
    if db_count > 0 and api_alerts_count == 0:
        print("🔧 PROBLÈME: L'API ne retourne aucune alerte alors que la DB en contient")
        print("📝 Solutions:")
        print("   1. Vérifier la connexion DB dans l'API:")
        print("      - Vérifier les variables d'environnement")
        print("      - Tester la connexion DB dans le code API")
        print("   2. Modifier data_processor.py pour utiliser la vraie DB:")
        print("      - Remplacer les données mock par des requêtes SQL")
        print("      - Vérifier la méthode get_alerts_data()")
        print("   3. Redémarrer les services:")
        print("      docker restart cti-dashboard-backend")
        
    elif db_count != api_alerts_count and api_alerts_count > 0:
        print("🔧 PROBLÈME: Incohérence entre DB et API")
        print("📝 Solutions:")
        print("   1. Vérifier les filtres dans l'API")
        print("   2. Synchroniser les données")
        print("   3. Vérifier les requêtes SQL")
        
    if api_results.get('alerts_count', 0) <= 1:
        print("\n🔧 PROBLÈME: Peu d'alertes retournées par l'API")
        print("📝 Solutions:")
        print("   1. Vérifier que l'API utilise la vraie DB")
        print("   2. Tester la création d'alertes via API")
        print("   3. Vérifier les logs du backend")
        
    print(f"\n🐳 Commandes Docker utiles:")
    print("   - Logs backend: docker logs cti-dashboard-backend")
    print("   - Redémarrer backend: docker restart cti-dashboard-backend")
    print("   - Shell backend: docker exec -it cti-dashboard-backend bash")
    print("   - Logs en temps réel: docker logs -f cti-dashboard-backend")

def main():
    """Fonction principale du diagnostic"""
    print("🔧 CTI DIAGNOSTIC - Version corrigée")
    print("=" * 60)
    print(f"⏰ Démarré à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 1. Test de la base de données
    connection = connect_to_db()
    db_count = 0
    recent_alerts = []
    
    if connection:
        db_count, recent_alerts = check_database_alerts(connection)
        connection.close()
        print("🔌 Connexion DB fermée")
    
    # 2. Test des endpoints API
    api_results = check_api_endpoints()
    
    # 3. Test des endpoints POST
    test_post_endpoints()
    
    # 4. Test de cohérence des données
    test_api_data_consistency(db_count)
    
    # 5. Test WebSocket
    check_websocket_connection()
    
    # 6. Solutions recommandées
    provide_solutions(db_count, api_results)
    
    print(f"\n⏱️ Diagnostic terminé à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()