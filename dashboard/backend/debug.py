#!/usr/bin/env python3
"""
Script de debug pour diagnostiquer les problèmes du dashboard CTI
À exécuter dans le conteneur backend: docker exec -it cti-dashboard-backend python debug_dashboard.py
"""

import requests
import subprocess
import socket
import psutil
import os
import sys
from datetime import datetime

def check_flask_process():
    """Vérifier si le processus Flask est en cours d'exécution"""
    print("🔍 Vérification du processus Flask...")
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            cmdline = ' '.join(proc.info['cmdline'] or [])
            if 'app.py' in cmdline or 'flask' in cmdline.lower() or 'socketio.run' in cmdline:
                print(f"✅ Processus Flask trouvé: PID {proc.info['pid']}")
                print(f"   Commande: {cmdline[:100]}...")
                return True
        
        print("❌ Aucun processus Flask trouvé")
        return False
    except Exception as e:
        print(f"❌ Erreur vérification processus: {e}")
        return False

def check_port_listening():
    """Vérifier si le port 5001 est en écoute"""
    print("\n🔍 Vérification du port 5001...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', 5001))
        sock.close()
        
        if result == 0:
            print("✅ Port 5001 est ouvert")
            return True
        else:
            print("❌ Port 5001 n'est pas accessible")
            return False
    except Exception as e:
        print(f"❌ Erreur vérification port: {e}")
        return False

def check_docker_networking():
    """Vérifier la configuration réseau Docker"""
    print("\n🔍 Vérification réseau Docker...")
    
    # Vérifier les interfaces réseau
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        print(f"📡 Interfaces réseau: {interfaces}")
    except:
        print("⚠️ Module netifaces non disponible")
    
    # Test de connectivité interne
    try:
        response = requests.get("http://0.0.0.0:5001/api/test", timeout=3)
        print(f"✅ API accessible via 0.0.0.0:5001 - Status: {response.status_code}")
        return True
    except requests.exceptions.ConnectionError:
        print("❌ API non accessible via 0.0.0.0:5001")
    except Exception as e:
        print(f"❌ Erreur connexion: {e}")
    
    return False

def start_flask_manually():
    """Essayer de démarrer Flask manuellement"""
    print("\n🚀 Tentative de démarrage Flask...")
    
    try:
        # Vérifier si app.py existe
        if not os.path.exists('/app/app.py'):
            print("❌ Fichier /app/app.py introuvable")
            return False
        
        print("📁 Fichier app.py trouvé")
        
        # Essayer d'importer l'app
        sys.path.insert(0, '/app')
        try:
            from app import app, socketio
            print("✅ Import de l'application réussi")
            
            # Démarrer en arrière-plan
            import threading
            def run_app():
                socketio.run(app, host='0.0.0.0', port=5001, debug=False)
            
            thread = threading.Thread(target=run_app, daemon=True)
            thread.start()
            
            import time
            time.sleep(3)  # Attendre le démarrage
            
            print("🔄 Application démarrée en arrière-plan")
            return True
            
        except Exception as e:
            print(f"❌ Erreur import application: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Erreur démarrage Flask: {e}")
        return False

def test_database_connection():
    """Tester la connexion à la base de données"""
    print("\n🗄️ Test connexion base de données...")
    
    try:
        import psycopg2
        
        # Configuration par défaut
        db_config = {
            'host': os.getenv('DB_HOST', 'cti-postgres'),
            'port': int(os.getenv('DB_PORT', 5432)),
            'database': os.getenv('DB_NAME', 'cti_db'),
            'user': os.getenv('DB_USER', 'cti_user'),
            'password': os.getenv('DB_PASSWORD', 'cti_password')
        }
        
        print(f"🔗 Tentative connexion à {db_config['host']}:{db_config['port']}")
        
        conn = psycopg2.connect(**db_config)
        cursor = conn.cursor()
        
        # Test simple
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        print(f"✅ PostgreSQL connecté: {version[0][:50]}...")
        
        # Vérifier les tables MITRE
        cursor.execute("SELECT COUNT(*) FROM mitre_techniques;")
        count = cursor.fetchone()[0]
        print(f"✅ Table mitre_techniques: {count} entrées")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Erreur connexion DB: {e}")
        return False

def run_minimal_test():
    """Test minimal avec serveur temporaire"""
    print("\n🧪 Test minimal avec serveur temporaire...")
    
    try:
        from flask import Flask, jsonify
        
        test_app = Flask(__name__)
        
        @test_app.route('/api/test')
        def test():
            return jsonify({'status': 'OK', 'message': 'Test server running'})
        
        @test_app.route('/api/dashboard/alerts')
        def mock_alerts():
            return jsonify({
                'alerts': [
                    {'id': 1, 'title': 'Test Alert', 'level': 'high', 'timestamp': datetime.now().isoformat()}
                ],
                'total': 1
            })
        
        # Démarrer serveur temporaire
        import threading
        import time
        
        def run_test_server():
            test_app.run(host='0.0.0.0', port=5001, debug=False)
        
        thread = threading.Thread(target=run_test_server, daemon=True)
        thread.start()
        time.sleep(2)
        
        # Test du serveur temporaire
        response = requests.get("http://localhost:5001/api/test", timeout=5)
        if response.status_code == 200:
            print("✅ Serveur temporaire fonctionne")
            
            # Test des alertes
            alerts_response = requests.get("http://localhost:5001/api/dashboard/alerts", timeout=5)
            if alerts_response.status_code == 200:
                print("✅ Endpoint alertes fonctionne")
                return True
        
        return False
        
    except Exception as e:
        print(f"❌ Erreur serveur temporaire: {e}")
        return False

def check_environment():
    """Vérifier l'environnement"""
    print("\n🌍 Vérification de l'environnement...")
    
    print(f"🐍 Python: {sys.version}")
    print(f"📁 Répertoire courant: {os.getcwd()}")
    print(f"📦 PYTHONPATH: {sys.path[:3]}...")
    
    # Variables d'environnement importantes
    important_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'FLASK_ENV']
    for var in important_vars:
        value = os.getenv(var, 'Non défini')
        print(f"🔧 {var}: {value}")
    
    # Vérifier les modules importants
    modules_to_check = ['flask', 'flask_socketio', 'psycopg2', 'requests']
    for module in modules_to_check:
        try:
            __import__(module)
            print(f"✅ Module {module}: OK")
        except ImportError as e:
            print(f"❌ Module {module}: {e}")

def main():
    """Fonction principale de diagnostic"""
    print("🔧 === DIAGNOSTIC DASHBOARD CTI ===\n")
    
    issues_found = []
    fixes_suggested = []
    
    # 1. Vérifier l'environnement
    check_environment()
    
    # 2. Vérifier le processus Flask
    if not check_flask_process():
        issues_found.append("Processus Flask non trouvé")
        fixes_suggested.append("Démarrer Flask: python /app/app.py")
    
    # 3. Vérifier le port
    if not check_port_listening():
        issues_found.append("Port 5001 non ouvert")
    
    # 4. Vérifier la base de données
    if not test_database_connection():
        issues_found.append("Connexion base de données échouée")
        fixes_suggested.append("Vérifier que le conteneur PostgreSQL est démarré")
    
    # 5. Test réseau Docker
    if not check_docker_networking():
        issues_found.append("Problème réseau Docker")
    
    # 6. Essayer de démarrer Flask si nécessaire
    if not check_port_listening():
        print("\n🔄 Tentative de démarrage du serveur...")
        if start_flask_manually():
            print("✅ Serveur démarré manuellement")
        else:
            # Serveur de test minimal
            if run_minimal_test():
                print("✅ Serveur de test minimal fonctionne")
    
    # Rapport final
    print(f"\n📋 === RAPPORT DE DIAGNOSTIC ===")
    if issues_found:
        print("❌ Problèmes identifiés:")
        for issue in issues_found:
            print(f"   - {issue}")
        
        if fixes_suggested:
            print("\n🔧 Solutions suggérées:")
            for fix in fixes_suggested:
                print(f"   - {fix}")
    else:
        print("✅ Aucun problème majeur détecté")
    
    print(f"\n💡 Commandes utiles:")
    print(f"   - Logs Flask: tail -f /app/logs/dashboard.log")
    print(f"   - Démarrer manuellement: cd /app && python app.py")
    print(f"   - Vérifier conteneurs: docker ps")
    print(f"   - Restart conteneur: docker restart cti-dashboard-backend")

if __name__ == "__main__":
    main()