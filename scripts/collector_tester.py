"""
Test rapide pour vérifier le bon fonctionnement des collecteurs CTI
"""

import os
import sys
import json
import time
from datetime import datetime

# Ajouter le répertoire parent au path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_config_files():
    """Teste la présence des fichiers de configuration"""
    print("🔍 Vérification des fichiers de configuration...")
    
    required_files = [
        '../config/api_keys.json',
        '../config/sources.json', 
        '../config/telegram_channels.json',
        '../config/settings.json'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
            print(f"❌ {file_path} - MANQUANT")
        else:
            print(f"✅ {file_path} - OK")
    
    if missing_files:
        print(f"\n⚠️  {len(missing_files)} fichier(s) de configuration manquant(s)")
        return False
    else:
        print("✅ Tous les fichiers de configuration sont présents")
        return True

def test_imports():
    """Teste l'importation des modules"""
    print("\n🔍 Test des importations...")
    
    modules_to_test = [
        ('scripts.collectors.rss_collector', 'RSSCollector'),
        ('scripts.collectors.otx_collector', 'OTXCollector'),
        ('scripts.collectors.twitter_collector', 'TwitterCollector'),
        ('scripts.collectors.telegram_collector', 'TelegramCollector'),
        ('scripts.collectors.abuse_ch_collector', 'AbuseCHCollector'),
        ('scripts.collectors.main_collector', 'MainCollector'),
    ]
    
    import_errors = []
    
    for module_name, class_name in modules_to_test:
        try:
            module = __import__(module_name, fromlist=[class_name])
            getattr(module, class_name)
            print(f"✅ {class_name} - Import OK")
        except ImportError as e:
            import_errors.append((class_name, str(e)))
            print(f"❌ {class_name} - Erreur: {e}")
        except Exception as e:
            import_errors.append((class_name, str(e)))
            print(f"❌ {class_name} - Erreur: {e}")
    
    if import_errors:
        print(f"\n⚠️  {len(import_errors)} erreur(s) d'importation")
        return False
    else:
        print("✅ Tous les modules s'importent correctement")
        return True

def test_output_directories():
    """Teste la création des dossiers de sortie"""
    print("\n🔍 Test des dossiers de sortie...")
    
    directories = [
        'output/daily_feeds',
        'output/searches', 
        'output/alerts',
        'logs'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            
            # Test d'écriture
            test_file = os.path.join(directory, 'test.json')
            with open(test_file, 'w') as f:
                json.dump({'test': True}, f)
            
            # Nettoyer
            os.remove(test_file)
            
            print(f"✅ {directory} - OK")
        except Exception as e:
            print(f"❌ {directory} - Erreur: {e}")
            return False
    
    print("✅ Tous les dossiers sont accessibles en écriture")
    return True

def test_basic_functionality():
    """Test de fonctionnalité basique"""
    print("\n🔍 Test de fonctionnalité basique...")
    
    try:
        # Test RSS Collector
        print("  Testing RSS Collector...")
        from scripts.collectors.rss_collector import RSSCollector
        rss_collector = RSSCollector()
        print("  ✅ RSS Collector initialisé")
        
        # Test OTX Collector
        print("  Testing OTX Collector...")
        from scripts.collectors.otx_collector import OTXCollector
        otx_collector = OTXCollector()
        print("  ✅ OTX Collector initialisé")
        
        # Test Main Collector
        print("  Testing Main Collector...")
        from scripts.collectors.main_collector import MainCollector
        main_collector = MainCollector()
        print("  ✅ Main Collector initialisé")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors du test de fonctionnalité : {e}")
        return False

def test_api_keys():
    """Teste la validité des clés API (structure seulement)"""
    print("\n🔍 Vérification de la structure des clés API...")
    
    try:
        if not os.path.exists('../config/api_keys.json'):
            print("❌ Fichier api_keys.json manquant")
            return False
        
        with open('../config/api_keys.json', 'r') as f:
            api_keys = json.load(f)
        
        expected_keys = {
            'otx_api_key': 'OTX API Key',
            'twitter_bearer_token': 'Twitter API Keys',
            'telegram_bot_token': 'Telegram API Keys'
        }
        
        for key, description in expected_keys.items():
            if key in api_keys:
                print(f"✅ {description} - Structure OK")
            else:
                print(f"❌ {description} - Clé manquante: {key}")
                return False
        
        return True
        
    except json.JSONDecodeError:
        print("❌ Fichier api_keys.json mal formaté")
        return False
    except Exception as e:
        print(f"❌ Erreur lecture api_keys.json: {e}")
        return False

def run_quick_test():
    """Exécute tous les tests rapides"""
    print("🚀 DÉBUT DES TESTS RAPIDES CTI COLLECTORS")
    print("="*50)
    
    start_time = time.time()
    
    tests = [
        ("Configuration Files", test_config_files),
        ("Module Imports", test_imports),
        ("Output Directories", test_output_directories),
        ("API Keys Structure", test_api_keys),
        ("Basic Functionality", test_basic_functionality)
    ]
    
    results = {}
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 {test_name}")
        print("-" * 30)
        try:
            result = test_func()
            results[test_name] = result
            if result:
                passed += 1
        except Exception as e:
            print(f"❌ Erreur inattendue: {e}")
            results[test_name] = False
    
    end_time = time.time()
    execution_time = end_time - start_time
    
    # Résumé final
    print("\n" + "="*50)
    print("📊 RÉSUMÉ DES TESTS")
    print("="*50)
    print(f"Tests exécutés : {total}")
    print(f"Réussis : {passed}")
    print(f"Échoués : {total - passed}")
    print(f"Taux de réussite : {(passed/total)*100:.1f}%")
    print(f"Temps d'exécution : {execution_time:.2f}s")
    
    if passed == total:
        print("\n🎉 TOUS LES TESTS SONT PASSÉS!")
        print("✅ Vos collecteurs CTI sont prêts à fonctionner")
    else:
        print("\n⚠️  CERTAINS TESTS ONT ÉCHOUÉ")
        print("🔧 Vérifiez les erreurs ci-dessus avant de lancer la collecte")
    
    print("="*50)
    
    # Sauvegarder les résultats
    try:
        os.makedirs('output/tests', exist_ok=True)
        report = {
            'test_date': datetime.now().isoformat(),
            'execution_time': execution_time,
            'results': results,
            'summary': {
                'total': total,
                'passed': passed,
                'failed': total - passed,
                'success_rate': (passed/total)*100
            }
        }
        
        report_file = f"output/tests/quick_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"📁 Rapport sauvegardé: {report_file}")
        
    except Exception as e:
        print(f"⚠️  Impossible de sauvegarder le rapport: {e}")
    
    return results

if __name__ == "__main__":
    run_quick_test()