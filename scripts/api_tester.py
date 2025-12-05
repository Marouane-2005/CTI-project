#!/usr/bin/env python3
"""
Script de test amélioré pour vérifier la communication avec les APIs CTI
avec gestion des timeouts et meilleure gestion d'erreurs
"""

import json
import requests
import asyncio
import sys
from datetime import datetime, timedelta
import tweepy
from OTXv2 import OTXv2
import shodan
from telethon import TelegramClient
import signal
from contextlib import contextmanager

class TimeoutException(Exception):
    pass

@contextmanager
def timeout(seconds):
    """Context manager pour les timeouts"""
    def timeout_handler(signum, frame):
        raise TimeoutException(f"Opération timeout après {seconds} secondes")
    
    # Configurer le signal d'alarme (Unix seulement)
    if hasattr(signal, 'SIGALRM'):
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
    else:
        # Pour Windows, on utilise une approche différente
        yield

class APITester:
    def __init__(self):
        # Charger les clés API
        try:
            with open('../config/api_keys.json', 'r') as f:
                self.api_keys = json.load(f)
            print("✓ Fichier api_keys.json chargé avec succès")
        except FileNotFoundError:
            print("✗ Fichier api_keys.json introuvable")
            sys.exit(1)
        except json.JSONDecodeError:
            print("✗ Erreur de format dans api_keys.json")
            sys.exit(1)
    
    def test_otx_api(self):
        """Test de l'API AlienVault OTX avec gestion améliorée des erreurs"""
        print("\n" + "="*50)
        print("TEST OTX (AlienVault Open Threat Exchange)")
        print("="*50)
        
        try:
            # Vérifier d'abord la clé API avec une requête simple
            print("🔄 Vérification de la clé API OTX...")
            
            # Test direct avec requests pour plus de contrôle
            headers = {
                'X-OTX-API-KEY': self.api_keys['otx_api_key'],
                'User-Agent': 'CTI-Collector/1.0'
            }
            
            # Test avec timeout plus court
            response = requests.get(
                'https://otx.alienvault.com/api/v1/pulses/subscribed',
                headers=headers,
                timeout=30  # 30 secondes max
            )
            
            if response.status_code == 200:
                data = response.json()
                pulses = data.get('results', [])
                
                print("✓ Connexion OTX réussie via API REST")
                print(f"  - {len(pulses)} pulses récupérés")
                
                if pulses:
                    first_pulse = pulses[0]
                    print(f"  - Premier pulse: {first_pulse.get('name', 'N/A')}")
                    print(f"  - Auteur: {first_pulse.get('author_name', 'N/A')}")
                    print(f"  - Date: {first_pulse.get('created', 'N/A')}")
                
                # Maintenant testons avec la librairie OTXv2 (avec une limite)
                print("\n🔄 Test avec la librairie OTXv2...")
                try:
                    import threading
                    import time
                    
                    def test_otx_lib():
                        """Fonction pour tester OTXv2 dans un thread séparé"""
                        try:
                            otx = OTXv2(self.api_keys['otx_api_key'])
                    
                            pulses_lib = otx.getsince((datetime.now() - timedelta(days=1)).isoformat())
                        
                            if pulses_lib and 'results' in pulses_lib:
                               return len(pulses_lib['results'])
                            else:
                               return 0
                        except Exception as e:
                            raise e
                    
                     # Créer un thread pour le test avec timeout
                    result = [None]
                    exception = [None]
                
                    def thread_target():
                      try:
                        result[0] = test_otx_lib()
                      except Exception as e:
                        exception[0] = e
                    thread = threading.Thread(target=thread_target)
                    thread.daemon = True
                    thread.start()
                
                # Attendre maximum 20 secondes
                    thread.join(timeout=20)
                
                    if thread.is_alive():
                      print("⚠ Timeout sur la librairie OTXv2 (>20s)")
                      print("  L'API REST fonctionne, la librairie est trop lente")
                    elif exception[0]:
                      print(f"⚠ Erreur avec la librairie OTXv2: {exception[0]}")
                      print("  (L'API REST fonctionne, problème avec la librairie)")
                    elif result[0] is not None:
                      print(f"✓ Librairie OTXv2 fonctionne - {result[0]} pulses récents")
                    else:
                     print("⚠ Librairie OTXv2: résultat inattendu")    
                except Exception as lib_error:
                    print(f"⚠ Erreur avec la librairie OTXv2: {lib_error}")
                    print("  (L'API REST fonctionne, problème avec la librairie)")
                
                return True
                
            elif response.status_code == 403:
                print("✗ Erreur OTX: Clé API invalide ou accès refusé")
                return False
            elif response.status_code == 429:
                print("✗ Erreur OTX: Limite de taux dépassée")
                return False
            else:
                print(f"✗ Erreur OTX: HTTP {response.status_code}")
                print(f"  Response: {response.text[:200]}...")
                return False
                
        except requests.exceptions.Timeout:
            print("✗ Erreur OTX: Timeout de connexion (>30s)")
            print("  Vérifiez votre connexion internet")
            return False
        except requests.exceptions.ConnectionError:
            print("✗ Erreur OTX: Impossible de se connecter au serveur")
            print("  Vérifiez votre connexion internet et les paramètres proxy")
            return False
        except KeyboardInterrupt:
            print("✗ Opération interrompue par l'utilisateur")
            return False
        except Exception as e:
            print(f"✗ Erreur OTX inattendue: {e}")
            return False
    
    def test_twitter_api(self):
        """Test de l'API Twitter avec gestion améliorée"""
        print("\n" + "="*50)
        print("TEST TWITTER API")
        print("="*50)
        
        try:
            print("🔄 Vérification du Bearer Token...")
            
            # Test direct avec requests
            headers = {
                'Authorization': f'Bearer {self.api_keys["twitter_bearer_token"]}',
                'User-Agent': 'CTI-Collector/1.0'
            }
            
            response = requests.get(
                'https://api.twitter.com/2/tweets/search/recent?query=cybersecurity&max_results=10',
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                tweets = data.get('data', [])
                
                print("✓ Connexion Twitter réussie")
                print(f"  - {len(tweets)} tweets récupérés")
                
                if tweets:
                    first_tweet = tweets[0]
                    print(f"  - Premier tweet: {first_tweet.get('text', '')[:100]}...")
                
                return True
            elif response.status_code == 401:
                print("✗ Erreur Twitter: Token invalide")
                return False
            elif response.status_code == 429:
                print("✗ Erreur Twitter: Limite de taux dépassée")
                return False
            else:
                print(f"✗ Erreur Twitter: HTTP {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            print("✗ Erreur Twitter: Timeout")
            return False
        except Exception as e:
            print(f"✗ Erreur Twitter: {e}")
            return False
    
    def test_virustotal_api(self):
        """Test de l'API VirusTotal"""
        print("\n" + "="*50)
        print("TEST VIRUSTOTAL API")
        print("="*50)
        
        try:
            headers = {
                "accept": "application/json",
                "x-apikey": self.api_keys['virustotal_api_key']
            }
            
            print("🔄 Test de l'API VirusTotal...")
            
            # Test avec un domaine simple
            url = "https://www.virustotal.com/api/v3/domains/google.com"
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                print("✓ Connexion VirusTotal réussie")
                
                domain_data = data.get('data', {}).get('attributes', {})
                print(f"  - Domaine testé: google.com")
                print(f"  - Réputation: {domain_data.get('reputation', 'N/A')}")
                
                return True
            elif response.status_code == 401:
                print("✗ Erreur VirusTotal: Clé API invalide")
                return False
            elif response.status_code == 429:
                print("✗ Erreur VirusTotal: Limite de quota dépassée")
                return False
            else:
                print(f"✗ Erreur VirusTotal: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Erreur VirusTotal: {e}")
            return False
    
    def test_shodan_api(self):
        """Test de l'API Shodan"""
        print("\n" + "="*50)
        print("TEST SHODAN API")
        print("="*50)
        
        try:
            print("🔄 Test de l'API Shodan...")
            
            # Test direct avec requests
            params = {
                'key': self.api_keys['shodan_api_key']
            }
            
            response = requests.get(
                'https://api.shodan.io/api-info',
                params=params,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                print("✓ Connexion Shodan réussie")
                print(f"  - Crédits de recherche: {data.get('query_credits', 'N/A')}")
                print(f"  - Crédits de scan: {data.get('scan_credits', 'N/A')}")
                
                # Test de recherche simple
                search_params = {
                    'key': self.api_keys['shodan_api_key'],
                    'query': 'apache',
                    'limit': 1
                }
                
                search_response = requests.get(
                    'https://api.shodan.io/shodan/host/search',
                    params=search_params,
                    timeout=15
                )
                
                if search_response.status_code == 200:
                    search_data = search_response.json()
                    print(f"  - Test de recherche: {search_data.get('total', 0)} résultats disponibles")
                
                return True
            elif response.status_code == 401:
                print("✗ Erreur Shodan: Clé API invalide")
                return False
            else:
                print(f"✗ Erreur Shodan: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Erreur Shodan: {e}")
            return False
    
    def test_telegram_api(self):
        """Test de l'API Telegram"""
        print("\n" + "="*50)
        print("TEST TELEGRAM API")
        print("="*50)
        
        try:
            bot_token = self.api_keys['telegram_bot_token']
            
            print("🔄 Test de l'API Telegram Bot...")
            
            url = f"https://api.telegram.org/bot{bot_token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('ok'):
                    bot_info = data.get('result', {})
                    print("✓ Connexion Telegram Bot réussie")
                    print(f"  - Nom du bot: {bot_info.get('first_name', 'N/A')}")
                    print(f"  - Username: @{bot_info.get('username', 'N/A')}")
                    
                    return True
                else:
                    print(f"✗ Erreur Telegram: {data.get('description', 'Erreur inconnue')}")
                    return False
            else:
                print(f"✗ Erreur Telegram: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            print(f"✗ Erreur Telegram: {e}")
            return False
    
    def test_abuse_ch_api(self):
        """Test de l'API Abuse.ch"""
        print("\n" + "="*50)
        print("TEST ABUSE.CH (URLhaus)")
        print("="*50)
        
        try:
            print("🔄 Test de l'API Abuse.ch...")
            
            abuse_ch_key = self.api_keys.get('abuse_ch_auth_key')
            if not abuse_ch_key:
              print("✗ Clé d'authentification Abuse.ch manquante!")
              print("  Depuis le 30 juin 2025, l'authentification est obligatoire.")
              print("  Obtenez une clé gratuite sur: https://auth.abuse.ch/")
              print("  Ajoutez 'abuse_ch_auth_key' dans votre fichier api_keys.json")
              return False
            url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
            headers = {
            'Auth-Key': abuse_ch_key,
            'Content-Type': 'application/json'
            }
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                
                if data.get('query_status') == 'ok':
                    urls = data.get('urls', [])
                    print(f"✓ Connexion Abuse.ch réussie")
                    print(f"  - {len(urls)} URLs malveillantes récupérées")
                    
                    if urls:
                      print(f"  - Exemple d'URL: {urls[0].get('url', 'N/A')}")
                      print(f"  - Threat: {urls[0].get('threat', 'N/A')}")
                    return True
                else:
                    print(f"✗ Erreur Abuse.ch: {data.get('query_status')}")
                    return False
            else:
                print(f"✗ Erreur Abuse.ch: HTTP {response.status_code}")
                print(f"  Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"✗ Erreur Abuse.ch: {e}")
            return False
    
    def run_all_tests(self):
        """Exécute tous les tests d'APIs"""
        print("🚀 DÉBUT DES TESTS D'APIS CTI")
        print("=" * 60)
        print(f"Date et heure: {datetime.now().isoformat()}")
        
        results = {}
        
        # Tests individuels avec gestion d'erreurs
        test_functions = {
            'otx': self.test_otx_api,
            'twitter': self.test_twitter_api,
            'virustotal': self.test_virustotal_api,
            'shodan': self.test_shodan_api,
            'telegram': self.test_telegram_api,
            'abuse_ch': self.test_abuse_ch_api
        }
        
        for api_name, test_func in test_functions.items():
            try:
                results[api_name] = test_func()
            except KeyboardInterrupt:
                print(f"\n⚠️ Test de {api_name} interrompu par l'utilisateur")
                results[api_name] = False
                break
            except Exception as e:
                print(f"\n✗ Erreur inattendue lors du test {api_name}: {e}")
                results[api_name] = False
        
        # Résumé final
        print("\n" + "="*60)
        print("📊 RÉSUMÉ DES TESTS")
        print("="*60)
        
        total_tests = len(results)
        successful_tests = sum(results.values())
        
        for api, status in results.items():
            status_icon = "✓" if status else "✗"
            print(f"{status_icon} {api.upper()}: {'OK' if status else 'ÉCHEC'}")
        
        print(f"\n📈 Score global: {successful_tests}/{total_tests} APIs fonctionnelles")
        
        if successful_tests == total_tests:
            print("🎉 Toutes les APIs sont opérationnelles !")
        elif successful_tests > 0:
            print("⚠️  Certaines APIs nécessitent une attention")
        else:
            print("🚨 Aucune API n'est fonctionnelle - vérifiez vos clés")
        
        return results
    
    def test_specific_api(self, api_name):
        """Test d'une API spécifique"""
        api_tests = {
            'otx': self.test_otx_api,
            'twitter': self.test_twitter_api,
            'virustotal': self.test_virustotal_api,
            'shodan': self.test_shodan_api,
            'abuse_ch': self.test_abuse_ch_api,
            'telegram': self.test_telegram_api
        }
        
        if api_name.lower() in api_tests:
            print(f"🔍 Test spécifique de l'API: {api_name.upper()}")
            try:
                return api_tests[api_name.lower()]()
            except KeyboardInterrupt:
                print("\n⚠️ Test interrompu par l'utilisateur")
                return False
        else:
            print(f"❌ API inconnue: {api_name}")
            print(f"APIs disponibles: {', '.join(api_tests.keys())}")
            return False

def main():
    try:
        tester = APITester()
        
        if len(sys.argv) > 1:
            # Test d'une API spécifique
            api_name = sys.argv[1]
            tester.test_specific_api(api_name)
        else:
            # Test de toutes les APIs
            tester.run_all_tests()
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrompus par l'utilisateur")
        sys.exit(1)

if __name__ == "__main__":
    main()