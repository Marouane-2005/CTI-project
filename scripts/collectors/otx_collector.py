import sys
import os

# Ajoute le dossier scripts/ à sys.path
base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(base_path)
from OTXv2 import OTXv2
import json
import os
from datetime import datetime, timedelta
from utils.logger import CTILogger

class OTXCollector:
    def __init__(self):
        self.logger = CTILogger("OTX_Collector")
        
        # Configuration par défaut
        self.max_pulses = 100  # Valeur par défaut
        self.modified_since_hours = 24 * 7  # 7 jours par défaut
        
        # Charger la clé API
        try:
            api_keys_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'api_keys.json')
            if not os.path.exists(api_keys_path):
                # Essayer d'autres chemins possibles
                possible_paths = [
                    '../config/api_keys.json',
                    '../../config/api_keys.json',
                    os.path.join(os.getcwd(), 'config', 'api_keys.json')
                ]
                for path in possible_paths:
                    if os.path.exists(path):
                        api_keys_path = path
                        break
                else:
                    raise FileNotFoundError("Fichier api_keys.json non trouvé")
            
            with open(api_keys_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                api_key = config.get('otx_api_key')
                
            if not api_key:
                raise ValueError("Clé API OTX non trouvée dans le fichier de configuration")
                
            self.otx = OTXv2(api_key)
            self.logger.info("Collecteur OTX initialisé avec succès")
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'initialisation du collecteur OTX : {e}")
            self.otx = None
    
    def collect_recent_pulses(self, days_back=7):
        """Collecte les pulses récents"""
        if not self.otx:
            self.logger.error("Collecteur OTX non initialisé")
            return []
            
        try:
            self.logger.info(f"Collecte des pulses OTX des {days_back} derniers jours")
            
            # Calculer la date de début
            since_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%dT%H:%M:%S')
            collected_pulses = []
            
            try:
                # Essayer d'abord avec modified_since
                self.logger.info(f"Tentative de collecte avec modified_since={since_date}")
                pulses = self.otx.getall(modified_since=since_date, limit=self.max_pulses)
                self.logger.info(f"Collecte avec modified_since réussie : {len(pulses)} pulses")
                
            except (TypeError, Exception) as e:
                # Fallback : récupérer tous et filtrer manuellement
                self.logger.warning(f"modified_since non supporté ({e}), utilisation du fallback")
                try:
                    pulses = self.otx.getall(limit=self.max_pulses)
                    self.logger.info(f"Collecte fallback réussie : {len(pulses)} pulses bruts")
                    
                    # Filtrer par date manuellement
                    since_datetime = datetime.now() - timedelta(days=days_back)
                    filtered_pulses = []
                    
                    for pulse in pulses:
                        try:
                            # Gérer différents formats de date
                            modified_str = pulse.get('modified', '')
                            if modified_str:
                                # Nettoyer la chaîne de date
                                modified_str = modified_str.replace('Z', '+00:00')
                                if not modified_str.endswith('+00:00') and not modified_str.endswith('-'):
                                    modified_str += '+00:00'
                                
                                # Parser la date
                                try:
                                    modified_date = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
                                except ValueError:
                                    # Format alternatif
                                    modified_date = datetime.strptime(modified_str.split('+')[0], '%Y-%m-%dT%H:%M:%S')
                                
                                # Rendre la date aware si elle ne l'est pas
                                if modified_date.tzinfo is None:
                                    modified_date = modified_date.replace(tzinfo=datetime.now().astimezone().tzinfo)
                                
                                # Comparer avec since_datetime (rendre aware aussi)
                                if since_datetime.tzinfo is None:
                                    since_datetime = since_datetime.replace(tzinfo=datetime.now().astimezone().tzinfo)
                                
                                if modified_date > since_datetime:
                                    filtered_pulses.append(pulse)
                                    
                        except Exception as date_error:
                            self.logger.warning(f"Erreur parsing date pour pulse {pulse.get('id', 'unknown')}: {date_error}")
                            # Inclure le pulse en cas de doute
                            filtered_pulses.append(pulse)
                    
                    pulses = filtered_pulses
                    self.logger.info(f"Après filtrage par date : {len(pulses)} pulses")
                    
                except Exception as fallback_error:
                    self.logger.error(f"Erreur lors du fallback : {fallback_error}")
                    return []
            
            # Traiter chaque pulse
            for pulse in pulses[:self.max_pulses]:  # Limiter au maximum configuré
                try:
                    pulse_data = {
                        'id': pulse.get('id', ''),
                        'name': pulse.get('name', ''),
                        'description': pulse.get('description', ''),
                        'author_name': pulse.get('author_name', ''),
                        'created': pulse.get('created', ''),
                        'modified': pulse.get('modified', ''),
                        'tags': pulse.get('tags', []),
                        'industries': pulse.get('industries', []),
                        'malware_families': pulse.get('malware_families', []),
                        'attack_ids': pulse.get('attack_ids', []),
                        'indicators': [],
                        'collected_at': datetime.now().isoformat(),
                        'source': 'otx'
                    }
                    
                    # Collecter les indicateurs
                    indicators = pulse.get('indicators', [])
                    for indicator in indicators[:50]:  # Limiter les indicateurs par pulse
                        try:
                            indicator_data = {
                                'type': indicator.get('type', ''),
                                'value': indicator.get('indicator', ''),
                                'description': indicator.get('description', ''),
                                'created': indicator.get('created', ''),
                                'is_active': indicator.get('is_active', True)
                            }
                            pulse_data['indicators'].append(indicator_data)
                        except Exception as ind_error:
                            self.logger.warning(f"Erreur traitement indicateur : {ind_error}")
                    
                    collected_pulses.append(pulse_data)
                    
                except Exception as pulse_error:
                    self.logger.warning(f"Erreur traitement pulse {pulse.get('id', 'unknown')}: {pulse_error}")
                    continue
            
            # Sauvegarder les pulses
            if collected_pulses:
                try:
                    output_dir = os.path.join(os.path.dirname(__file__), '..', 'output', 'daily_feeds')
                    os.makedirs(output_dir, exist_ok=True)
                    
                    output_file = os.path.join(output_dir, f"otx_pulses_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(collected_pulses, f, indent=2, ensure_ascii=False, default=str)
                    
                    self.logger.info(f"Pulses sauvegardés dans : {output_file}")
                    
                except Exception as save_error:
                    self.logger.warning(f"Erreur lors de la sauvegarde : {save_error}")
            
            self.logger.info(f"Pulses OTX collectés : {len(collected_pulses)}")
            return collected_pulses
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte OTX : {e}")
            return []
    
    def search_pulses_by_keywords(self, keywords):
        """Recherche de pulses par mots-clés"""
        if not self.otx:
            self.logger.error("Collecteur OTX non initialisé")
            return []
            
        try:
            results = []
            
            for keyword in keywords:
                try:
                    self.logger.info(f"Recherche OTX pour : {keyword}")
                    search_results = self.otx.search_pulses(keyword)
                    
                    if search_results and 'results' in search_results:
                        for result in search_results['results'][:20]:  # Limiter les résultats
                            pulse_data = {
                                'keyword': keyword,
                                'pulse_id': result.get('id', ''),
                                'name': result.get('name', ''),
                                'description': result.get('description', ''),
                                'created': result.get('created', ''),
                                'modified': result.get('modified', ''),
                                'author_name': result.get('author_name', ''),
                                'tags': result.get('tags', []),
                                'industries': result.get('industries', []),
                                'malware_families': result.get('malware_families', []),
                                'search_date': datetime.now().isoformat(),
                                'source': 'otx_search'
                            }
                            results.append(pulse_data)
                    
                    self.logger.info(f"Trouvé {len(search_results.get('results', []))} résultats pour '{keyword}'")
                    
                except Exception as keyword_error:
                    self.logger.error(f"Erreur recherche pour '{keyword}' : {keyword_error}")
                    continue
            
            # Sauvegarder les résultats de recherche
            if results:
                try:
                    output_dir = os.path.join(os.path.dirname(__file__), '..', 'output', 'searches')
                    os.makedirs(output_dir, exist_ok=True)
                    
                    output_file = os.path.join(output_dir, f"otx_search_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    
                    search_data = {
                        'keywords': keywords,
                        'search_date': datetime.now().isoformat(),
                        'total_results': len(results),
                        'results': results
                    }
                    
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(search_data, f, indent=2, ensure_ascii=False, default=str)
                    
                    self.logger.info(f"Résultats de recherche sauvegardés dans : {output_file}")
                    
                except Exception as save_error:
                    self.logger.warning(f"Erreur lors de la sauvegarde des résultats : {save_error}")
            
            self.logger.info(f"Recherche terminée : {len(results)} résultats au total")
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la recherche OTX : {e}")
            return []
    
    def get_pulse_details(self, pulse_id):
        """Récupère les détails complets d'un pulse"""
        if not self.otx:
            self.logger.error("Collecteur OTX non initialisé")
            return None
            
        try:
            self.logger.info(f"Récupération des détails du pulse : {pulse_id}")
            pulse_details = self.otx.get_pulse_details(pulse_id)
            
            if pulse_details:
                # Enrichir avec des métadonnées
                pulse_details['retrieved_at'] = datetime.now().isoformat()
                pulse_details['source'] = 'otx_details'
            
            return pulse_details
            
        except Exception as e:
            self.logger.error(f"Erreur récupération détails pulse {pulse_id} : {e}")
            return None
    
    def get_indicators_by_type(self, indicator_type, limit=100):
        """Récupère les indicateurs par type"""
        if not self.otx:
            self.logger.error("Collecteur OTX non initialisé")
            return []
            
        try:
            self.logger.info(f"Récupération indicateurs de type : {indicator_type}")
            indicators = self.otx.get_all_indicators(indicator_type=indicator_type, limit=limit)
            
            # Enrichir les indicateurs
            for indicator in indicators:
                indicator['retrieved_at'] = datetime.now().isoformat()
                indicator['source'] = 'otx_indicators'
            
            self.logger.info(f"Indicateurs {indicator_type} récupérés : {len(indicators)}")
            return indicators
            
        except Exception as e:
            self.logger.error(f"Erreur récupération indicateurs {indicator_type} : {e}")
            return []
    
    def test_connection(self):
        """Test de la connexion à l'API OTX"""
        if not self.otx:
            return False, "Collecteur non initialisé"
            
        try:
            # Test simple avec une recherche vide
            test_result = self.otx.search_pulses("test", limit=1)
            return True, "Connexion OTX OK"
        except Exception as e:
            return False, f"Erreur connexion OTX : {e}"
    
# Test du collecteur
if __name__ == "__main__":
    collector = OTXCollector()
    
    # Test de connexion
    is_connected, message = collector.test_connection()
    print(f"Test connexion : {message}")
    
    if is_connected:
        print("\n=== Test collecte pulses récents ===")
        pulses = collector.collect_recent_pulses(days_back=7)
        print(f"Pulses collectés : {len(pulses)}")
        
        if pulses:
            print(f"Premier pulse : {pulses[0]['name']}")
        
        print("\n=== Test recherche par mots-clés ===")
        keywords = ["ransomware", "apt", "malware"]
        results = collector.search_pulses_by_keywords(keywords)
        print(f"Résultats de recherche : {len(results)}")
        
        if results:
            print(f"Premier résultat : {results[0]['name']}")
    else:
        print("Impossible de tester les fonctionnalités sans connexion API")