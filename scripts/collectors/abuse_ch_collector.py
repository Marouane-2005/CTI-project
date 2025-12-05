"""
Collecteur Abuse.ch pour la veille CTI - VERSION CORRIGÉE avec CSV Parser
Collecte les indicateurs de compromission depuis les feeds Abuse.ch
"""
import sys
import os

# Ajoute le dossier scripts/ à sys.path
base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(base_path)

import json
import os
import requests
import csv
from datetime import datetime, timedelta
from io import StringIO
from utils.logger import CTILogger

class AbuseCHCollector:
    def __init__(self):
        self.logger = CTILogger("AbuseCH_Collector")
        
        # URLs des feeds Abuse.ch - CORRIGÉES
        self.feeds = {
            'malware_bazaar': {
                'url': 'https://bazaar.abuse.ch/export/csv/recent/',
                'type': 'malware_samples',
                'description': 'Échantillons de malware récents'
            },
            'feodo_tracker': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                'type': 'botnet_ips',
                'description': 'IPs de botnets Feodo/Emotet/Qakbot'
            },
            'ssl_blacklist': {
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'type': 'malicious_ssl',
                'description': 'Certificats SSL malveillants'
            },
            'url_haus': {
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'type': 'malicious_urls',
                'description': 'URLs malveillantes récentes'
            },
            'threat_fox': {
                'url': 'https://threatfox.abuse.ch/export/csv/recent/',
                'type': 'iocs',
                'description': 'Indicateurs de compromission'
            }
        }
        
        # Configuration des headers
        self.headers = {
            'User-Agent': 'CTI-Collector/1.0 (Cyber Threat Intelligence Tool)',
            'Accept': 'text/csv,application/csv,text/plain,*/*'
        }
    
    def collect_feed(self, feed_name, feed_config):
        """Collecte un feed spécifique d'Abuse.ch"""
        try:
            self.logger.info(f"Collecte du feed {feed_name}: {feed_config['description']}")
            
            # Télécharger le feed avec gestion d'erreurs améliorée
            response = requests.get(
                feed_config['url'], 
                headers=self.headers, 
                timeout=60,
                allow_redirects=True
            )
            
            self.logger.info(f"Réponse HTTP pour {feed_name}: {response.status_code}")
            
            # Vérifier si la réponse est vide ou invalide
            if not response.text.strip():
                self.logger.warning(f"Réponse vide pour {feed_name}")
                return []
            
            # Log des premières lignes pour débugger
            first_lines = response.text[:500]
            self.logger.info(f"Premières lignes de {feed_name}: {first_lines[:200]}...")
            
            response.raise_for_status()
            
            # Parser le CSV avec gestion d'erreurs améliorée
            indicators = []
            
            try:
                # Traiter selon le type de feed
                if feed_name == 'malware_bazaar':
                    indicators = self._parse_malware_bazaar(response.text)
                elif feed_name == 'feodo_tracker':
                    indicators = self._parse_feodo_tracker(response.text)
                elif feed_name == 'ssl_blacklist':
                    indicators = self._parse_ssl_blacklist(response.text)
                elif feed_name == 'url_haus':
                    indicators = self._parse_url_haus(response.text)
                elif feed_name == 'threat_fox':
                    indicators = self._parse_threat_fox(response.text)
                
            except Exception as parse_error:
                self.logger.error(f"Erreur de parsing pour {feed_name}: {parse_error}")
                self.logger.info(f"Contenu problématique: {response.text[:1000]}")
                return []
            
            # Ajouter les métadonnées
            for indicator in indicators:
                indicator.update({
                    'source': f'abuse.ch_{feed_name}',
                    'feed_type': feed_config['type'],
                    'collected_at': datetime.now().isoformat()
                })
            
            # Sauvegarder avec chemin absolu
            output_dir = os.path.abspath(os.path.join(
                os.path.dirname(__file__), '..', 'output', 'daily_feeds'
            ))
            os.makedirs(output_dir, exist_ok=True)
            
            output_file = os.path.join(
                output_dir,
                f"abuse_ch_{feed_name}_{datetime.now().strftime('%Y%m%d')}.json"
            )
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(indicators, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Feed {feed_name} collecté : {len(indicators)} indicateurs")
            return indicators
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout lors de la collecte du feed {feed_name}")
            return []
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Erreur de requête pour le feed {feed_name}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte du feed {feed_name}: {e}")
            return []
    
    def _parse_csv_robust(self, csv_text, delimiter=','):
        """
        Parse CSV de manière robuste en utilisant le module csv de Python
        Gère les virgules dans les champs et les guillemets
        """
        try:
            # Filtrer les commentaires et lignes vides
            lines = [line for line in csv_text.strip().split('\n') 
                    if line.strip() and not line.startswith('#')]
            
            if not lines:
                return [], []
            
            # Utiliser StringIO pour traiter comme un fichier
            csv_file = StringIO('\n'.join(lines))
            
            # Détecter le dialecte CSV automatiquement
            try:
                sample = '\n'.join(lines[:10])  # Échantillon des 10 premières lignes
                dialect = csv.Sniffer().sniff(sample, delimiters=',;|')
                csv_file.seek(0)
                reader = csv.reader(csv_file, dialect)
            except:
                # Fallback vers le dialecte par défaut
                csv_file.seek(0)
                reader = csv.reader(csv_file, delimiter=delimiter, quotechar='"')
            
            # Lire toutes les lignes
            rows = list(reader)
            
            if not rows:
                return [], []
            
            # Première ligne = headers
            headers = [h.strip() for h in rows[0]]
            
            # Autres lignes = données
            data_rows = rows[1:] if len(rows) > 1 else []
            
            return headers, data_rows
            
        except Exception as e:
            self.logger.error(f"Erreur parsing CSV robuste: {e}")
            return [], []
    
    def _parse_malware_bazaar(self, csv_text):
        """Parse le feed Malware Bazaar avec CSV parser robuste"""
        indicators = []
        try:
            headers, data_rows = self._parse_csv_robust(csv_text)
            
            if not headers or not data_rows:
                self.logger.warning("Aucune donnée CSV valide trouvée pour Malware Bazaar")
                return indicators
                
            self.logger.info(f"Malware Bazaar - Headers détectés: {headers}")
            self.logger.info(f"Malware Bazaar - {len(data_rows)} lignes de données")
            
            for row_num, values in enumerate(data_rows, 1):
                try:
                    # Vérifier la cohérence du nombre de colonnes
                    if len(values) != len(headers):
                        # Essayer de corriger en ajustant la longueur
                        if len(values) < len(headers):
                            values.extend([''] * (len(headers) - len(values)))
                        else:
                            values = values[:len(headers)]
                    
                    # Créer un dictionnaire avec les headers
                    row = dict(zip(headers, values))
                    
                    # Nettoyer les valeurs
                    for key in row:
                        if isinstance(row[key], str):
                            row[key] = row[key].strip()
                    
                    # Chercher le hash SHA256 dans différents champs possibles
                    sha256_hash = (row.get('sha256_hash') or 
                                 row.get('sha256') or 
                                 row.get('hash') or
                                 row.get('SHA256'))
                    
                    if sha256_hash and sha256_hash.strip() and sha256_hash != '':
                        indicator = {
                            'type': 'file_hash',
                            'value': sha256_hash.strip(),
                            'first_seen': row.get('first_seen', '').strip(),
                            'last_seen': row.get('last_seen', '').strip(),
                            'malware_family': row.get('malware', row.get('signature', '')).strip(),
                            'file_name': row.get('file_name', '').strip(),
                            'file_size': row.get('file_size', '').strip(),
                            'file_type': row.get('file_type', '').strip(),
                            'tags': [tag.strip() for tag in str(row.get('tags', '')).split(',') if tag.strip()],
                            'confidence': 'high'
                        }
                        indicators.append(indicator)
                        
                except Exception as row_error:
                    self.logger.warning(f"Erreur ligne {row_num} Malware Bazaar: {row_error}")
                    continue
                    
            self.logger.info(f"Malware Bazaar: {len(indicators)} indicateurs parsés")
                    
        except Exception as e:
            self.logger.error(f"Erreur parsing Malware Bazaar: {e}")
            
        return indicators
    
    def _parse_feodo_tracker(self, csv_text):
        """Parse le feed Feodo Tracker avec CSV parser robuste"""
        indicators = []
        try:
            headers, data_rows = self._parse_csv_robust(csv_text)
            
            if not headers or not data_rows:
                self.logger.warning("Aucune donnée CSV valide trouvée pour Feodo Tracker")
                return indicators
                
            self.logger.info(f"Feodo Tracker - Headers détectés: {headers}")
            self.logger.info(f"Feodo Tracker - {len(data_rows)} lignes de données")
            
            for row_num, values in enumerate(data_rows, 1):
                try:
                    # Ajuster la longueur si nécessaire
                    if len(values) != len(headers):
                        if len(values) < len(headers):
                            values.extend([''] * (len(headers) - len(values)))
                        else:
                            values = values[:len(headers)]
                    
                    row = dict(zip(headers, values))
                    
                    # Nettoyer les valeurs
                    for key in row:
                        if isinstance(row[key], str):
                            row[key] = row[key].strip()
                    
                    # Chercher l'adresse IP dans différents champs possibles
                    ip_address = (row.get('ip_address') or 
                                row.get('ip') or 
                                row.get('dst_ip') or 
                                row.get('IPAddress') or
                                row.get('IP'))
                    
                    if ip_address and ip_address.strip() and ip_address != '':
                        indicator = {
                            'type': 'ip_address',
                            'value': ip_address.strip(),
                            'port': row.get('port', '').strip(),
                            'status': row.get('status', '').strip(),
                            'hostname': row.get('hostname', '').strip(),
                            'as_number': row.get('as_number', '').strip(),
                            'as_name': row.get('as_name', '').strip(),
                            'country': row.get('country', '').strip(),
                            'first_seen': row.get('first_seen', '').strip(),
                            'last_seen': row.get('last_seen', '').strip(),
                            'malware_family': 'feodo/emotet/qakbot',
                            'confidence': 'high'
                        }
                        indicators.append(indicator)
                        
                except Exception as row_error:
                    self.logger.warning(f"Erreur ligne {row_num} Feodo Tracker: {row_error}")
                    continue
                    
            self.logger.info(f"Feodo Tracker: {len(indicators)} indicateurs parsés")
                    
        except Exception as e:
            self.logger.error(f"Erreur parsing Feodo Tracker: {e}")
            
        return indicators
    
    def _parse_ssl_blacklist(self, csv_text):
        """Parse le feed SSL Blacklist avec CSV parser robuste"""
        indicators = []
        try:
            headers, data_rows = self._parse_csv_robust(csv_text)
            
            if not headers or not data_rows:
                self.logger.warning("Aucune donnée CSV valide trouvée pour SSL Blacklist")
                return indicators
                
            self.logger.info(f"SSL Blacklist - Headers détectés: {headers}")
            self.logger.info(f"SSL Blacklist - {len(data_rows)} lignes de données")
            
            for row_num, values in enumerate(data_rows, 1):
                try:
                    # Ajuster la longueur si nécessaire
                    if len(values) != len(headers):
                        if len(values) < len(headers):
                            values.extend([''] * (len(headers) - len(values)))
                        else:
                            values = values[:len(headers)]
                    
                    row = dict(zip(headers, values))
                    
                    # Nettoyer les valeurs
                    for key in row:
                        if isinstance(row[key], str):
                            row[key] = row[key].strip()
                    
                    fingerprint = (row.get('sha1_fingerprint') or 
                                 row.get('sha1') or 
                                 row.get('fingerprint') or
                                 row.get('SHA1') or
                                 row.get('Listing_reason'))
                    
                    if fingerprint and fingerprint.strip() and fingerprint != '':
                        indicator = {
                            'type': 'ssl_certificate',
                            'value': fingerprint.strip(),
                            'subject': row.get('subject', '').strip(),
                            'issuer': row.get('issuer', '').strip(),
                            'not_before': row.get('not_before', '').strip(),
                            'not_after': row.get('not_after', '').strip(),
                            'reason': row.get('reason', row.get('Listing_reason', '')).strip(),
                            'confidence': 'high'
                        }
                        indicators.append(indicator)
                        
                except Exception as row_error:
                    self.logger.warning(f"Erreur ligne {row_num} SSL Blacklist: {row_error}")
                    continue
                    
            self.logger.info(f"SSL Blacklist: {len(indicators)} indicateurs parsés")
                    
        except Exception as e:
            self.logger.error(f"Erreur parsing SSL Blacklist: {e}")
            
        return indicators
    
    def _parse_url_haus(self, csv_text):
        """Parse le feed URLhaus avec CSV parser robuste"""
        indicators = []
        try:
            headers, data_rows = self._parse_csv_robust(csv_text)
            
            if not headers or not data_rows:
                self.logger.warning("Aucune donnée CSV valide trouvée pour URLhaus")
                return indicators
                
            self.logger.info(f"URLhaus - Headers détectés: {headers}")
            self.logger.info(f"URLhaus - {len(data_rows)} lignes de données")
            
            for row_num, values in enumerate(data_rows, 1):
                try:
                    # Ajuster la longueur si nécessaire
                    if len(values) != len(headers):
                        if len(values) < len(headers):
                            values.extend([''] * (len(headers) - len(values)))
                        else:
                            values = values[:len(headers)]
                    
                    row = dict(zip(headers, values))
                    
                    # Nettoyer les valeurs
                    for key in row:
                        if isinstance(row[key], str):
                            row[key] = row[key].strip()
                    
                    url = row.get('url', '').strip()
                    
                    if url and url != '':
                        indicator = {
                            'type': 'url',
                            'value': url,
                            'url_status': row.get('url_status', '').strip(),
                            'date_added': row.get('date_added', '').strip(),
                            'threat': row.get('threat', '').strip(),
                            'tags': [tag.strip() for tag in str(row.get('tags', '')).split(',') if tag.strip()],
                            'urlhaus_link': row.get('urlhaus_link', '').strip(),
                            'confidence': 'high'
                        }
                        indicators.append(indicator)
                        
                except Exception as row_error:
                    self.logger.warning(f"Erreur ligne {row_num} URLhaus: {row_error}")
                    continue
                    
            self.logger.info(f"URLhaus: {len(indicators)} indicateurs parsés")
                    
        except Exception as e:
            self.logger.error(f"Erreur parsing URLhaus: {e}")
            
        return indicators
    
    def _parse_threat_fox(self, csv_text):
        """Parse le feed ThreatFox avec CSV parser robuste"""
        indicators = []
        try:
            headers, data_rows = self._parse_csv_robust(csv_text)
            
            if not headers or not data_rows:
                self.logger.warning("Aucune donnée CSV valide trouvée pour ThreatFox")
                return indicators
                
            self.logger.info(f"ThreatFox - Headers détectés: {headers}")
            self.logger.info(f"ThreatFox - {len(data_rows)} lignes de données")
            
            for row_num, values in enumerate(data_rows, 1):
                try:
                    # Ajuster la longueur si nécessaire
                    if len(values) != len(headers):
                        if len(values) < len(headers):
                            values.extend([''] * (len(headers) - len(values)))
                        else:
                            values = values[:len(headers)]
                    
                    row = dict(zip(headers, values))
                    
                    # Nettoyer les valeurs
                    for key in row:
                        if isinstance(row[key], str):
                            row[key] = row[key].strip()
                    
                    ioc_value = row.get('ioc', '').strip()
                    
                    if ioc_value and ioc_value != '':
                        indicator = {
                            'type': row.get('ioc_type', 'unknown').strip(),
                            'value': ioc_value,
                            'malware_family': row.get('malware', '').strip(),
                            'malware_alias': row.get('malware_alias', '').strip(),
                            'confidence_level': row.get('confidence_level', '').strip(),
                            'first_seen': row.get('first_seen', '').strip(),
                            'last_seen': row.get('last_seen', '').strip(),
                            'reference': row.get('reference', '').strip(),
                            'tags': [tag.strip() for tag in str(row.get('tags', '')).split(',') if tag.strip()],
                            'confidence': 'high'
                        }
                        indicators.append(indicator)
                        
                except Exception as row_error:
                    self.logger.warning(f"Erreur ligne {row_num} ThreatFox: {row_error}")
                    continue
                    
            self.logger.info(f"ThreatFox: {len(indicators)} indicateurs parsés")
                    
        except Exception as e:
            self.logger.error(f"Erreur parsing ThreatFox: {e}")
            
        return indicators
    
    def collect_all_feeds(self):
        """Collecte tous les feeds Abuse.ch"""
        all_indicators = []
        
        for feed_name, feed_config in self.feeds.items():
            indicators = self.collect_feed(feed_name, feed_config)
            all_indicators.extend(indicators)
        
        # Sauvegarder le résumé global
        summary = {
            'total_indicators': len(all_indicators),
            'feeds_processed': len(self.feeds),
            'collection_date': datetime.now().isoformat(),
            'indicators_by_type': self._count_by_type(all_indicators),
            'indicators': all_indicators
        }
        
        # Chemin absolu pour le fichier de résumé
        output_dir = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'output', 'daily_feeds'
        ))
        os.makedirs(output_dir, exist_ok=True)
        
        summary_file = os.path.join(
            output_dir,
            f"abuse_ch_summary_{datetime.now().strftime('%Y%m%d')}.json"
        )
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Collecte Abuse.ch terminée : {len(all_indicators)} indicateurs")
        return all_indicators
    
    def _count_by_type(self, indicators):
        """Compte les indicateurs par type"""
        counts = {}
        for indicator in indicators:
            ioc_type = indicator.get('type', 'unknown')
            counts[ioc_type] = counts.get(ioc_type, 0) + 1
        return counts
    
    def search_indicators(self, search_terms, days_back=7):
        """Recherche dans les indicateurs collectés"""
        try:
            self.logger.info(f"Recherche d'indicateurs : {search_terms}")
            
            results = []
            since_date = datetime.now() - timedelta(days=days_back)
            
            # Rechercher dans les fichiers récents avec chemin absolu
            output_dir = os.path.abspath(os.path.join(
                os.path.dirname(__file__), '..', 'output', 'daily_feeds'
            ))
            
            for i in range(days_back):
                date_str = (datetime.now() - timedelta(days=i)).strftime('%Y%m%d')
                summary_file = os.path.join(output_dir, f"abuse_ch_summary_{date_str}.json")
                
                if os.path.exists(summary_file):
                    with open(summary_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        for indicator in data.get('indicators', []):
                            # Rechercher dans la valeur de l'indicateur
                            for term in search_terms:
                                if term.lower() in indicator.get('value', '').lower():
                                    results.append({
                                        'search_term': term,
                                        'indicator': indicator,
                                        'match_field': 'value'
                                    })
                                # Rechercher dans la famille de malware
                                elif term.lower() in indicator.get('malware_family', '').lower():
                                    results.append({
                                        'search_term': term,
                                        'indicator': indicator,
                                        'match_field': 'malware_family'
                                    })
                                # Rechercher dans les tags
                                elif any(term.lower() in tag.lower() for tag in indicator.get('tags', [])):
                                    results.append({
                                        'search_term': term,
                                        'indicator': indicator,
                                        'match_field': 'tags'
                                    })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la recherche : {e}")
            return []
    
    def get_feed_status(self):
        """Vérifie le statut des feeds"""
        status = {
            'check_time': datetime.now().isoformat(),
            'feeds_status': {}
        }
        
        for feed_name, feed_config in self.feeds.items():
            try:
                response = requests.head(
                    feed_config['url'], 
                    headers=self.headers, 
                    timeout=30,
                    allow_redirects=True
                )
                status['feeds_status'][feed_name] = {
                    'status': 'online' if response.status_code == 200 else 'warning',
                    'status_code': response.status_code,
                    'description': feed_config['description'],
                    'content_length': response.headers.get('Content-Length', 'unknown')
                }
            except Exception as e:
                status['feeds_status'][feed_name] = {
                    'status': 'error',
                    'error': str(e),
                    'description': feed_config['description']
                }
        
        return status
    
    def collect_sync(self):
        """Méthode synchrone pour compatibilité avec main_collector"""
        return self.collect_all_feeds()
    
    def debug_feed_content(self, feed_name, max_lines=20):
        """Méthode pour débugger le contenu d'un feed spécifique"""
        if feed_name not in self.feeds:
            print(f"Feed {feed_name} non trouvé. Feeds disponibles: {list(self.feeds.keys())}")
            return
            
        feed_config = self.feeds[feed_name]
        
        try:
            response = requests.get(feed_config['url'], headers=self.headers, timeout=60)
            print(f"=== DEBUG {feed_name.upper()} ===")
            print(f"Status: {response.status_code}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'unknown')}")
            print(f"Content-Length: {len(response.text)}")
            print("\n=== CONTENU BRUT (premières lignes) ===")
            
            lines = response.text.split('\n')[:max_lines]
            for i, line in enumerate(lines, 1):
                print(f"{i:2d}: {line}")
                
            print(f"\n=== ANALYSE CSV ROBUSTE ===")
            headers, data_rows = self._parse_csv_robust(response.text)
            print(f"Headers détectés: {headers}")
            print(f"Nombre de lignes de données: {len(data_rows)}")
            
            if data_rows:
                print("\n=== PREMIÈRE LIGNE DE DONNÉES ===")
                first_row = data_rows[0]
                for i, (header, value) in enumerate(zip(headers, first_row)):
                    print(f"{header}: '{value}'")
                    
                print(f"\n=== ANALYSE ÉCHANTILLON (5 premières lignes) ===")
                for row_num, row_data in enumerate(data_rows[:5], 1):
                    if len(row_data) != len(headers):
                        print(f"Ligne {row_num}: {len(row_data)} colonnes vs {len(headers)} attendues")
                    else:
                        print(f"Ligne {row_num}: OK ({len(row_data)} colonnes)")
                    
        except Exception as e:
            print(f"Erreur lors du debug: {e}")

# Test du collecteur avec diagnostics améliorés
if __name__ == "__main__":
    import sys
    
    collector = AbuseCHCollector()
    
    if len(sys.argv) > 1:
        command = sys.argv[1]
        
        if command == "collect":
            # Collecte de tous les feeds
            indicators = collector.collect_all_feeds()
            print(f"Indicateurs collectés : {len(indicators)}")
            
        elif command == "search" and len(sys.argv) > 2:
            # Recherche d'indicateurs
            search_terms = sys.argv[2].split(',')
            results = collector.search_indicators(search_terms)
            print(f"Résultats trouvés : {len(results)}")
            
        elif command == "status":
            # Vérification du statut des feeds
            status = collector.get_feed_status()
            print(json.dumps(status, indent=2))
            
        elif command == "debug" and len(sys.argv) > 2:
            # Debug d'un feed spécifique
            feed_name = sys.argv[2]
            collector.debug_feed_content(feed_name)
            
        elif command == "test":
            # Test de diagnostic complet
            print("=== Test de diagnostic Abuse.ch ===")
            status = collector.get_feed_status()
            
            for feed_name, feed_status in status['feeds_status'].items():
                print(f"\n{feed_name.upper()}:")
                print(f"  Status: {feed_status['status']}")
                print(f"  Code: {feed_status.get('status_code', 'N/A')}")
                
                if feed_status['status'] == 'online':
                    # Test de collecte pour ce feed
                    feed_config = collector.feeds[feed_name]
                    indicators = collector.collect_feed(feed_name, feed_config)
                    print(f"  Indicateurs: {len(indicators)}")
                    
                    if indicators:
                        print(f"  Exemple: {indicators[0]}")
            
        else:
            print("Usage: python abuse_ch_collector.py [collect|search|status|test|debug <feed_name>]")
    else:
        # Test par défaut
        print("=== Test rapide ===")
        status = collector.get_feed_status()
        print("Statut des feeds:")
        for feed, info in status['feeds_status'].items():
            print(f"  {feed}: {info['status']}")
        
        print("\nTest de collecte...")
        indicators = collector.collect_all_feeds()
        print(f"Total collecté: {len(indicators)} indicateurs")