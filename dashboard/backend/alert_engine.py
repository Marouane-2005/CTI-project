import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from scripts.utils.database import Database
from scripts.analyzers.risk_calculator import RiskCalculator

class AlertEngine:
    def __init__(self):
        self.db = Database()
        self.risk_calc = RiskCalculator()
        self.alert_rules = self.load_alert_rules()
        self.notification_channels = self.load_notification_config()
    
    def load_alert_rules(self) -> Dict:
        """Chargement des règles d'alertes"""
        default_rules = {
            'critical_ioc_threshold': 8.0,
            'suspicious_pattern_count': 5,
            'geo_anomaly_threshold': 3,
            'new_campaign_indicators': 3,
            'mitre_technique_frequency': 10,
            'time_window_minutes': 60
        }
        
        try:
            with open('../../config/alert_rules.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return default_rules
    
    def load_notification_config(self) -> Dict:
        """Configuration des notifications"""
        try:
            with open('../../config/notifications.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {
                'email': {'enabled': False},
                'slack': {'enabled': False},
                'webhook': {'enabled': False}
            }
    
    def process_indicator(self, indicator_data: Dict) -> List[Dict]:
        """Traitement d'un indicateur pour génération d'alertes"""
        alerts = []
        
        # Calcul du score de risque
        risk_score = self.risk_calc.calculate_risk(indicator_data)
        
        # Règle 1: Seuil critique
        if risk_score >= self.alert_rules['critical_ioc_threshold']:
            alerts.append(self.create_alert(
                level='critical',
                title='IOC à risque critique détecté',
                description=f"Indicateur {indicator_data.get('value')} avec score {risk_score}",
                indicator_data=indicator_data,
                risk_score=risk_score
            ))
        
        # Règle 2: Pattern géographique suspect
        if self.detect_geo_anomaly(indicator_data):
            alerts.append(self.create_alert(
                level='high',
                title='Anomalie géographique détectée',
                description='Pattern géographique inhabituel détecté',
                indicator_data=indicator_data
            ))
        
        # Règle 3: Nouvelle campagne potentielle
        if self.detect_new_campaign(indicator_data):
            alerts.append(self.create_alert(
                level='medium',
                title='Nouvelle campagne potentielle',
                description='Cluster d\'indicateurs suggérant une nouvelle campagne',
                indicator_data=indicator_data
            ))
        
        # Règle 4: Technique MITRE fréquente
        if self.detect_mitre_frequency_anomaly(indicator_data):
            alerts.append(self.create_alert(
                level='high',
                title='Technique MITRE très active',
                description='Augmentation significative d\'une technique MITRE',
                indicator_data=indicator_data
            ))
        
        # Stockage et notification des alertes
        for alert in alerts:
            self.store_alert(alert)
            self.send_notifications(alert)
        
        return alerts
    
    # CORRECTION : Ajouter la logique manquante
    
    
    # Liste des pays inhabituels - à adapter selon votre contexte
      
    def get_unusual_countries(self):
      return ['CN', 'RU', 'IR', 'KP', 'BY']
    
    def get_suspicious_countries(self):
     try:
        # Charger depuis la config si disponible
        config_file = '../../config/suspicious_countries.json'
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f).get('countries', [])
     except Exception:
        pass
    
     # Valeurs par défaut
     return ['CN', 'RU', 'IR', 'KP', 'BY', 'SY']

    def find_similar_indicators(self, indicator_data: Dict, recent_indicators: List) -> List:
      similar = []
      current_tags = set(indicator_data.get('tags', []))
      current_type = indicator_data.get('type', '')
      current_source = indicator_data.get('source', '')
    
      for indicator in recent_indicators:
        similarity_score = 0
        indicator_tags = set(indicator.get('tags', []))
        
        # Similarité par tags
        common_tags = current_tags.intersection(indicator_tags)
        if len(common_tags) >= 2:
            similarity_score += len(common_tags) * 0.3
        
        # Similarité par type
        if current_type == indicator.get('type', ''):
            similarity_score += 0.2
            
        # Similarité par source
        if current_source == indicator.get('source', ''):
            similarity_score += 0.1
        
        # Techniques MITRE communes
        current_techniques = set(indicator_data.get('mitre_techniques', []))
        indicator_techniques = set(indicator.get('mitre_techniques', []))
        common_techniques = current_techniques.intersection(indicator_techniques)
        if common_techniques:
            similarity_score += len(common_techniques) * 0.4
        
        # Seuil de similarité
        if similarity_score >= 0.6:
            similar.append({
                **indicator,
                'similarity_score': similarity_score
            })
    
      return sorted(similar, key=lambda x: x['similarity_score'], reverse=True)


    def create_alert(self, level: str, title: str, description: str, 
                    indicator_data: Dict, risk_score: float = None) -> Dict:
        """Création d'une alerte structurée"""
        return {
            'id': self.generate_alert_id(),
            'level': level,
            'title': title,
            'description': description,
            'indicator': indicator_data,
            'risk_score': risk_score,
            'timestamp': datetime.now().isoformat(),
            'acknowledged': False,
            'mitre_techniques': indicator_data.get('mitre_techniques', []),
            'source': indicator_data.get('source', 'unknown')
        }
    
    def detect_geo_anomaly(self, indicator_data: Dict) -> bool:
     try:
        geo_data = indicator_data.get('geolocation', {})
        if not geo_data:
            return False
        
        # Liste des pays à surveiller (configurable)
        suspicious_countries = self.get_suspicious_countries()
        country_code = geo_data.get('country_code') or geo_data.get('country')
        
        if country_code in suspicious_countries:
            logger.info(f"🌍 Anomalie géo détectée: {country_code}")
            return True
            
        return False
        
     except Exception as e:
        logger.error(f"Erreur detect_geo_anomaly: {e}")
        return False
    
    def detect_new_campaign(self, indicator_data: Dict) -> bool:
        """Détection de nouvelles campagnes - CORRECTION"""
        try:
            # Analyse des patterns récents
            recent_indicators = self.db.get_recent_indicators(hours=24)
            
            # Clustering basé sur les attributs
            similar_indicators = self.find_similar_indicators(
                indicator_data, recent_indicators
            )
            
            return len(similar_indicators) >= self.alert_rules['new_campaign_indicators']
        except Exception as e:
            print(f"Erreur detect_new_campaign: {e}")
            return False
        
        
    def detect_mitre_frequency_anomaly(self, indicator_data: Dict) -> bool:
        """Détection d'anomalies de fréquence MITRE"""
        techniques = indicator_data.get('mitre_techniques', [])
        if not techniques:
            return False
        
        for technique in techniques:
            recent_count = self.db.count_technique_occurrences(
                technique, hours=self.alert_rules['time_window_minutes'] // 60
            )
            if recent_count >= self.alert_rules['mitre_technique_frequency']:
                return True
        
        return False
    
    def store_alert(self, alert: Dict):
        """Stockage de l'alerte en base"""
        self.db.insert_alert(alert)
    
    def send_notifications(self, alert: Dict):
        """Envoi des notifications"""
        if alert['level'] == 'critical' and self.notification_channels.get('email', {}).get('enabled'):
            self.send_email_notification(alert)
        
        if alert['level'] in ['critical', 'high'] and self.notification_channels.get('slack', {}).get('enabled'):
            self.send_slack_notification(alert)
        
        if self.notification_channels.get('webhook', {}).get('enabled'):
            self.send_webhook_notification(alert)
    
    def generate_alert_id(self) -> str:
        """Génération d'un ID unique pour l'alerte"""
        return f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(datetime.now().microsecond) % 10000}"
    
    # Méthodes de notification à implémenter selon vos besoins
    def send_email_notification(self, alert: Dict):
        """Notification email"""
        pass  # Implémentation selon votre config
    
    def send_slack_notification(self, alert: Dict):
        """Notification Slack"""
        pass  # Implémentation selon votre config
    
    def send_webhook_notification(self, alert: Dict):
        """Notification webhook"""
        pass  # Implémentation selon votre config