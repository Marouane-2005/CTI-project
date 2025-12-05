"""
WebSocket Handler pour le dashboard CTI
Gestion des connexions temps réel pour la veille automatique
"""

import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Set
from flask_socketio import emit, join_room, leave_room

# Configuration du logger pour Docker
def setup_docker_logger():
    """Configure le logger pour affichage dans Docker"""
    
    # Créer le dossier logs s'il n'existe pas
    os.makedirs('logs', exist_ok=True)
    
    # Format des logs
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Logger principal
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Éviter les handlers dupliqués
    if not logger.handlers:
        
        # 1. HANDLER CONSOLE (CRUCIAL pour Docker logs)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # 2. HANDLER FICHIER (optionnel)
        try:
            file_handler = logging.FileHandler('logs/websocket.log', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            # Si échec fichier, continue avec console seulement
            print(f"Warning: Cannot create log file: {e}")
    
    return logger

# Initialiser le logger
logger = setup_docker_logger()
class WebSocketHandler:
    def __init__(self, socketio):
        self.socketio = socketio
        self.connected_clients: Set[str] = set()
        self.client_subscriptions: Dict[str, List[str]] = {}
        self.rooms = {
            'threats': 'threat_updates',
            'alerts': 'alert_updates', 
            'iocs': 'ioc_updates',
            'campaigns': 'campaign_updates',
            'mitre': 'mitre_updates'
        }
        
        # Log d'initialisation pour vérifier que ça fonctionne
        logger.info("🚀 WebSocket Handler initialisé")
        print("WebSocket Handler - Debug print")  # Debug supplémentaire
        
        # Enregistrement des événements
        self.register_events()
        
    def register_events(self):
        """Enregistrement des événements WebSocket"""
        
        logger.info("📝 Enregistrement des événements WebSocket")
        
        @self.socketio.on('connect')
        def handle_connect():
            client_id = self.get_client_id()
            self.connected_clients.add(client_id)
            self.client_subscriptions[client_id] = []
            
            # IMPORTANT: Log qui doit apparaître dans Docker
            logger.info(f"✅ Client {client_id} connecté au dashboard")
            print(f"[WEBSOCKET] Client connecté: {client_id}")  # Debug print
            
            # Envoi des données initiales
            emit('connected', {
                'status': 'connected',
                'client_id': client_id,
                'timestamp': datetime.now().isoformat(),
                'available_channels': list(self.rooms.keys())
            })
            
        @self.socketio.on('disconnect')
        def handle_disconnect():
            client_id = self.get_client_id()
            self.connected_clients.discard(client_id)
            
            # Nettoyage des abonnements
            if client_id in self.client_subscriptions:
                for room in self.client_subscriptions[client_id]:
                    leave_room(room)
                del self.client_subscriptions[client_id]
                
            logger.info(f"❌ Client {client_id} déconnecté du dashboard")
            print(f"[WEBSOCKET] Client déconnecté: {client_id}")
            
        @self.socketio.on('subscribe')
        def handle_subscribe(data):
            """Abonnement à un canal de données"""
            client_id = self.get_client_id()
            channels = data.get('channels', [])
            
            logger.info(f"📊 Client {client_id} s'abonne à: {channels}")
            
            for channel in channels:
                if channel in self.rooms:
                    room_name = self.rooms[channel]
                    join_room(room_name)
                    
                    if client_id not in self.client_subscriptions:
                        self.client_subscriptions[client_id] = []
                    self.client_subscriptions[client_id].append(room_name)
                    
            emit('subscription_confirmed', {
                'subscribed_channels': channels,
                'timestamp': datetime.now().isoformat()
            })
            
        @self.socketio.on('unsubscribe')
        def handle_unsubscribe(data):
            """Désabonnement d'un canal"""
            client_id = self.get_client_id()
            channels = data.get('channels', [])
            
            logger.info(f"🔄 Client {client_id} se désabonne de: {channels}")
            
            for channel in channels:
                if channel in self.rooms:
                    room_name = self.rooms[channel]
                    leave_room(room_name)
                    
                    if client_id in self.client_subscriptions:
                        if room_name in self.client_subscriptions[client_id]:
                            self.client_subscriptions[client_id].remove(room_name)
                            
            emit('unsubscription_confirmed', {
                'unsubscribed_channels': channels
            })
            
        @self.socketio.on('get_live_stats')
        def handle_get_live_stats():
            """Statistiques en temps réel"""
            stats = self.get_connection_stats()
            logger.info(f"📈 Statistiques demandées: {stats}")
            emit('live_stats', stats)

    def get_client_id(self):
        """Génération d'un ID client unique"""
        from flask import request
        return request.sid
        
    def get_connection_stats(self) -> Dict:
        """Statistiques des connexions"""
        stats = {
            'connected_clients': len(self.connected_clients),
            'total_subscriptions': sum(len(subs) for subs in self.client_subscriptions.values()),
            'active_rooms': list(self.rooms.values()),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.debug(f"Stats générées: {stats}")
        return stats
        
        
    # =============================================================================
    # Méthodes de diffusion pour intégration avec vos collectors
    # =============================================================================
    
    def broadcast_threat_update(self, threat_data: Dict):
        """Diffusion mise à jour menace"""
        try:
            formatted_data = {
                'type': 'threat_update',
                'data': threat_data,
                'timestamp': datetime.now().isoformat(),
                'source': threat_data.get('source', 'unknown')
            }
            
            self.socketio.emit('threat_update', formatted_data, room=self.rooms['threats'])
            
            # Log visible dans Docker
            indicator = threat_data.get('indicator', 'N/A')
            logger.info(f"🎯 Diffusion threat_update: {indicator}")
            print(f"[BROADCAST] Threat update: {indicator}")
            
        except Exception as e:
            logger.error(f"❌ Erreur diffusion threat_update: {e}")
            print(f"[ERROR] Broadcast threat error: {e}")
            
    def broadcast_new_alert(self, alert_data: Dict):
        """Diffusion nouvelle alerte"""
        try:
            formatted_alert = {
                'type': 'new_alert',
                'alert': alert_data,
                'timestamp': datetime.now().isoformat(),
                'priority': alert_data.get('level', 'medium')
            }
            
            self.socketio.emit('new_alert', formatted_alert, room=self.rooms['alerts'])
            
            # Log visible dans Docker
            title = alert_data.get('title', 'N/A')
            level = alert_data.get('level', 'unknown')
            logger.info(f"🚨 Diffusion alerte {level}: {title}")
            print(f"[ALERT] New alert ({level}): {title}")
            
        except Exception as e:
            logger.error(f"❌ Erreur diffusion alert: {e}")
            print(f"[ERROR] Alert broadcast error: {e}")
            
    def broadcast_ioc_update(self, ioc_data: Dict):
        """Diffusion mise à jour IOC"""
        try:
            formatted_ioc = {
                'type': 'ioc_update', 
                'ioc': ioc_data,
                'timestamp': datetime.now().isoformat(),
                'risk_score': ioc_data.get('risk_score', 0)
            }
            
            self.socketio.emit('ioc_update', formatted_ioc, room=self.rooms['iocs'])
            logger.debug(f"Diffusion IOC: {ioc_data.get('value', 'N/A')}")
            
        except Exception as e:
            logger.error(f"Erreur diffusion IOC: {e}")
            
    def broadcast_campaign_update(self, campaign_data: Dict):
        """Diffusion mise à jour campagne"""
        try:
            formatted_campaign = {
                'type': 'campaign_update',
                'campaign': campaign_data,
                'timestamp': datetime.now().isoformat(),
                'threat_actor': campaign_data.get('threat_actor', 'unknown')
            }
            
            self.socketio.emit('campaign_update', formatted_campaign, room=self.rooms['campaigns'])
            logger.info(f"Diffusion campagne: {campaign_data.get('name', 'N/A')}")
            
        except Exception as e:
            logger.error(f"Erreur diffusion campagne: {e}")
            
    def broadcast_mitre_update(self, mitre_data: Dict):
        """Diffusion mise à jour MITRE ATT&CK"""
        try:
            formatted_mitre = {
                'type': 'mitre_update',
                'technique': mitre_data,
                'timestamp': datetime.now().isoformat(),
                'tactic': mitre_data.get('tactic', 'unknown')
            }
            
            self.socketio.emit('mitre_update', formatted_mitre, room=self.rooms['mitre'])
            logger.debug(f"Diffusion MITRE: {mitre_data.get('technique_id', 'N/A')}")
            
        except Exception as e:
            logger.error(f"Erreur diffusion MITRE: {e}")
    
            
    def broadcast_system_notification(self, notification: Dict):
        """Notification système générale"""
        try:
            formatted_notification = {
                'type': 'system_notification',
                'message': notification,
                'timestamp': datetime.now().isoformat(),
                'level': notification.get('level', 'info')
            }
            
            # Diffusion à tous les clients connectés
            self.socketio.emit('system_notification', formatted_notification)
            
            # Log système visible dans Docker
            message = notification.get('message', 'N/A')
            logger.info(f"💡 Notification système: {message}")
            print(f"[SYSTEM] {message}")
            
        except Exception as e:
            logger.error(f"❌ Erreur notification système: {e}")
            print(f"[ERROR] System notification error: {e}")

# Instance globale pour utilisation dans app.py
websocket_handler = None

def init_websocket_handler(socketio):
    """Initialisation du gestionnaire WebSocket"""
    global websocket_handler
    
    logger.info("🔧 Initialisation WebSocket Handler...")
    print("[INIT] Initializing WebSocket Handler")
    
    websocket_handler = WebSocketHandler(socketio)
    
    logger.info("✅ WebSocket Handler initialisé avec succès")
    print("[INIT] WebSocket Handler ready")
    
    return websocket_handler

# Fonctions d'utilisation pour vos collectors existants
def emit_threat_update(threat_data: Dict):
    """Interface pour vos collectors - Mise à jour menace"""
    if websocket_handler:
        websocket_handler.broadcast_threat_update(threat_data)
    else:
        logger.warning("⚠️ WebSocket handler non initialisé pour threat_update")
        print("[WARNING] WebSocket handler not initialized")


def emit_new_alert(alert_data: Dict):
    """Interface pour vos collectors - Nouvelle alerte"""
    if websocket_handler:
        websocket_handler.broadcast_new_alert(alert_data)
    else:
        logger.warning("⚠️ WebSocket handler non initialisé pour alert")
        print("[WARNING] WebSocket handler not initialized")

def emit_ioc_update(ioc_data: Dict):
    """Interface pour vos collectors - Mise à jour IOC"""
    if websocket_handler:
        websocket_handler.broadcast_ioc_update(ioc_data)

def emit_campaign_update(campaign_data: Dict):
    """Interface pour vos collectors - Mise à jour campagne"""
    if websocket_handler:
        websocket_handler.broadcast_campaign_update(campaign_data)

def emit_mitre_update(mitre_data: Dict):
    """Interface pour vos collectors - Mise à jour MITRE"""
    if websocket_handler:
        websocket_handler.broadcast_mitre_update(mitre_data)

def emit_system_notification(message: str, level: str = 'info'):
    """Interface pour notifications système"""
    if websocket_handler:
        websocket_handler.broadcast_system_notification({
            'message': message,
            'level': level
        })
    else:
        logger.warning(f"⚠️ WebSocket handler non initialisé pour notification: {message}")
        print(f"[WARNING] Cannot send notification: {message}")

# Test de logging au chargement du module
logger.info("📦 Module WebSocket Handler chargé")
print("[MODULE] WebSocket Handler module loaded")