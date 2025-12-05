#!/usr/bin/env python3
"""
Serveur WebSocket standalone pour le dashboard CTI
Point d'entrée pour le service cti-websocket
"""

import os
import sys
import logging
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS

# Configuration du chemin Python
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

# Import du gestionnaire WebSocket
from dashboard.backend.websocket_handler import init_websocket_handler

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/websocket.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def create_websocket_app():
    """Création de l'application WebSocket"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'cti-websocket-secret-key-2025'
    
    # Configuration CORS
    CORS(app, origins="*")
    
    # Initialisation SocketIO
    socketio = SocketIO(
        app, 
        cors_allowed_origins="*", 
        async_mode='threading',
        logger=True,
        engineio_logger=True
    )
    
    # Initialisation du gestionnaire WebSocket
    websocket_handler = init_websocket_handler(socketio)
    
    @app.route('/health')
    def health_check():
        """Point de contrôle santé"""
        return {
            'status': 'healthy',
            'service': 'cti-websocket',
            'connected_clients': len(websocket_handler.connected_clients)
        }
    
    @app.route('/stats')
    def websocket_stats():
        """Statistiques WebSocket"""
        return websocket_handler.get_connection_stats()
    
    logger.info("✅ Application WebSocket créée")
    return app, socketio

def main():
    """Point d'entrée principal"""
    try:
        logger.info("🚀 Démarrage du serveur WebSocket CTI...")
        
        # Vérification des répertoires
        os.makedirs('/app/logs', exist_ok=True)
        
        # Création de l'application
        app, socketio = create_websocket_app()
        
        # Variables d'environnement
        host = os.getenv('WEBSOCKET_HOST', '0.0.0.0')
        port = int(os.getenv('WEBSOCKET_PORT', 5002))
        debug = os.getenv('FLASK_ENV', 'production') == 'development'
        
        logger.info(f"🌐 WebSocket Server démarré sur {host}:{port}")
        
        # Démarrage du serveur
        socketio.run(
            app,
            host=host,
            port=port,
            debug=debug,
            allow_unsafe_werkzeug=True
        )
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du démarrage WebSocket: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()