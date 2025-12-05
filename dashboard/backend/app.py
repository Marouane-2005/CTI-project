"""
Application Flask principale pour le dashboard CTI
Version corrigée avec résolution des problèmes de routage
"""

from flask import Flask, jsonify, request, render_template, send_from_directory, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import JWTManager
from auth import auth_bp
from auth.routes import check_if_token_revoked
from config.auth_config import AuthConfig
from flask_cors import CORS
from datetime import datetime, timedelta
import sys
import traceback
import os
import json
import threading
import logging
import hashlib
import time

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import de vos modules existants avec gestion d'erreur
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

# ✅ Imports avec gestion d'erreur
CORE_MODULES_AVAILABLE = False
DASHBOARD_MODULES_AVAILABLE = False

# Import ReportGenerator avec vérification des dépendances
ReportGenerator = None
try:
    # ✅ VERIFICATION: Tester ReportLab d'abord
    import reportlab
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate
    logger.info(f"✅ ReportLab disponible: {reportlab.Version}")
    
    # ✅ VERIFICATION: Tester Jinja2
    import jinja2
    logger.info(f"✅ Jinja2 disponible: {jinja2.__version__}")
    
    # ✅ Import du module seulement si les dépendances sont OK
    from report_generator import ReportGenerator
    logger.info("✅ ReportGenerator module importé avec succès")
    
except ImportError as e:
    logger.error(f"❌ Dépendances manquantes: {e}")
    ReportGenerator = None
except Exception as e:
    logger.error(f"❌ Erreur import ReportGenerator: {e}")
    ReportGenerator = None


try:
    from scripts.utils.database import DatabaseManager
    from scripts.utils.opencti_helper import OpenCTIHelper
    from scripts.analyzers.risk_calculator import RiskCalculator
    from scripts.analyzers.ioc_enricher import IOCEnricher
    CORE_MODULES_AVAILABLE = True
    print("✅ Modules core importés avec succès")
except ImportError as e:
    print(f"⚠️ Modules core non disponibles: {e}")
    # Définir des classes mock
    class DatabaseManager:
        def __init__(self):
            self.db_connection = True
        def acknowledge_alert(self, alert_id, user_id):
            pass
    
    class OpenCTIHelper:
        def __init__(self, config):
            # Gestion flexible de la configuration
            if 'opencti' in config:
                self.base_url = config['opencti'].get('url', 'http://localhost:8080')
                self.token = config['opencti'].get('token', '')
                self.ssl_verify = config['opencti'].get('ssl_verify', False)
            else:
                # Configuration par défaut si pas de structure opencti
                self.base_url = config.get('url', 'http://localhost:8080')
                self.token = config.get('token', '')
                self.ssl_verify = config.get('ssl_verify', False)
            print(f"Mock OpenCTIHelper configuré: {self.base_url}")
    
    class RiskCalculator:
        def calculate_risk(self, indicator_data):
            return 5.0
    
    class IOCEnricher:
        def __init__(self):
            pass

# Import des modules dashboard avec gestion des dépendances manquantes
try:
    # Vérifier si asyncpg est disponible
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    print("⚠️ asyncpg non disponible, utilisation du mode synchrone")
    ASYNCPG_AVAILABLE = False

try:
    from data_processor import DashboardDataProcessor
    from alert_engine import AlertEngine
    from websocket_handler import init_websocket_handler
    DASHBOARD_MODULES_AVAILABLE = True
    print("✅ Modules dashboard importés avec succès")
except ImportError as e:
    print(f"⚠️ Modules dashboard non disponibles: {e}")
    print("🔄 Utilisation des classes mock pour le développement")
    
    # Classes mock pour le développement
    class DashboardDataProcessor:
        def __init__(self):
            self.db_connection = True
            
        def get_dashboard_overview(self):
            return {
                'status': 'active',
                'total_indicators': 1250,
                'active_alerts': 5,
                'threat_level': 'medium',
                'last_update': datetime.now().isoformat()
            }
            
        def get_live_threats(self, hours=1):
            return {
                'threats': [
                    {
                        'id': 'threat_001',
                        'type': 'ip-addr',
                        'value': '192.168.1.100',
                        'risk_score': 8.5,
                        'timestamp': datetime.now().isoformat()
                    }
                ],
                'total': 1
            }
            
        def search_indicators(self, params):
            return {'indicators': [], 'total': 0}
            
        def get_alerts_data(self, acknowledged=None):
            return {
                'alerts': [
                    {
                        'id': 'alert_001',
                        'title': 'IOC à risque critique détecté',
                        'level': 'critical',
                        'description': 'Indicateur malveillant détecté',
                        'timestamp': datetime.now().isoformat(),
                        'acknowledged': False,
                        'source': 'threat_intel'
                    }
                ],
                'total': 1
            }
            
        def insert_alert(self, alert):
            pass
    
    class AlertEngine:
        def process_indicator(self, data):
            return [{
                'id': f'alert_{int(datetime.now().timestamp())}',
                'level': 'high',
                'title': 'Test Alert',
                'description': 'Alert generated from indicator',
                'timestamp': datetime.now().isoformat(),
                'acknowledged': False,
                'source': 'alert_engine'
            }]
    
    def init_websocket_handler(socketio):
        class MockWebSocketHandler:
            def __init__(self):
                self.connected_clients = []
                self.socketio = socketio
            def broadcast_ioc_update(self, data): 
                print(f"📡 Broadcasting IOC update: {data}")
            def broadcast_new_alert(self, data): 
                print(f"🚨 Broadcasting new alert: {data}")
            def broadcast_system_notification(self, data): 
                print(f"📢 Broadcasting notification: {data}")
        return MockWebSocketHandler()

# Configuration Flask
# ✅ CORRECTION: Configuration Flask avec gestion d'erreur améliorée
data_processor = None
report_generator = None

try:
    # Créer data_processor
    from data_processor import DashboardDataProcessor
    data_processor = DashboardDataProcessor()
    logger.info("✅ DashboardDataProcessor créé")
    
    # Créer report_generator seulement si ReportGenerator est disponible
    if ReportGenerator is not None:
        try:
            report_generator = ReportGenerator(data_processor)
            logger.info("✅ ReportGenerator instance créée avec succès")
        except Exception as rg_error:
            logger.error(f"❌ Erreur création ReportGenerator: {rg_error}")
            report_generator = None
    else:
        logger.warning("⚠️ ReportGenerator non disponible - dépendances manquantes")
        report_generator = None
        
except Exception as e:
    logger.error(f"❌ Erreur création instances: {e}")
    # Créer au minimum data_processor
    if data_processor is None:
        try:
            from data_processor import DashboardDataProcessor
            data_processor = DashboardDataProcessor()
        except:
            data_processor = DashboardDataProcessor()  # Version mock
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = AuthConfig.JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = AuthConfig.JWT_ACCESS_TOKEN_EXPIRES
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = AuthConfig.JWT_REFRESH_TOKEN_EXPIRES
app.config['JWT_ALGORITHM'] = AuthConfig.JWT_ALGORITHM
    
    # Initialiser JWT
jwt = JWTManager(app)
    
    # Configurer la vérification des tokens révoqués
jwt.token_in_blocklist_loader(check_if_token_revoked)
    
    # CORS pour permettre les requêtes du frontend
CORS(app, origins=["http://localhost:8080", "http://localhost:3000"])
    
    # Enregistrer le blueprint d'authentification
app.register_blueprint(auth_bp)
    
# CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:8080", "http://localhost:3000", "http://localhost:8081", 
                   "http://localhost:8083", "http://localhost:8084"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# SocketIO avec configuration CORS
socketio = SocketIO(
    app, 
    cors_allowed_origins=["http://localhost:8083", "http://localhost:8084", 
                         "http://localhost:3000", "http://localhost:8081"],
    async_mode='threading',
    logger=True,
    engineio_logger=True
)

# Instances globales
try:
    db = DatabaseManager()
    print("✅ DatabaseManager initialisé")
except Exception as e:
    print(f"⚠️ Erreur DatabaseManager: {e}")
    db = DatabaseManager()  # Utiliser la version mock

try:
    # Configuration corrigée pour OpenCTI - structure attendue par votre classe
    opencti_config = {
        'opencti': {
            'url': os.getenv('OPENCTI_URL', 'http://localhost:8080'),
            'token': os.getenv('OPENCTI_TOKEN', ''),
            'ssl_verify': os.getenv('OPENCTI_SSL_VERIFY', 'false').lower() == 'true'
        }
    }
    opencti_helper = OpenCTIHelper(opencti_config)
    print("✅ OpenCTIHelper initialisé")
except Exception as e:
    print(f"⚠️ Erreur OpenCTIHelper: {e}")
    # Configuration mock avec la bonne structure
    opencti_helper = None
    print("🔄 OpenCTIHelper désactivé, fonctionnement en mode dégradé")

try:
    risk_calc = RiskCalculator()
    print("✅ RiskCalculator initialisé")
except Exception as e:
    print(f"⚠️ Erreur RiskCalculator: {e}")
    risk_calc = RiskCalculator()

try:
    ioc_enricher = IOCEnricher()
    print("✅ IOCEnricher initialisé")
except Exception as e:
    print(f"⚠️ Erreur IOCEnricher: {e}")
    ioc_enricher = IOCEnricher()


# Instances dashboard
data_processor = DashboardDataProcessor()
alert_engine = AlertEngine()

# Initialisation WebSocket
try:
    websocket_handler = init_websocket_handler(socketio)
    if not hasattr(websocket_handler, 'connected_clients'):
        websocket_handler.connected_clients = []
except Exception as e:
    logger.error(f"Erreur websocket_handler: {e}")
    class MockWebSocketHandler:
        def __init__(self):
            self.connected_clients = []
        def broadcast_ioc_update(self, data): pass
        def broadcast_new_alert(self, data): pass
        def broadcast_system_notification(self, data): pass
    websocket_handler = MockWebSocketHandler()

# Middleware pour logging des requêtes
@app.before_request
def log_request_info():
    logger.info(f"🌐 {request.method} {request.url}")

@app.after_request
def log_response_info(response):
    logger.info(f"✅ Response: {response.status_code}")
    return response

# Gestion d'erreur globale
@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"❌ Erreur: {str(e)}")
    logger.error(traceback.format_exc())
    return jsonify({
        'error': str(e),
        'type': type(e).__name__
    }), 500

# =============================================================================
# Routes principales
# =============================================================================

@app.route('/', methods=['GET'])
def home():
    """Page d'accueil du dashboard"""
    return jsonify({
        'message': 'CTI Dashboard API',
        'version': '1.0.0',
        'status': 'running',
        'timestamp': datetime.now().isoformat(),
        'available_endpoints': [
            '/api/test',
            '/api/dashboard/overview',
            '/api/dashboard/threats/live',
            '/api/dashboard/alerts'
        ]
    })

# ROUTE DE TEST CORRIGÉE
@app.route('/api/test', methods=['GET', 'OPTIONS'])
def api_test():
    """Route de test pour vérifier la connectivité"""
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "*")
        response.headers.add('Access-Control-Allow-Methods', "*")
        return response
    
    try:
        return jsonify({
            'status': 'OK',
            'message': 'CTI Dashboard API Backend fonctionnel',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'modules_available': {
                'database': data_processor.db_connection if hasattr(data_processor, 'db_connection') else True,
                'websocket': websocket_handler is not None,
                'alert_engine': alert_engine is not None,
                'core_modules': CORE_MODULES_AVAILABLE,
                'dashboard_modules': DASHBOARD_MODULES_AVAILABLE
            },
            'server_info': {
                'python_version': sys.version,
                'flask_running': True,
                'cors_enabled': True
            }
        })
    except Exception as e:
        logger.error(f"Erreur api_test: {e}")
        return jsonify({
            'status': 'ERROR',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/dashboard/overview', methods=['GET'])
def get_dashboard_overview():
    """Vue d'ensemble du dashboard"""
    try:
        overview = data_processor.get_dashboard_overview()
        return jsonify(overview)
    except Exception as e:
        logger.error(f"Erreur get_dashboard_overview: {e}")
        return jsonify({'error': 'Erreur lors du chargement des données'}), 500

@app.route('/api/dashboard/threats/live', methods=['GET'])
def get_live_threats():
    """Menaces en temps réel"""
    try:
        hours = int(request.args.get('hours', 1))
        live_threats = data_processor.get_live_threats(hours=hours)
        return jsonify(live_threats)
    except Exception as e:
        logger.error(f"Erreur get_live_threats: {e}")
        return jsonify({'error': 'Erreur lors du chargement des menaces'}), 500

@app.route('/api/dashboard/alerts', methods=['GET'])
def get_alerts():
    """Récupération des alertes"""
    try:
        acknowledged = request.args.get('acknowledged')
        if acknowledged is not None:
            acknowledged = acknowledged.lower() == 'true'
        
        alerts_data = data_processor.get_alerts_data(acknowledged)
        return jsonify(alerts_data)
    except Exception as e:
        logger.error(f"Erreur get_alerts: {e}")
        return jsonify({
            'alerts': [],
            'total': 0,
            'status': 'error',
            'error': str(e)
        })

@app.route('/api/dashboard/alerts', methods=['POST'])
def create_alert():
    """Créer une nouvelle alerte via POST"""
    try:
        alert_data = request.get_json()
        
        if not alert_data:
            return jsonify({'error': 'Aucune donnée fournie'}), 400
        
        # Valider les champs requis
        required_fields = ['title', 'level', 'description']
        for field in required_fields:
            if field not in alert_data:
                return jsonify({'error': f'Champ requis manquant: {field}'}), 400
        
        # Compléter l'alerte avec des valeurs par défaut
        alert = {
            'id': alert_data.get('id', f'alert_{int(datetime.now().timestamp())}'),
            'title': alert_data['title'],
            'level': alert_data['level'],
            'description': alert_data['description'],
            'timestamp': alert_data.get('timestamp', datetime.now().isoformat()),
            'acknowledged': alert_data.get('acknowledged', False),
            'source': alert_data.get('source', 'api_direct'),
            'indicator_data': alert_data.get('indicator_data', {}),
            'mitre_data': alert_data.get('mitre_data', {}),
            'detection_method': alert_data.get('detection_method', 'manual')
        }
        
        # ✅ CORRECTION : Utiliser try-except pour l'insertion
        try:
            success = data_processor.insert_alert(alert)
        except Exception as insert_error:
            logger.error(f"Erreur insertion alerte: {insert_error}")
            success = False
        
        if success:
            # Notification WebSocket (avec protection)
            try:
                if websocket_handler and hasattr(websocket_handler, 'broadcast_new_alert'):
                    websocket_handler.broadcast_new_alert(alert)
            except Exception as ws_error:
                logger.warning(f"Erreur WebSocket: {ws_error}")
            
            return jsonify({
                'status': 'success',
                'message': 'Alerte créée avec succès',
                'alert': alert
            }), 201
        else:
            return jsonify({
                'status': 'error', 
                'message': 'Erreur lors de la création de l\'alerte'
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur create_alert: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500



@app.route('/api/dashboard/alerts/detailed', methods=['GET'])
def get_detailed_alerts():
    """Récupère les alertes avec détails complets pour le dashboard"""
    try:
        hours = int(request.args.get('hours', 24))
        include_acknowledged = request.args.get('acknowledged', 'true').lower() == 'true'
        
        detailed_alerts = data_processor.get_detailed_alerts_for_report(hours=hours)
        
        # Filtrer selon les paramètres
        alerts = detailed_alerts.get('alerts', [])
        if not include_acknowledged:
            alerts = [a for a in alerts if not a.get('acknowledged', False)]
        
        return jsonify({
            'alerts': alerts,
            'total': len(alerts),
            'detailed': True,
            'filters': {
                'hours': hours,
                'include_acknowledged': include_acknowledged
            }
        })
        
    except Exception as e:
        logger.error(f"Erreur get_detailed_alerts: {e}")
        return jsonify({
            'alerts': [],
            'total': 0,
            'error': str(e)
        }), 500
@app.route('/api/dashboard/alerts/create', methods=['POST'])
def create_alert_alternative():
    """Route alternative pour créer une alerte (endpoint dédié)"""
    return create_alert()

@app.route('/api/dashboard/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Marquer une alerte comme acquittée"""
    try:
        data = request.get_json() or {}
        user_id = data.get('user_id', 'dashboard-user')
        
        # Utiliser votre DatabaseManager existant
        if hasattr(db, 'acknowledge_alert'):
            success = db.acknowledge_alert(alert_id, user_id)
        else:
            # Fallback si la méthode n'existe pas
            success = True
            logger.info(f"[MOCK] Alerte {alert_id} acquittée par {user_id}")
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Alerte acquittée',
                'alert_id': alert_id,
                'acknowledged_by': user_id,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Erreur lors de l\'acquittement'
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur acknowledge_alert: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/alerts/bulk', methods=['POST'])
def create_bulk_alerts():
    """Créer plusieurs alertes en une fois"""
    try:
        data = request.get_json()
        alerts_data = data.get('alerts', [])
        
        if not alerts_data:
            return jsonify({'error': 'Aucune alerte fournie'}), 400
        
        created_alerts = []
        failed_alerts = []
        
        for alert_data in alerts_data:
            try:
                # Compléter l'alerte
                alert = {
                    'id': alert_data.get('id', f'alert_{int(datetime.now().timestamp())}_{len(created_alerts)}'),
                    'title': alert_data['title'],
                    'level': alert_data['level'], 
                    'description': alert_data['description'],
                    'timestamp': alert_data.get('timestamp', datetime.now().isoformat()),
                    'acknowledged': alert_data.get('acknowledged', False),
                    'source': alert_data.get('source', 'api_bulk'),
                    'indicator_data': alert_data.get('indicator_data', {}),
                    'mitre_data': alert_data.get('mitre_data', {}),
                    'detection_method': alert_data.get('detection_method', 'bulk_import')
                }
                
                success = data_processor.insert_alert(alert)
                
                if success:
                    created_alerts.append(alert)
                    
                    # Notification WebSocket
                    try:
                        if websocket_handler and hasattr(websocket_handler, 'broadcast_new_alert'):
                            websocket_handler.broadcast_new_alert(alert)
                    except Exception:
                        pass  # Ignorer les erreurs WebSocket
                else:
                    failed_alerts.append(alert_data)
                    
            except Exception as e:
                logger.error(f"Erreur création alerte individuelle: {e}")
                failed_alerts.append(alert_data)
        
        return jsonify({
            'status': 'completed',
            'created': len(created_alerts),
            'failed': len(failed_alerts),
            'alerts_created': created_alerts,
            'errors': failed_alerts if failed_alerts else None
        })
        
    except Exception as e:
        logger.error(f"Erreur create_bulk_alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/alerts/count', methods=['GET'])
def get_alerts_count():
    """Obtenir le nombre d'alertes par statut"""
    try:
        # Vous devrez implémenter cette méthode dans DashboardDataProcessor
        if hasattr(data_processor, 'get_alerts_count'):
            counts = data_processor.get_alerts_count()
        else:
            # Mock data
            counts = {
                'total': 21,
                'acknowledged': 1,
                'unacknowledged': 20,
                'by_level': {
                    'critical': 5,
                    'high': 8,
                    'medium': 6,
                    'low': 2
                }
            }
        
        return jsonify(counts)
        
    except Exception as e:
        logger.error(f"Erreur get_alerts_count: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/alerts/recent', methods=['GET'])
def get_recent_alerts():
    """Obtenir les alertes récentes avec pagination"""
    try:
        limit = int(request.args.get('limit', 10))
        offset = int(request.args.get('offset', 0))
        level_filter = request.args.get('level')  # critical, high, medium, low
        
        # Vous devrez implémenter cette méthode dans DashboardDataProcessor
        if hasattr(data_processor, 'get_recent_alerts'):
            alerts = data_processor.get_recent_alerts(limit=limit, offset=offset, level=level_filter)
        else:
            # Utiliser les données existantes
            all_alerts = data_processor.get_alerts_data()
            alerts = all_alerts.get('alerts', [])[:limit]
        
        return jsonify({
            'alerts': alerts,
            'limit': limit,
            'offset': offset,
            'has_more': len(alerts) == limit
        })
        
    except Exception as e:
        logger.error(f"Erreur get_recent_alerts: {e}")
        return jsonify({'error': str(e), 'alerts': []})


@app.route('/api/test/create-sample-iocs', methods=['POST'])
def create_sample_iocs():
    """Route de test pour créer des IOCs d'exemple"""
    try:
        sample_iocs = [
            {
                'id': f'ioc_test_{int(datetime.now().timestamp())}_1',
                'value': '192.168.1.100',
                'type': 'ip',
                'source': 'threat_intel',
                'risk_score': 8.5,
                'created_at': datetime.now().isoformat(),
                'mitre_techniques': ['T1055', 'T1071'],
                'enrichments': {
                    'geolocation': {'country': 'CN'},
                    'reputation': 'malicious'
                },
                'confidence_level': 85
            },
            {
                'id': f'ioc_test_{int(datetime.now().timestamp())}_2',
                'value': 'malicious-domain.com',
                'type': 'domain',
                'source': 'osint_feed',
                'risk_score': 7.2,
                'created_at': datetime.now().isoformat(),
                'mitre_techniques': ['T1071'],
                'enrichments': {
                    'dns_records': ['A', 'MX'],
                    'reputation': 'suspicious'
                },
                'confidence_level': 75
            },
            {
                'id': f'ioc_test_{int(datetime.now().timestamp())}_3',
                'value': 'a1b2c3d4e5f67890abcdef123456789012345678',
                'type': 'hash',
                'source': 'malware_analysis',
                'risk_score': 9.1,
                'created_at': datetime.now().isoformat(),
                'mitre_techniques': ['T1204', 'T1055'],
                'enrichments': {
                    'file_type': 'PE32',
                    'malware_family': 'Trojan.Generic'
                },
                'confidence_level': 95
            }
        ]
        
        created_count = 0
        for ioc in sample_iocs:
            success = data_processor.insert_ioc(ioc)
            if success:
                created_count += 1
                
                # Notification WebSocket
                if websocket_handler:
                    websocket_handler.broadcast_ioc_update(ioc)
        
        return jsonify({
            'status': 'success',
            'message': f'{created_count} IOCs créés avec succès',
            'created_count': created_count,
            'total_requested': len(sample_iocs),
            'iocs': sample_iocs
        })
        
    except Exception as e:
        logger.error(f"Erreur create_sample_iocs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/dashboard/alerts/test', methods=['POST'])
def create_test_alert():
    """Route pour créer des alertes de test"""
    try:
        test_alert = {
            'id': f'test_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            'level': 'high',
            'title': 'Test Alert - IP Malveillante',
            'description': 'Alerte générée pour test du système',
            'timestamp': datetime.now().isoformat(),
            'acknowledged': False,
            'source': 'test_generator'
        }
        
        data_processor.insert_alert(test_alert)
        
        if websocket_handler:
            websocket_handler.broadcast_new_alert(test_alert)
        
        return jsonify({'status': 'success', 'alert': test_alert})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/test/create-alerts', methods=['POST'])
def create_sample_alerts():
    """Route de test pour générer des alertes"""
    try:
        alerts = []
        for i in range(3):
            alert = {
                'id': f'test_alert_{i}_{int(datetime.now().timestamp())}',
                'level': ['critical', 'high', 'medium'][i],
                'title': f'Test Alert #{i+1}',
                'description': f'Alerte de test numéro {i+1}',
                'timestamp': datetime.now().isoformat(),
                'acknowledged': False,
                'source': 'test_generator'
            }
            alerts.append(alert)
            
            data_processor.insert_alert(alert)
            
            if websocket_handler:
                websocket_handler.broadcast_new_alert(alert)
        
        return jsonify({'created_alerts': len(alerts), 'alerts': alerts})
    except Exception as e:
        logger.error(f"Erreur create_sample_alerts: {e}")
        return jsonify({'error': str(e)}), 500

# Routes de fallback avec données mock
@app.route('/api/dashboard/mitre/heatmap', methods=['GET'])
def get_mitre_heatmap():
    try:
        days = int(request.args.get('days', 30))
        return jsonify({
            'heatmap': [
                {
                    'technique_id': 'T1566',
                    'name': 'Phishing', 
                    'tactic': 'Initial Access',
                    'count': 5,
                    'frequency': 8
                }
            ],
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/metrics/timeline', methods=['GET'])
def get_metrics_timeline():
    try:
        days = int(request.args.get('days', 7))
        return jsonify({
            'timeline': [
                {
                    'date': (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d'),
                    'threats': 10 + i,
                    'alerts': 3 + (i % 3)
                } for i in range(days)
            ],
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Erreur get_metrics_timeline: {e}")
        return jsonify({'error': str(e), 'timeline': []}), 200

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    try:
        stats = {
            'connected_clients': len(getattr(websocket_handler, 'connected_clients', [])),
            'active_alerts': 0,
            'total_indicators': 0, 
            'data_sources': 0,
            'last_update': datetime.now().isoformat(),
            'uptime_hours': 1.0
        }
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Erreur get_dashboard_stats: {e}")
        return jsonify({'error': str(e)}), 500

# Route pour simuler une attaque


@app.route('/api/dashboard/iocs/recent', methods=['GET'])
def get_recent_iocs():
    """Récupère les IOCs récents avec filtres"""
    try:
        hours = int(request.args.get('hours', 24))
        ioc_type = request.args.get('type', 'all')
        risk_level = request.args.get('risk_level', 'all')
        
        # Utiliser data_processor pour récupérer les IOCs
        if hasattr(data_processor, 'get_recent_iocs'):
            iocs_data = data_processor.get_recent_iocs(hours, ioc_type, risk_level)
        else:
            # Fallback avec des données mock
            iocs_data = {
                'iocs': [
                    {
                        'id': 'ioc_001',
                        'value': '192.168.1.100',
                        'type': 'ip',
                        'source': 'threat_intel',
                        'risk_score': 8.5,
                        'created_at': datetime.now().isoformat(),
                        'mitre_techniques': ['T1055', 'T1071'],
                        'enrichments': {
                            'geolocation': {'country': 'CN'},
                            'reputation': 'malicious'
                        },
                        'confidence_level': 85
                    },
                    {
                        'id': 'ioc_002', 
                        'value': 'malicious-domain.com',
                        'type': 'domain',
                        'source': 'osint_feed',
                        'risk_score': 7.2,
                        'created_at': (datetime.now() - timedelta(hours=2)).isoformat(),
                        'mitre_techniques': ['T1071'],
                        'enrichments': {
                            'dns_records': ['A', 'MX'],
                            'reputation': 'suspicious'
                        },
                        'confidence_level': 75
                    }
                ],
                'total': 2,
                'status': 'mock_data'
            }
        
        return jsonify(iocs_data)
        
    except Exception as e:
        logger.error(f"Erreur get_recent_iocs: {e}")
        return jsonify({
            'iocs': [],
            'total': 0,
            'error': str(e)
        })

def _get_mock_iocs(self):
    """Données IOCs pour test/développement"""
    return {
        'iocs': [
            {
                'id': 'ioc_001',
                'value': '192.168.1.100',
                'type': 'ip',
                'source': 'threat_intel',
                'risk_score': 8.5,
                'created_at': datetime.now().isoformat(),
                'mitre_techniques': ['T1055', 'T1071'],
                'enrichments': {
                    'geolocation': {'country': 'CN'},
                    'reputation': 'malicious'
                },
                'confidence_level': 85
            },
            {
                'id': 'ioc_002', 
                'value': 'malicious-domain.com',
                'type': 'domain',
                'source': 'osint_feed',
                'risk_score': 7.2,
                'created_at': (datetime.now() - timedelta(hours=2)).isoformat(),
                'mitre_techniques': ['T1071'],
                'enrichments': {
                    'dns_records': ['A', 'MX'],
                    'reputation': 'suspicious'
                },
                'confidence_level': 75
            }
        ],
        'total': 2,
        'status': 'mock_data'
    }    

def search_iocs(self, search_params):
    """Recherche d'IOCs avec paramètres avancés"""
    try:
        if not self.db_connection:
            return {'iocs': [], 'total': 0}
            
        with self.db_connection.cursor(cursor_factory=RealDictCursor) as cursor:
            query = "SELECT * FROM indicators WHERE 1=1"
            params = []
            
            # Filtres de recherche
            if search_params.get('search_term'):
                query += " AND (value ILIKE %s OR source ILIKE %s)"
                term = f"%{search_params['search_term']}%"
                params.extend([term, term])
            
            if search_params.get('type'):
                query += " AND type = %s"
                params.append(search_params['type'])
            
            if search_params.get('min_risk_score'):
                query += " AND risk_score >= %s"
                params.append(search_params['min_risk_score'])
            
            query += " ORDER BY created_at DESC LIMIT 50"
            
            cursor.execute(query, params)
            iocs = [dict(row) for row in cursor.fetchall()]
            
            return {
                'iocs': iocs,
                'total': len(iocs),
                'search_params': search_params
            }
            
    except Exception as e:
        logger.error(f"Erreur search_iocs: {e}")
        return {'iocs': [], 'total': 0}

@app.route('/api/dashboard/iocs/create', methods=['POST'])
def create_ioc():
    """CORRIGÉ - Crée un nouvel IOC"""
    try:
        ioc_data = request.get_json()
        
        if not ioc_data or 'value' not in ioc_data or 'type' not in ioc_data:
            return jsonify({'error': 'Données IOC invalides'}), 400
        
        # Générer un IOC complet
        ioc = {
            'id': f"ioc_{int(datetime.now().timestamp())}",
            'value': ioc_data['value'],
            'type': ioc_data['type'],
            'source': ioc_data.get('source', 'manual_input'),
            'risk_score': ioc_data.get('risk_score', 5.0),
            'created_at': datetime.now().isoformat(),
            'mitre_techniques': ioc_data.get('mitre_techniques', []),
            'enrichments': ioc_data.get('enrichments', {}),
            'confidence_level': ioc_data.get('confidence_level', 50)
        }
        
        # CORRECTION: Insérer en base via data_processor
        success = data_processor.insert_ioc(ioc)
        
        if success:
            # Notification WebSocket
            if websocket_handler:
                websocket_handler.broadcast_ioc_update(ioc)
            
            return jsonify({
                'status': 'success',
                'message': 'IOC créé avec succès',
                'ioc': ioc
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Erreur lors de la création de l\'IOC'
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur create_ioc: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/iocs/search', methods=['POST'])
def search_iocs_route():
    """Route de recherche IOCs (corrigée)"""
    try:
        search_params = request.get_json() or {}
        
        if hasattr(data_processor, 'search_iocs'):
            results = data_processor.search_iocs(search_params)
        else:
            # Mock data
            results = {
                'iocs': [],
                'total': 0,
                'search_params': search_params
            }
        
        return jsonify(results)
    except Exception as e:
        logger.error(f"Erreur search_iocs_route: {e}")
        return jsonify({
            'iocs': [],
            'total': 0,
            'error': str(e)
        })

def create_ioc_from_alert(self, alert):
    """Crée un IOC à partir d'une alerte détectée"""
    try:
        # Extraction des informations de l'alerte
        ioc_value = None
        ioc_type = None
        
        # Logique d'extraction selon le type d'alerte
        if 'IP' in alert.get('title', ''):
            # Extraire l'IP de la description ou du titre
            import re
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            match = re.search(ip_pattern, alert.get('description', ''))
            if match:
                ioc_value = match.group(0)
                ioc_type = 'ip'
        
        if ioc_value and ioc_type:
            ioc = {
                'id': f"ioc_{int(datetime.now().timestamp())}",
                'value': ioc_value,
                'type': ioc_type,
                'source': alert.get('source', 'alert_engine'),
                'risk_score': self._alert_level_to_risk_score(alert.get('level')),
                'created_at': datetime.now().isoformat(),
                'mitre_techniques': [],
                'enrichments': {
                    'from_alert': alert['id'],
                    'alert_level': alert.get('level')
                },
                'confidence_level': 80
            }
            
            # Insérer l'IOC en base
            self.insert_ioc(ioc)
            
            return ioc
    
    except Exception as e:
        logger.error(f"Erreur create_ioc_from_alert: {e}")
        return None

def _alert_level_to_risk_score(self, level):
    """Convertit le niveau d'alerte en score de risque"""
    mapping = {
        'critical': 9.0,
        'high': 7.5,
        'medium': 5.0,
        'low': 2.5
    }
    return mapping.get(level, 5.0)

def insert_ioc(self, ioc):
    """Insère un IOC en base de données"""
    try:
        if not self.db_connection:
            logger.info(f"[MOCK] IOC inséré: {ioc['value']}")
            return True
            
        with self.db_connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO indicators (
                    id, value, type, source, risk_score, 
                    created_at, mitre_techniques, enrichments, confidence_level
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (value) DO UPDATE SET
                    risk_score = EXCLUDED.risk_score,
                    enrichments = EXCLUDED.enrichments
            """, (
                ioc['id'], ioc['value'], ioc['type'], ioc['source'],
                ioc['risk_score'], ioc['created_at'],
                json.dumps(ioc['mitre_techniques']),
                json.dumps(ioc['enrichments']),
                ioc['confidence_level']
            ))
            self.db_connection.commit()
            return True
            
    except Exception as e:
        logger.error(f"Erreur insert_ioc: {e}")
        return False

# === ROUTES RAPPORTS ===

@app.route('/api/test/pdf', methods=['GET'])
def test_pdf_generation():
    """Route de test pour vérifier la génération PDF"""
    try:
        test_data = {
            'id': f'test_{int(datetime.now().timestamp())}',
            'title': 'Test PDF Generation',
            'type': 'test',
            'executive_summary': 'Test de génération PDF',
            'key_metrics': {'test': 'OK'}
        }
        
        pdf_path = report_generator._generate_pdf_report(test_data)
        
        if pdf_path and os.path.exists(pdf_path):
            file_size = os.path.getsize(pdf_path)
            return jsonify({
                'status': 'success',
                'pdf_path': pdf_path,
                'file_size': file_size,
                'message': 'PDF généré avec succès'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Échec génération PDF'
            }), 500
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/reports/generate', methods=['POST', 'OPTIONS'])
def generate_report():
    """Route corrigée pour générer des rapports"""
    
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.get_json() or {}
        report_type = data.get('type', 'daily')
        
        logger.info(f"🔄 Demande génération rapport type: {report_type}")
        
        # ✅ Vérifier que report_generator existe et est valide
        global report_generator
        if report_generator is None:
            logger.error("❌ ReportGenerator non disponible")
            return jsonify({
                'status': 'error',
                'error': 'Service de génération de rapports indisponible',
                'details': 'Module ReportLab probablement non installé'
                
            }), 503
        
        # Générer le rapport
        try:
            if report_type == 'weekly':
                result = report_generator.generate_weekly_report()
            else:  # daily par défaut
                result = report_generator.generate_daily_report()
            
            if result and isinstance(result, dict):
                if result.get('status') in ['completed', 'partial']:
                    logger.info(f"✅ Rapport généré: {result.get('report_id')}")
                    return jsonify(result)
                else:
                    logger.error(f"❌ Erreur génération: {result.get('error')}")
                    return jsonify(result), 500
            else:
                return jsonify({
                    'status': 'error',
                    'error': 'Résultat de génération invalide'
                }), 500
                
        except Exception as gen_error:
            logger.error(f"❌ Erreur pendant génération: {gen_error}")
            import traceback
            traceback.print_exc()
            return jsonify({
                'status': 'error',
                'error': str(gen_error)
            }), 500
            
    except Exception as e:
        logger.error(f"❌ Erreur générale generate_report: {e}")
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/test/reportlab', methods=['GET'])
def test_reportlab():
    """Test des dépendances ReportLab"""
    try:
        # Test ReportLab
        import reportlab
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet
        import io
        
        # Créer un PDF de test en mémoire
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = [Paragraph("Test ReportLab", styles['Title'])]
        doc.build(story)
        
        pdf_size = len(buffer.getvalue())
        buffer.close()
        
        # Test Jinja2
        import jinja2
        template = jinja2.Template("Test {{ name }}")
        rendered = template.render(name="Jinja2")
        
        return jsonify({
            'status': 'success',
            'reportlab_version': reportlab.Version,
            'jinja2_version': jinja2.__version__,
            'test_pdf_size': pdf_size,
            'test_template': rendered,
            'report_generator_class_available': ReportGenerator is not None,
            'report_generator_instance': report_generator is not None
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'details': 'Problème avec les dépendances ReportLab ou Jinja2'
        }), 500

@app.route('/api/reports/recent', methods=['GET', 'OPTIONS'])
def get_recent_reports():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        return jsonify({
            'reports': [
                {
                    'id': 'report_001',
                    'title': 'Rapport Test',
                    'status': 'completed',
                    'created_at': datetime.now().isoformat()
                }
            ]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/debug/report-status', methods=['GET'])
def debug_report_status():
    """Route de debug pour vérifier l'état du générateur de rapports"""
    try:
        global report_generator, data_processor
        
        status = {
            'report_generator_exists': report_generator is not None,
            'data_processor_exists': data_processor is not None,
            'reportlab_available': ReportGenerator is not None,
            'reports_dir': getattr(report_generator, 'reports_dir', 'N/A') if report_generator else 'N/A',
            'reports_dir_exists': False,
            'reports_dir_writable': False
        }
        
        if report_generator and hasattr(report_generator, 'reports_dir'):
            reports_dir = report_generator.reports_dir
            status['reports_dir_exists'] = os.path.exists(reports_dir)
            status['reports_dir_writable'] = os.access(reports_dir, os.W_OK) if os.path.exists(reports_dir) else False
        
        return jsonify(status)
        
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'})

@app.route('/api/reports/<report_id>/download', methods=['GET', 'OPTIONS'])
def download_report(report_id):
    """Téléchargement corrigé des rapports PDF"""
    global report_generator
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        logger.info(f"🔽 Demande téléchargement rapport: {report_id}")
        
        # ✅ CORRECTION: Vérifier que report_generator existe
        # ✅ CORRECTION: Vérifier et créer report_generator si nécessaire
        global report_generator
        if report_generator is None:
         try:
           if ReportGenerator is not None and data_processor is not None:
            report_generator = ReportGenerator(data_processor)
            logger.info("✅ ReportGenerator créé à la demande")
           else:
            logger.error("❌ ReportGenerator ou data_processor indisponible")
            return jsonify({'error': 'Service de rapports indisponible'}), 503
         except Exception as init_error:
          logger.error(f"❌ Impossible créer ReportGenerator: {init_error}")
          return jsonify({'error': f'Erreur initialisation: {str(init_error)}'}), 503
        
        # Récupérer le chemin du fichier
        try:
            pdf_path = report_generator.download_report(report_id)
        except Exception as download_error:
            logger.error(f"❌ Erreur méthode download: {download_error}")
            pdf_path = None
        
        # Si pas trouvé par la méthode, chercher directement
        # ✅ FALLBACK: Créer un PDF minimal
        if not pdf_path:
           try:
        # Générer un PDF de test
             test_pdf_path = os.path.join(report_generator.reports_dir if report_generator else 'reports/', f"{report_id}_fallback.pdf")
        
             from reportlab.platypus import SimpleDocTemplate, Paragraph
             from reportlab.lib.pagesizes import A4
             from reportlab.lib.styles import getSampleStyleSheet
        
             doc = SimpleDocTemplate(test_pdf_path, pagesize=A4)
             styles = getSampleStyleSheet()
             story = [Paragraph(f"Rapport {report_id}", styles['Title'])]
             doc.build(story)
        
             if os.path.exists(test_pdf_path):
               pdf_path = test_pdf_path
               logger.info(f"✅ PDF fallback créé: {pdf_path}")
        
           except Exception as fallback_error:
              logger.error(f"❌ Erreur fallback PDF: {fallback_error}")
        
        if not pdf_path:
            reports_dir = getattr(report_generator, 'reports_dir', 'reports/')
            pdf_filename = f"{report_id}.pdf"
            pdf_path = os.path.join(reports_dir, pdf_filename)
        
        # Vérifier l'existence et la validité du fichier
        if pdf_path and os.path.exists(pdf_path):
            file_size = os.path.getsize(pdf_path)
            if file_size == 0:
                logger.error(f"❌ Fichier PDF vide: {pdf_path}")
                return jsonify({'error': 'Fichier PDF corrompu'}), 404
            
            logger.info(f"✅ Fichier trouvé: {pdf_path} ({file_size} bytes)")
            
            try:
                # ✅ CORRECTION: Utilisation correcte de send_from_directory
                directory = os.path.dirname(os.path.abspath(pdf_path))
                filename = os.path.basename(pdf_path)
                
                response = send_from_directory(
                    directory=directory,
                    path=filename,
                    as_attachment=True,
                    download_name=f'rapport_{report_id}.pdf',
                    mimetype='application/pdf'
                )
                
                # Headers supplémentaires
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = f'attachment; filename="rapport_{report_id}.pdf"'
                response.headers['Content-Length'] = str(file_size)
                
                return response
                
            except Exception as send_error:
                logger.error(f"❌ Erreur envoi fichier: {send_error}")
                # Fallback: lire et envoyer le fichier manuellement
                try:
                    with open(pdf_path, 'rb') as f:
                        pdf_data = f.read()
                    
                    response = make_response(pdf_data)
                    response.headers['Content-Type'] = 'application/pdf'
                    response.headers['Content-Disposition'] = f'attachment; filename="rapport_{report_id}.pdf"'
                    response.headers['Content-Length'] = str(len(pdf_data))
                    
                    return response
                except Exception as read_error:
                    logger.error(f"❌ Erreur lecture fichier: {read_error}")
                    return jsonify({'error': 'Erreur lecture fichier'}), 500
        else:
            logger.error(f"❌ Fichier non trouvé: {report_id}")
            return jsonify({
                'error': 'Rapport non trouvé',
                'report_id': report_id,
                'searched_path': pdf_path
            }), 404
        
    except Exception as e:
        logger.error(f"❌ Erreur téléchargement: {e}")
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/dashboard/test/simulate-attack', methods=['POST'])
def simulate_attack():
    """Simule une attaque pour tester le système d'alertes"""
    try:
        malicious_indicator = {
            'type': 'ip-addr',
            'value': '192.168.1.100',
            'source': 'test_simulation',
            'confidence': 85,
            'malware_families': ['trojan', 'backdoor'],
            'geolocation': {
                'country_code': 'CN',
                'country': 'China'
            },
            'mitre_techniques': ['T1055', 'T1071'],
            'tags': ['apt', 'c2-server', 'malware'],
            'timestamp': datetime.now().isoformat()
        }
        
        # Processus d'alerte
        generated_alerts = alert_engine.process_indicator(malicious_indicator)
        
        # Notification WebSocket
        for alert in generated_alerts:
            websocket_handler.broadcast_new_alert(alert)
        
        return jsonify({
            'status': 'success',
            'message': 'Attaque simulée avec succès',
            'indicator': malicious_indicator,
            'alerts_generated': len(generated_alerts),
            'alerts': generated_alerts
        })
        
    except Exception as e:
        logger.error(f"Erreur simulate_attack: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# Démarrage de l'application
# =============================================================================

if __name__ == '__main__':
    try:
        print("🚀 Démarrage CTI Dashboard Backend")
        print(f"📡 API disponible sur: http://localhost:5001")
        print(f"🔌 WebSocket disponible sur: ws://localhost:5001")
        print(f"🧪 Test endpoint: http://localhost:5001/api/test")
        
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5001, 
            debug=True,  # Activer pour le développement
            allow_unsafe_werkzeug=True
        )
        
    except Exception as e:
        logger.error(f"❌ Erreur lors du démarrage: {e}")
        raise