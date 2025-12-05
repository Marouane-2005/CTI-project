"""
Système de logging pour le projet CTI
Logs structurés avec rotation et archivage
"""

import logging
import os
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from typing import Dict, Any, Optional
import traceback

class CTILogger:
    def __init__(self, module_name: str, log_level: str = "INFO"):
        """
        Logger CTI avec gestion complète de l'encodage
        """
        self.module_name = module_name
        self.logger = logging.getLogger(module_name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        if not self.logger.handlers:
            self.setup_handlers()
    
    def setup_handlers(self):
        """Configure les handlers avec encodage UTF-8"""
        os.makedirs("logs", exist_ok=True)
        
        # Format sans émojis pour éviter les problèmes d'encodage
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Handler pour fichier principal avec encodage UTF-8 explicite
        try:
            file_handler = RotatingFileHandler(
                f"logs/{self.module_name.lower()}.log",
                maxBytes=10*1024*1024,
                backupCount=5,
                encoding='utf-8'  # IMPORTANT: encodage explicite
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print(f"Erreur création file handler: {e}")
        
        # Handler global avec encodage UTF-8
        try:
            global_handler = TimedRotatingFileHandler(
                "logs/cti_global.log",
                when='midnight',
                interval=1,
                backupCount=30,
                encoding='utf-8'  # IMPORTANT: encodage explicite
            )
            global_handler.setFormatter(formatter)
            self.logger.addHandler(global_handler)
        except Exception as e:
            print(f"Erreur création global handler: {e}")
        
        # Handler console avec gestion d'erreurs d'encodage
        try:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            # Configurer l'encodage pour le handler console
            if hasattr(console_handler.stream, 'reconfigure'):
                console_handler.stream.reconfigure(encoding='utf-8', errors='replace')
            self.logger.addHandler(console_handler)
        except Exception as e:
            print(f"Erreur création console handler: {e}")
    
    def _safe_message(self, message: str) -> str:
        """Nettoie le message pour éviter les problèmes d'encodage"""
        if not isinstance(message, str):
            message = str(message)
        
        # Remplacer les émojis problématiques par du texte
        emoji_replacements = {
            '📊': '[STATS]',
            '✅': '[OK]',
            '❌': '[ERROR]',
            '⚠️': '[WARNING]',
            '🔄': '[PROCESSING]',
            '🚀': '[START]',
            '⏹️': '[STOP]',
            '💡': '[INFO]',
            '🎯': '[TARGET]',
            '🔧': '[CONFIG]',
            '📦': '[PACKAGE]',
            '📝': '[LOG]',
            '👋': '[BYE]'
        }
        
        for emoji, replacement in emoji_replacements.items():
            message = message.replace(emoji, replacement)
        
        # Encoder/décoder pour nettoyer les caractères problématiques
        try:
            # Encoder en bytes puis décoder avec gestion d'erreurs
            message = message.encode('utf-8', errors='replace').decode('utf-8', errors='replace')
        except Exception:
            # En cas d'erreur, convertir tous les caractères non-ASCII
            message = message.encode('ascii', errors='replace').decode('ascii')
        
        return message
    
    def info(self, message: str, extra_data: Optional[Dict] = None):
        """Log d'information avec encodage sécurisé"""
        safe_message = self._safe_message(message)
        self._log_with_context(logging.INFO, safe_message, extra_data)
    
    def warning(self, message: str, extra_data: Optional[Dict] = None):
        """Log d'avertissement avec encodage sécurisé"""
        safe_message = self._safe_message(message)
        self._log_with_context(logging.WARNING, safe_message, extra_data)
    
    def error(self, message: str, extra_data: Optional[Dict] = None, exception: Optional[Exception] = None):
        """Log d'erreur avec encodage sécurisé"""
        safe_message = self._safe_message(message)
        
        if exception:
            extra_data = extra_data or {}
            extra_data['exception'] = self._safe_message(str(exception))
            # Nettoyer le traceback aussi
            tb = traceback.format_exc()
            extra_data['traceback'] = self._safe_message(tb)
        
        self._log_with_context(logging.ERROR, safe_message, extra_data)
    
    def critical(self, message: str, extra_data: Optional[Dict] = None):
        """Log critique avec encodage sécurisé"""
        safe_message = self._safe_message(message)
        self._log_with_context(logging.CRITICAL, safe_message, extra_data)
    
    def debug(self, message: str, extra_data: Optional[Dict] = None):
        """Log de debug avec encodage sécurisé"""
        safe_message = self._safe_message(message)
        self._log_with_context(logging.DEBUG, safe_message, extra_data)
    
    def _log_with_context(self, level: int, message: str, extra_data: Optional[Dict] = None):
        """Log avec contexte et gestion d'encodage"""
        try:
            # Log du message principal
            self.logger.log(level, message)
            
            # Log du contexte en JSON si présent
            if extra_data:
                self._log_json_context({
                    'module': self.module_name,
                    'timestamp': datetime.now().isoformat(),
                    'message': message,
                    'data': extra_data
                })
        except Exception as e:
            # En cas d'erreur de logging, utiliser print comme fallback
            try:
                print(f"[LOGGING ERROR] {message} - Error: {e}")
            except:
                print("[LOGGING ERROR] Unable to log message due to encoding issues")
    
    def _log_json_context(self, context: Dict):
        """Sauvegarde contexte JSON avec gestion d'encodage"""
        try:
            json_file = f"logs/{self.module_name.lower()}_context.jsonl"
            
            # Nettoyer le contexte pour JSON
            clean_context = self._clean_for_json(context)
            
            with open(json_file, 'a', encoding='utf-8') as f:
                json_line = json.dumps(clean_context, ensure_ascii=False, default=str)
                f.write(json_line + '\n')
        except Exception as e:
            # Fallback silencieux pour éviter les boucles infinies
            pass
    
    def _clean_for_json(self, obj):
        """Nettoie un objet pour la sérialisation JSON"""
        if isinstance(obj, dict):
            return {k: self._clean_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._clean_for_json(item) for item in obj]
        elif isinstance(obj, str):
            return self._safe_message(obj)
        else:
            return str(obj)
    
    def log_collection_stats(self, stats: Dict):
        """Log spécialisé pour les statistiques de collecte"""
        self.info("Collection terminée", {
            'total_items': stats.get('total_items', 0),
            'sources_processed': stats.get('sources_processed', 0),
            'errors_count': len(stats.get('errors', [])),
            'duration': stats.get('duration', 0),
            'memory_usage': stats.get('memory_usage', 0)
        })
    
    def log_api_call(self, api_name: str, endpoint: str, status_code: int, response_time: float):
        """Log des appels API"""
        self.info(f"API Call: {api_name}", {
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time_ms': response_time * 1000,
            'success': status_code < 400
        })
    
    def log_database_operation(self, operation: str, table: str, affected_rows: int):
        """Log des opérations de base de données"""
        self.info(f"Database: {operation}", {
            'table': table,
            'affected_rows': affected_rows,
            'operation': operation
        })
    
    def log_file_operation(self, operation: str, file_path: str, file_size: int = 0):
        """Log des opérations sur fichiers"""
        self.info(f"File: {operation}", {
            'file_path': file_path,
            'file_size_bytes': file_size,
            'operation': operation
        })
    
    def log_security_event(self, event_type: str, details: Dict):
        """Log des événements de sécurité"""
        self.warning(f"Security Event: {event_type}", {
            'event_type': event_type,
            'details': details,
            'severity': 'security'
        })
    
    def log_performance_metric(self, metric_name: str, value: float, unit: str = "ms"):
        """Log des métriques de performance"""
        self.info(f"Performance: {metric_name}", {
            'metric_name': metric_name,
            'value': value,
            'unit': unit,
            'category': 'performance'
        })


class CTILogAnalyzer:
    """Analyseur de logs pour générer des rapports"""
    
    def __init__(self, log_directory: str = "logs"):
        self.log_directory = log_directory
    
    def generate_daily_report(self, date: str = None) -> Dict:
        """Génère un rapport quotidien des logs"""
        if not date:
            date = datetime.now().strftime("%Y-%m-%d")
        
        report = {
            'date': date,
            'summary': {
                'total_logs': 0,
                'errors': 0,
                'warnings': 0,
                'info': 0
            },
            'modules': {},
            'top_errors': [],
            'performance_metrics': {}
        }
        
        try:
            # Analyser les fichiers de logs
            for filename in os.listdir(self.log_directory):
                if filename.endswith('.log'):
                    self._analyze_log_file(f"{self.log_directory}/{filename}", report)
            
            # Analyser les contextes JSON
            for filename in os.listdir(self.log_directory):
                if filename.endswith('_context.jsonl'):
                    self._analyze_json_context(f"{self.log_directory}/{filename}", report)
            
        except Exception as e:
            print(f"Erreur lors de l'analyse des logs : {e}")
        
        return report
    
    def _analyze_log_file(self, filepath: str, report: Dict):
        """Analyse un fichier de log"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    if '- ERROR -' in line:
                        report['summary']['errors'] += 1
                    elif '- WARNING -' in line:
                        report['summary']['warnings'] += 1
                    elif '- INFO -' in line:
                        report['summary']['info'] += 1
                    
                    report['summary']['total_logs'] += 1
        except Exception as e:
            print(f"Erreur lecture fichier {filepath} : {e}")
    
    def _analyze_json_context(self, filepath: str, report: Dict):
        """Analyse les contextes JSON"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        context = json.loads(line.strip())
                        module = context.get('module', 'unknown')
                        
                        if module not in report['modules']:
                            report['modules'][module] = {
                                'total_operations': 0,
                                'errors': 0,
                                'last_activity': context.get('timestamp')
                            }
                        
                        report['modules'][module]['total_operations'] += 1
                        
                        if 'exception' in context.get('data', {}):
                            report['modules'][module]['errors'] += 1
                    
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Erreur analyse contexte {filepath} : {e}")
    
    def cleanup_old_logs(self, days: int = 30):
        """Nettoie les anciens logs"""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            for filename in os.listdir(self.log_directory):
                filepath = os.path.join(self.log_directory, filename)
                
                if os.path.isfile(filepath):
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    
                    if file_mtime < cutoff_date:
                        os.remove(filepath)
                        print(f"Suppression ancien log : {filename}")
        
        except Exception as e:
            print(f"Erreur lors du nettoyage des logs : {e}")


# Fonction utilitaire pour créer un logger rapidement
def get_logger(module_name: str, log_level: str = "INFO") -> CTILogger:
    """Fonction utilitaire pour créer un logger"""
    return CTILogger(module_name, log_level)


# Test du système de logging
if __name__ == "__main__":
    # Test basique
    logger = get_logger("TEST_MODULE")
    
    logger.info("Test du système de logging")
    logger.warning("Ceci est un avertissement")
    logger.error("Ceci est une erreur", {'error_code': 500})
    
    # Test avec exception
    try:
        raise ValueError("Test d'exception")
    except Exception as e:
        logger.error("Erreur capturée", exception=e)
    
    # Test des logs spécialisés
    logger.log_collection_stats({
        'total_items': 150,
        'sources_processed': 5,
        'errors': [],
        'duration': 45.2
    })
    
    logger.log_api_call("OTX_API", "/api/v1/pulses", 200, 0.5)
    
    print("Tests de logging terminés - Vérifiez le dossier logs/")