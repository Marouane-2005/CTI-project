#!/usr/bin/env python3
"""
Health Check System pour le pipeline CTI
Vérifications de santé des services et composants
"""

import os
import sys
import json
import time
import socket
import requests
import psutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Ajout du répertoire parent au chemin
sys.path.append(str(Path(__file__).parent.parent))

try:
    from utils.logger import get_logger
    from scripts.utils.database import DatabaseManager
    from utils.opencti_helper import OpenCTIHelper
except ImportError:
    # Fallback si les modules utils ne sont pas disponibles
    import logging
    def get_logger(name):
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(name)

@dataclass
class HealthStatus:
    """Classe pour représenter le statut de santé d'un service"""
    service: str
    status: str  # 'healthy', 'warning', 'critical', 'unknown'
    message: str
    response_time_ms: float = 0.0
    last_check: str = ""
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.last_check == "":
            self.last_check = datetime.now().isoformat()
        if self.details is None:
            self.details = {}

class HealthChecker:
    """Vérificateur de santé principal pour le pipeline CTI"""
    
    def __init__(self, config_path: str = None):
        """Initialisation du vérificateur de santé"""
        self.logger = get_logger(__name__)
        self.config_path = config_path or "config/opencti_config.json"
        
        # Chargement de la configuration
        self.config = self._load_config()
        
        # Seuils de performance
        self.performance_thresholds = {
            'response_time_ms': 5000,  # 5 secondes max
            'memory_usage_percent': 80,  # 80% max
            'disk_usage_percent': 85,   # 85% max
            'cpu_usage_percent': 90     # 90% max
        }
        
        self.logger.info("🏥 HealthChecker initialisé")
    
    def _load_config(self) -> Dict:
        """Chargement de la configuration"""
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                self.logger.warning(f"⚠️ Config non trouvée: {self.config_path}")
                return {}
        except Exception as e:
            self.logger.error(f"❌ Erreur chargement config: {e}")
            return {}
    
    def check_opencti_connection(self) -> HealthStatus:
        """Vérification de la connexion OpenCTI"""
        start_time = time.time()
        
        try:
            opencti_config = self.config.get("opencti", {})
            url = opencti_config.get("url", "http://localhost:8080")
            token = opencti_config.get("token", "")
            
            if not token:
                return HealthStatus(
                    service="opencti",
                    status="critical", 
                    message="Token OpenCTI manquant",
                    details={"url": url}
                )
            
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            # Test de connexion simple
            response = requests.get(
                f"{url}/graphql",
                headers=headers,
                timeout=10
            )
            
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                # Test GraphQL basique
                query = '{ me { id name } }'
                graphql_response = requests.post(
                    f"{url}/graphql",
                    headers=headers,
                    json={"query": query},
                    timeout=10
                )
                
                if graphql_response.status_code == 200:
                    data = graphql_response.json()
                    if 'errors' not in data:
                        return HealthStatus(
                            service="opencti",
                            status="healthy",
                            message="Connexion OpenCTI opérationnelle",
                            response_time_ms=response_time,
                            details={
                                "url": url,
                                "user_authenticated": True,
                                "api_version": "GraphQL"
                            }
                        )
            
            return HealthStatus(
                service="opencti",
                status="warning",
                message=f"OpenCTI répond avec status: {response.status_code}",
                response_time_ms=response_time,
                details={"status_code": response.status_code, "url": url}
            )
            
        except requests.exceptions.Timeout:
            return HealthStatus(
                service="opencti",
                status="critical",
                message="Timeout lors de la connexion OpenCTI",
                response_time_ms=(time.time() - start_time) * 1000
            )
        except requests.exceptions.ConnectionError:
            return HealthStatus(
                service="opencti", 
                status="critical",
                message="Impossible de se connecter à OpenCTI",
                details={"url": opencti_config.get("url", "unknown")}
            )
        except Exception as e:
            return HealthStatus(
                service="opencti",
                status="critical", 
                message=f"Erreur connexion OpenCTI: {str(e)}"
            )
    
    def check_database_connection(self) -> HealthStatus:
        """Vérification de la connexion base de données"""
        start_time = time.time()
        
        try:
            # Tentative d'utilisation du DatabaseManager existant
            db = DatabaseManager()
            
            # Test de connexion simple
            result = db.execute_query("SELECT 1 as test_connection")
            response_time = (time.time() - start_time) * 1000
            
            if result:
                # Vérifications additionnelles
                tables_check = db.execute_query("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """)
                
                return HealthStatus(
                    service="database",
                    status="healthy",
                    message="Base de données opérationnelle",
                    response_time_ms=response_time,
                    details={
                        "tables_count": len(tables_check) if tables_check else 0,
                        "connection_pool": "active"
                    }
                )
            else:
                return HealthStatus(
                    service="database",
                    status="warning",
                    message="Connexion DB possible mais résultat vide",
                    response_time_ms=response_time
                )
                
        except Exception as e:
            return HealthStatus(
                service="database",
                status="critical",
                message=f"Erreur base de données: {str(e)}"
            )
    
    def check_redis_connection(self) -> HealthStatus:
        """Vérification de la connexion Redis"""
        start_time = time.time()
        
        try:
            import redis
            
            # Configuration Redis depuis les variables d'environnement
            redis_host = os.getenv('REDIS_HOST', 'localhost')
            redis_port = int(os.getenv('REDIS_PORT', '6379'))
            redis_db = int(os.getenv('REDIS_DB', '0'))
            
            # Connexion Redis
            r = redis.Redis(
                host=redis_host,
                port=redis_port, 
                db=redis_db,
                decode_responses=True,
                socket_connect_timeout=5
            )
            
            # Test ping
            ping_result = r.ping()
            response_time = (time.time() - start_time) * 1000
            
            if ping_result:
                # Informations additionnelles
                info = r.info()
                
                return HealthStatus(
                    service="redis",
                    status="healthy",
                    message="Redis opérationnel",
                    response_time_ms=response_time,
                    details={
                        "version": info.get('redis_version', 'unknown'),
                        "connected_clients": info.get('connected_clients', 0),
                        "used_memory_human": info.get('used_memory_human', 'unknown')
                    }
                )
            else:
                return HealthStatus(
                    service="redis",
                    status="critical",
                    message="Redis ping failed"
                )
                
        except ImportError:
            return HealthStatus(
                service="redis",
                status="warning",
                message="Module redis non installé"
            )
        except Exception as e:
            return HealthStatus(
                service="redis",
                status="critical",
                message=f"Erreur Redis: {str(e)}"
            )
    
    def check_system_resources(self) -> HealthStatus:
        """Vérification des ressources système"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Mémoire
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disque
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            
            # Détermination du statut global
            status = "healthy"
            messages = []
            
            if cpu_percent > self.performance_thresholds['cpu_usage_percent']:
                status = "warning"
                messages.append(f"CPU élevé: {cpu_percent:.1f}%")
            
            if memory_percent > self.performance_thresholds['memory_usage_percent']:
                status = "critical" if memory_percent > 95 else "warning"
                messages.append(f"Mémoire élevée: {memory_percent:.1f}%")
            
            if disk_percent > self.performance_thresholds['disk_usage_percent']:
                status = "critical" if disk_percent > 95 else "warning"  
                messages.append(f"Disque plein: {disk_percent:.1f}%")
            
            message = "Ressources système OK" if not messages else "; ".join(messages)
            
            return HealthStatus(
                service="system_resources",
                status=status,
                message=message,
                details={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory_percent,
                    "memory_available_gb": round(memory.available / (1024**3), 2),
                    "disk_percent": disk_percent,
                    "disk_free_gb": round(disk.free / (1024**3), 2)
                }
            )
            
        except Exception as e:
            return HealthStatus(
                service="system_resources",
                status="critical",
                message=f"Erreur vérification système: {str(e)}"
            )
    
    def check_file_permissions(self) -> HealthStatus:
        """Vérification des permissions des fichiers critiques"""
        try:
            critical_paths = [
                "config/",
                "logs/",
                "output/",
                "scripts/"
            ]
            
            issues = []
            
            for path_str in critical_paths:
                path = Path(path_str)
                if not path.exists():
                    issues.append(f"{path_str} n'existe pas")
                    continue
                
                # Vérification lecture
                if not os.access(path, os.R_OK):
                    issues.append(f"{path_str} non lisible")
                
                # Vérification écriture pour certains dossiers
                if path_str in ["logs/", "output/"] and not os.access(path, os.W_OK):
                    issues.append(f"{path_str} non accessible en écriture")
            
            if issues:
                return HealthStatus(
                    service="file_permissions",
                    status="warning",
                    message=f"Problèmes de permissions: {'; '.join(issues)}",
                    details={"issues": issues}
                )
            else:
                return HealthStatus(
                    service="file_permissions", 
                    status="healthy",
                    message="Permissions des fichiers OK"
                )
                
        except Exception as e:
            return HealthStatus(
                service="file_permissions",
                status="critical",
                message=f"Erreur vérification permissions: {str(e)}"
            )
    
    def check_network_connectivity(self) -> HealthStatus:
        """Vérification de la connectivité réseau"""
        start_time = time.time()
        
        try:
            # Test de connectivité vers services externes
            test_hosts = [
                ("8.8.8.8", 53),      # Google DNS
                ("1.1.1.1", 53),      # Cloudflare DNS
            ]
            
            connectivity_results = []
            
            for host, port in test_hosts:
                try:
                    sock = socket.create_connection((host, port), timeout=5)
                    sock.close()
                    connectivity_results.append(f"{host}:OK")
                except:
                    connectivity_results.append(f"{host}:FAIL")
            
            response_time = (time.time() - start_time) * 1000
            
            failed_count = sum(1 for result in connectivity_results if "FAIL" in result)
            
            if failed_count == 0:
                status = "healthy"
                message = "Connectivité réseau OK"
            elif failed_count < len(test_hosts):
                status = "warning"
                message = "Connectivité réseau partielle"
            else:
                status = "critical"
                message = "Pas de connectivité réseau"
            
            return HealthStatus(
                service="network_connectivity",
                status=status,
                message=message,
                response_time_ms=response_time,
                details={"tests": connectivity_results}
            )
            
        except Exception as e:
            return HealthStatus(
                service="network_connectivity",
                status="critical",
                message=f"Erreur test réseau: {str(e)}"
            )
    
    def check_all_services(self) -> Dict[str, HealthStatus]:
        """Vérification complète de tous les services"""
        self.logger.info("🏥 Début de la vérification complète de santé")
        
        checks = {
            "opencti": self.check_opencti_connection,
            "database": self.check_database_connection, 
            "redis": self.check_redis_connection,
            "system_resources": self.check_system_resources,
            "file_permissions": self.check_file_permissions,
            "network_connectivity": self.check_network_connectivity
        }
        
        results = {}
        overall_status = "healthy"
        
        for service_name, check_function in checks.items():
            try:
                result = check_function()
                results[service_name] = result
                
                # Mise à jour du statut global
                if result.status == "critical":
                    overall_status = "critical"
                elif result.status == "warning" and overall_status != "critical":
                    overall_status = "warning"
                    
            except Exception as e:
                self.logger.error(f"❌ Erreur lors du check {service_name}: {e}")
                results[service_name] = HealthStatus(
                    service=service_name,
                    status="critical",
                    message=f"Erreur durant la vérification: {str(e)}"
                )
                overall_status = "critical"
        
        # Ajout d'un résumé global
        results["_overall"] = HealthStatus(
            service="overall",
            status=overall_status,
            message=f"Statut global: {overall_status}",
            details={
                "total_services": len(checks),
                "healthy": len([r for r in results.values() if r.status == "healthy"]),
                "warning": len([r for r in results.values() if r.status == "warning"]), 
                "critical": len([r for r in results.values() if r.status == "critical"])
            }
        )
        
        self.logger.info(f"🏥 Vérification terminée - Statut global: {overall_status}")
        return results
    
    def generate_health_report(self, results: Dict[str, HealthStatus] = None) -> Dict:
        """Génération d'un rapport de santé détaillé"""
        if results is None:
            results = self.check_all_services()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": results.get("_overall", HealthStatus("overall", "unknown", "")).status,
            "services": {},
            "summary": {
                "total_services": len(results) - 1,  # -1 pour exclure _overall
                "healthy": 0,
                "warning": 0, 
                "critical": 0,
                "unknown": 0
            }
        }
        
        # Compilation des résultats par service
        for service_name, status in results.items():
            if service_name == "_overall":
                continue
                
            report["services"][service_name] = asdict(status)
            report["summary"][status.status] += 1
        
        return report
    
    def save_health_report(self, results: Dict[str, HealthStatus] = None) -> str:
        """Sauvegarde du rapport de santé"""
        try:
            report = self.generate_health_report(results)
            
            # Création du dossier de rapports
            reports_dir = Path("logs/health_reports")
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Nom du fichier avec timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = reports_dir / f"health_report_{timestamp}.json"
            
            # Sauvegarde
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"📋 Rapport de santé sauvegardé: {filename}")
            return str(filename)
            
        except Exception as e:
            self.logger.error(f"❌ Erreur sauvegarde rapport: {e}")
            return ""
    
    def print_health_summary(self, results: Dict[str, HealthStatus] = None):
        """Affichage résumé de la santé des services"""
        if results is None:
            results = self.check_all_services()
        
        print("\n" + "="*60)
        print("🏥 RAPPORT DE SANTÉ - PIPELINE CTI")
        print("="*60)
        
        overall = results.get("_overall")
        if overall:
            status_emoji = {
                "healthy": "✅",
                "warning": "⚠️", 
                "critical": "❌",
                "unknown": "❓"
            }
            
            print(f"📊 STATUT GLOBAL: {status_emoji.get(overall.status, '❓')} {overall.status.upper()}")
            print(f"🕒 Horodatage: {overall.last_check}")
            print()
        
        # Détail par service
        for service_name, status in results.items():
            if service_name == "_overall":
                continue
            
            status_emoji = {
                "healthy": "✅",
                "warning": "⚠️",
                "critical": "❌", 
                "unknown": "❓"
            }
            
            emoji = status_emoji.get(status.status, "❓")
            print(f"{emoji} {service_name.upper()}: {status.message}")
            
            if status.response_time_ms > 0:
                print(f"   ⏱️  Temps de réponse: {status.response_time_ms:.0f}ms")
            
            if status.details:
                for key, value in status.details.items():
                    print(f"   📋 {key}: {value}")
            print()
        
        print("="*60)

def main():
    """Point d'entrée pour utilisation en ligne de commande"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Health Check du pipeline CTI")
    parser.add_argument("--config", help="Chemin vers la configuration")
    parser.add_argument("--save", action="store_true", help="Sauvegarder le rapport")
    parser.add_argument("--quiet", action="store_true", help="Mode silencieux")
    
    args = parser.parse_args()
    
    # Création du vérificateur
    checker = HealthChecker(config_path=args.config)
    
    # Exécution des vérifications
    results = checker.check_all_services()
    
    # Affichage des résultats
    if not args.quiet:
        checker.print_health_summary(results)
    
    # Sauvegarde si demandée
    if args.save:
        checker.save_health_report(results)
    
    # Code de sortie selon le statut global
    overall_status = results.get("_overall", HealthStatus("", "unknown", "")).status
    exit_codes = {
        "healthy": 0,
        "warning": 1,
        "critical": 2,
        "unknown": 3
    }
    
    sys.exit(exit_codes.get(overall_status, 3))

if __name__ == "__main__":
    main()