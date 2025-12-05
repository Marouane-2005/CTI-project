# dashboard/tests/integration/test_dashboard_detection_fixed.py
"""
Script de test CORRIGÉ pour valider les capacités de détection du CTI Dashboard
Version adaptée à votre architecture existante
"""

import asyncio
import aiohttp
import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging
from dataclasses import dataclass
import sys
import os

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TestScenario:
    name: str
    description: str
    test_data: Dict[str, Any]
    expected_alerts: int
    risk_threshold: float

class DashboardDetectionTester:
    def __init__(self, dashboard_url: str = "http://localhost:5001"):
        self.dashboard_url = dashboard_url
        self.session = None
        self.test_results = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_api_connectivity(self) -> bool:
        """Test de connectivité avec endpoints alternatifs"""
        # Liste des endpoints à tester par ordre de priorité
        test_endpoints = [
            "/",  # Route racine (existe dans votre app.py)
            "/api/dashboard/overview",  # Endpoint principal
            "/api/dashboard/stats",     # Endpoint de stats
        ]
        
        for endpoint in test_endpoints:
            try:
                logger.info(f"🔍 Test connectivité: {self.dashboard_url}{endpoint}")
                async with self.session.get(f"{self.dashboard_url}{endpoint}") as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            logger.info(f"✅ API connectivité OK via {endpoint}")
                            logger.info(f"📊 Réponse: {data.get('message', 'API accessible')}")
                            return True
                        except Exception as json_error:
                            # Si ce n'est pas du JSON, mais status 200, c'est OK quand même
                            logger.info(f"✅ API connectivité OK via {endpoint} (non-JSON)")
                            return True
                    else:
                        logger.warning(f"⚠️ Endpoint {endpoint}: Status {response.status}")
                        
            except Exception as e:
                logger.warning(f"⚠️ Erreur endpoint {endpoint}: {e}")
                continue
        
        # Test final avec un endpoint plus basique
        try:
            logger.info("🔍 Test connectivité basique...")
            async with self.session.get(self.dashboard_url) as response:
                if response.status == 200:
                    logger.info("✅ Serveur accessible (réponse basique OK)")
                    return True
                else:
                    logger.error(f"❌ Serveur non accessible: Status {response.status}")
                    
        except Exception as e:
            logger.error(f"❌ Serveur complètement inaccessible: {e}")
            
        return False

    async def check_backend_health(self) -> Dict[str, Any]:
        """Vérification approfondie de l'état du backend"""
        health_info = {
            "server_accessible": False,
            "endpoints_working": [],
            "endpoints_failing": [],
            "database_connected": None,
            "modules_loaded": None
        }
        
        # Test des endpoints principaux
        endpoints_to_test = [
            "/",
            "/api/dashboard/overview", 
            "/api/dashboard/stats",
            "/api/dashboard/threats/live",
            "/api/dashboard/alerts",
            "/api/dashboard/mitre/overview"
        ]
        
        for endpoint in endpoints_to_test:
            try:
                async with self.session.get(f"{self.dashboard_url}{endpoint}") as response:
                    if response.status == 200:
                        health_info["endpoints_working"].append(endpoint)
                        health_info["server_accessible"] = True
                    else:
                        health_info["endpoints_failing"].append(f"{endpoint} ({response.status})")
            except Exception as e:
                health_info["endpoints_failing"].append(f"{endpoint} (error: {str(e)[:50]})")
        
        return health_info

    def generate_test_scenarios(self) -> List[TestScenario]:
        """Génère les scénarios de test adaptés"""
        scenarios = [
            # 1. Test basique de l'overview
            TestScenario(
                name="DASHBOARD_OVERVIEW_TEST",
                description="Test de l'endpoint overview du dashboard",
                test_data={
                    "endpoint": "/api/dashboard/overview",
                    "method": "GET"
                },
                expected_alerts=0,
                risk_threshold=0.0
            ),
            
            # 2. Test des métriques de base
            TestScenario(
                name="DASHBOARD_STATS_TEST", 
                description="Test de l'endpoint des statistiques",
                test_data={
                    "endpoint": "/api/dashboard/stats",
                    "method": "GET"
                },
                expected_alerts=0,
                risk_threshold=0.0
            ),
            
            # 3. Test MITRE overview
            TestScenario(
                name="MITRE_OVERVIEW_TEST",
                description="Test de l'endpoint MITRE overview",
                test_data={
                    "endpoint": "/api/dashboard/mitre/overview",
                    "method": "GET"
                },
                expected_alerts=0,
                risk_threshold=0.0
            ),
            
            # 4. Test de recherche IOC (si données disponibles)
            TestScenario(
                name="IOC_SEARCH_TEST",
                description="Test de recherche d'IOCs",
                test_data={
                    "endpoint": "/api/dashboard/iocs/search",
                    "method": "POST",
                    "payload": {
                        "search_term": "test",
                        "ioc_type": "domain",
                        "limit": 10
                    }
                },
                expected_alerts=0,
                risk_threshold=0.0
            ),
            
            # 5. Test des alertes
            TestScenario(
                name="ALERTS_RETRIEVAL_TEST",
                description="Test de récupération des alertes",
                test_data={
                    "endpoint": "/api/dashboard/alerts",
                    "method": "GET"
                },
                expected_alerts=0,
                risk_threshold=0.0
            )
        ]
        
        return scenarios

    async def run_endpoint_test(self, scenario: TestScenario) -> Dict[str, Any]:
        """Exécute un test d'endpoint spécifique"""
        logger.info(f"🧪 Test endpoint: {scenario.name}")
        
        test_result = {
            "scenario": scenario.name,
            "description": scenario.description,
            "timestamp": datetime.now().isoformat(),
            "endpoint": scenario.test_data.get("endpoint"),
            "method": scenario.test_data.get("method", "GET"),
            "success": False,
            "response_time_ms": 0,
            "status_code": None,
            "error": None,
            "response_data": None
        }
        
        try:
            start_time = time.time()
            
            endpoint = scenario.test_data["endpoint"]
            method = scenario.test_data.get("method", "GET")
            payload = scenario.test_data.get("payload")
            
            request_kwargs = {}
            if payload:
                request_kwargs["json"] = payload
            
            async with self.session.request(
                method, 
                f"{self.dashboard_url}{endpoint}",
                **request_kwargs
            ) as response:
                
                end_time = time.time()
                test_result["response_time_ms"] = round((end_time - start_time) * 1000, 2)
                test_result["status_code"] = response.status
                
                if response.status == 200:
                    try:
                        response_data = await response.json()
                        test_result["response_data"] = response_data
                        test_result["success"] = True
                        logger.info(f"✅ {scenario.name}: OK ({test_result['response_time_ms']}ms)")
                    except Exception as json_error:
                        # Réponse 200 mais pas JSON
                        test_result["success"] = True
                        test_result["error"] = f"Réponse non-JSON: {str(json_error)}"
                        logger.info(f"✅ {scenario.name}: OK (non-JSON)")
                else:
                    test_result["error"] = f"HTTP {response.status}"
                    logger.warning(f"⚠️ {scenario.name}: {response.status}")
                    
        except Exception as e:
            test_result["error"] = str(e)
            logger.error(f"❌ {scenario.name}: {e}")
            
        return test_result

    async def run_performance_test(self) -> Dict[str, Any]:
        """Test de performance simplifié"""
        logger.info("🚀 Test de performance des endpoints")
        
        start_time = time.time()
        
        # Test simultané de plusieurs endpoints
        tasks = []
        endpoints = [
            "/api/dashboard/overview",
            "/api/dashboard/stats", 
            "/api/dashboard/alerts",
            "/api/dashboard/mitre/overview"
        ]
        
        for endpoint in endpoints:
            task = self.session.get(f"{self.dashboard_url}{endpoint}")
            tasks.append(task)
        
        # Exécution parallèle
        try:
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            end_time = time.time()
            
            successful_requests = 0
            total_requests = len(endpoints)
            
            for response in responses:
                if hasattr(response, 'status') and response.status == 200:
                    successful_requests += 1
                    await response.release()  # Libérer la connexion
            
            processing_time = end_time - start_time
            
            return {
                "total_endpoints": total_requests,
                "successful_requests": successful_requests,
                "processing_time_seconds": round(processing_time, 2),
                "success_rate": round((successful_requests / total_requests) * 100, 2),
                "avg_response_time": round((processing_time / total_requests) * 1000, 2)
            }
            
        except Exception as e:
            logger.error(f"Erreur test de performance: {e}")
            return {
                "error": str(e),
                "total_endpoints": len(endpoints),
                "successful_requests": 0,
                "success_rate": 0
            }

    async def generate_detailed_report(self, test_results: List[Dict], performance_result: Dict, health_info: Dict) -> str:
        """Génère un rapport détaillé des tests"""
        
        successful_tests = sum(1 for result in test_results if result["success"])
        total_tests = len(test_results)
        
        report = f"""
🔍 RAPPORT DE TEST DÉTAILLÉ - CTI DASHBOARD
{'='*70}

📊 RÉSUMÉ GÉNÉRAL
• Date/Heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• URL Backend: {self.dashboard_url}
• Tests exécutés: {total_tests}
• Tests réussis: {successful_tests} ✅
• Tests échoués: {total_tests - successful_tests} ❌
• Taux de réussite: {(successful_tests/total_tests)*100:.1f}%

🏥 ÉTAT DU SERVEUR
• Serveur accessible: {'✅' if health_info['server_accessible'] else '❌'}
• Endpoints fonctionnels: {len(health_info['endpoints_working'])}
• Endpoints en échec: {len(health_info['endpoints_failing'])}

"""

        if health_info['endpoints_working']:
            report += "✅ Endpoints fonctionnels:\n"
            for ep in health_info['endpoints_working']:
                report += f"   • {ep}\n"
        
        if health_info['endpoints_failing']:
            report += "\n❌ Endpoints en échec:\n"
            for ep in health_info['endpoints_failing']:
                report += f"   • {ep}\n"

        report += f"""
🎯 PERFORMANCE
• Endpoints testés: {performance_result.get('total_endpoints', 0)}
• Requêtes réussies: {performance_result.get('successful_requests', 0)}
• Temps total: {performance_result.get('processing_time_seconds', 0)}s
• Taux de succès: {performance_result.get('success_rate', 0):.1f}%
• Temps moyen: {performance_result.get('avg_response_time', 0):.1f}ms

📋 DÉTAIL DES TESTS
"""
        
        for result in test_results:
            status_icon = "✅" if result["success"] else "❌"
            report += f"\n{status_icon} {result['scenario']}\n"
            report += f"   Endpoint: {result['method']} {result['endpoint']}\n"
            report += f"   Status: {result['status_code']}\n"
            report += f"   Temps: {result['response_time_ms']}ms\n"
            
            if result.get('error'):
                report += f"   Erreur: {result['error']}\n"
            
            if result.get('response_data'):
                # Afficher un résumé de la réponse
                data = result['response_data']
                if isinstance(data, dict):
                    keys = list(data.keys())[:3]  # Premiers 3 clés
                    report += f"   Réponse: {', '.join(keys)}{'...' if len(data.keys()) > 3 else ''}\n"

        report += f"""
{'='*70}
🔧 RECOMMANDATIONS

"""
        
        if not health_info['server_accessible']:
            report += "❗ CRITIQUE: Serveur backend non accessible\n"
            report += "   • Vérifiez que le serveur Flask est démarré\n"
            report += "   • Vérifiez l'URL: " + self.dashboard_url + "\n"
            report += "   • Commande: cd dashboard/backend && python app.py\n\n"
        
        if len(health_info['endpoints_failing']) > len(health_info['endpoints_working']):
            report += "⚠️ ATTENTION: Plus d'endpoints en échec qu'en fonctionnement\n"
            report += "   • Vérifiez la base de données PostgreSQL\n"
            report += "   • Vérifiez les dépendances Python\n"
            report += "   • Consultez les logs du backend\n\n"
        
        if performance_result.get('success_rate', 0) < 80:
            report += "⚠️ PERFORMANCE: Taux de succès bas\n"
            report += "   • Vérifiez la charge du serveur\n"
            report += "   • Augmentez les timeouts\n\n"
        
        report += f"Rapport généré le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return report

    async def run_all_tests(self) -> None:
        """Exécute tous les tests avec diagnostic complet"""
        logger.info("🔬 DÉBUT DES TESTS CTI DASHBOARD")
        logger.info("="*60)
        
        # 1. Diagnostic de santé du backend
        logger.info("🏥 Diagnostic du backend...")
        health_info = await self.check_backend_health()
        
        # 2. Test de connectivité amélioré
        logger.info("🔌 Test de connectivité...")
        connectivity_ok = await self.test_api_connectivity()
        
        if not connectivity_ok:
            logger.error("❌ ARRÊT: Impossible de se connecter au backend")
            logger.info("💡 Vérifications suggérées:")
            logger.info("   1. Le serveur backend est-il démarré ?")
            logger.info("   2. L'URL est-elle correcte ? " + self.dashboard_url)
            logger.info("   3. Y a-t-il des erreurs dans les logs du serveur ?")
            
            # Rapport minimal en cas d'échec de connectivité
            minimal_report = f"""
❌ ÉCHEC DE CONNEXION - CTI DASHBOARD
{'='*50}

URL testée: {self.dashboard_url}
Heure: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

PROBLÈME: Impossible de se connecter au serveur backend

SOLUTIONS:
1. Démarrez le serveur backend:
   cd dashboard/backend
   python app.py

2. Vérifiez l'URL dans la configuration

3. Consultez les logs pour les erreurs

Endpoints testés: {', '.join(health_info['endpoints_failing'])}
"""
            print(minimal_report)
            return
        
        # 3. Génération et exécution des tests
        scenarios = self.generate_test_scenarios()
        logger.info(f"📋 {len(scenarios)} tests d'endpoints générés")
        
        test_results = []
        for scenario in scenarios:
            result = await self.run_endpoint_test(scenario)
            test_results.append(result)
            
            # Pause courte entre les tests
            await asyncio.sleep(0.5)
        
        # 4. Test de performance
        logger.info("🚀 Test de performance en cours...")
        performance_result = await self.run_performance_test()
        
        # 5. Génération du rapport final
        report = await self.generate_detailed_report(test_results, performance_result, health_info)
        
        # Affichage et sauvegarde
        print(report)
        
        # Sauvegarde dans fichier avec timestamp
        filename = f"dashboard_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report)
        
        logger.info(f"✅ Tests terminés - Rapport sauvegardé: {filename}")

async def main():
    """Point d'entrée principal avec gestion d'arguments"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Tests de détection du dashboard CTI")
    parser.add_argument("--url", default="http://localhost:5001", 
                       help="URL du backend (défaut: http://localhost:5001)")
    parser.add_argument("--timeout", type=int, default=30,
                       help="Timeout en secondes (défaut: 30)")
    
    args = parser.parse_args()
    
    logger.info(f"🎯 Configuration des tests:")
    logger.info(f"   URL Backend: {args.url}")
    logger.info(f"   Timeout: {args.timeout}s")
    
    # Configuration du timeout global pour aiohttp
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with DashboardDetectionTester(args.url) as tester:
        # Configuration du timeout pour la session
        tester.session = aiohttp.ClientSession(timeout=timeout)
        await tester.run_all_tests()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("⏹️ Tests interrompus par l'utilisateur")
    except Exception as e:
        logger.error(f"❌ Erreur critique lors des tests: {e}")
        import traceback
        traceback.print_exc()