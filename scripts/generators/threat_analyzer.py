"""
Analyseur de menaces CTI - Intégration avec base de données PostgreSQL
Analyse les données collectées et génère des insights
"""

import json
import os
import re
from datetime import datetime, timedelta
from collections import Counter
import psycopg2
from psycopg2.extras import RealDictCursor
from utils.database import DatabaseManager
from utils.logger import CTILogger

class ThreatAnalyzer:
    def __init__(self, config_path='config/database.json'):
        """Initialise l'analyseur de menaces"""
        self.logger = CTILogger("Threat_Analyzer")
        
        # Initialiser la connexion à la base de données
        try:
            self.db = DatabaseManager(config_path)
            self.logger.info("Connexion à la base de données établie")
        except Exception as e:
            self.logger.error(f"Erreur de connexion à la base : {e}")
            self.db = None
        
        # Classification des menaces
        self.threat_keywords = {
            'ransomware': ['ransomware', 'crypto', 'encrypt', 'ransom', 'lockbit', 'conti', 'maze', 'ryuk'],
            'apt': ['apt', 'advanced persistent', 'nation-state', 'targeted attack', 'lazarus', 'fancy bear'],
            'phishing': ['phishing', 'spear phishing', 'credential', 'social engineering', 'business email'],
            'malware': ['malware', 'trojan', 'virus', 'worm', 'backdoor', 'rat', 'botnet'],
            'vulnerability': ['vulnerability', 'exploit', 'cve', 'zero-day', '0-day', 'rce', 'sql injection'],
            'data_breach': ['data breach', 'leak', 'exposure', 'database', 'credentials', 'personal data'],
            'ddos': ['ddos', 'denial of service', 'amplification', 'botnet attack'],
            'supply_chain': ['supply chain', 'third party', 'vendor compromise', 'solarwinds']
        }
        
        # Secteurs d'activité ciblés
        self.sectors = {
            'healthcare': ['hospital', 'medical', 'health', 'clinic', 'pharmaceutical', 'patient'],
            'finance': ['bank', 'financial', 'payment', 'credit', 'atm', 'swift', 'fintech'],
            'government': ['government', 'public', 'ministry', 'agency', 'municipal', 'embassy'],
            'education': ['university', 'school', 'education', 'academic', 'student', 'research'],
            'industrial': ['manufacturing', 'energy', 'utility', 'oil', 'gas', 'scada', 'ics'],
            'technology': ['software', 'tech', 'cloud', 'saas', 'platform', 'microsoft', 'google'],
            'retail': ['retail', 'e-commerce', 'shopping', 'pos', 'payment card'],
            'transportation': ['airline', 'transport', 'logistics', 'shipping', 'aviation']
        }

    def analyze_threat_landscape(self, days_back=7):
        """Analyse le paysage des menaces depuis la base de données"""
        if not self.db or not self.db.pg_conn:
            self.logger.error("Connexion à la base de données non disponible")
            return {}

        try:
            self.logger.info(f"Début de l'analyse du paysage des menaces ({days_back} derniers jours)")
            
            # Récupérer toutes les données récentes
            recent_data = self._get_recent_threat_data(days_back)
            
            analysis_results = {
                'analysis_period': {
                    'start_date': (datetime.now() - timedelta(days=days_back)).isoformat(),
                    'end_date': datetime.now().isoformat(),
                    'days_analyzed': days_back
                },
                'data_summary': {
                    'total_collected_items': len(recent_data['collected_items']),
                    'total_cves': len(recent_data['cves']),
                    'total_iocs': len(recent_data['iocs']),
                    'total_alerts': len(recent_data['alerts'])
                },
                'threat_categories': self._categorize_threats(recent_data['collected_items']),
                'targeted_sectors': self._identify_sectors(recent_data['collected_items']),
                'cve_analysis': self._analyze_cves(recent_data['cves']),
                'ioc_analysis': self._analyze_iocs_data(recent_data['iocs']),
                'alert_analysis': self._analyze_alerts(recent_data['alerts']),
                'trending_keywords': self._extract_trending_keywords(recent_data['collected_items']),
                'risk_assessment': self._calculate_risk_score(recent_data),
                'temporal_analysis': self._analyze_temporal_patterns(recent_data),
                'source_analysis': self._analyze_sources(recent_data['collected_items']),
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            # Sauvegarder les résultats
            self._save_analysis_results(analysis_results)
            
            self.logger.info("Analyse du paysage des menaces terminée avec succès")
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse : {e}")
            return {}

    def _get_recent_threat_data(self, days_back):
        """Récupère les données récentes de toutes les tables"""
        cursor = self.db.pg_conn.cursor()
        start_date = datetime.now() - timedelta(days=days_back)
        
        data = {
            'collected_items': [],
            'cves': [],
            'iocs': [],
            'alerts': []
        }
        
        # Éléments collectés récents
        cursor.execute("""
            SELECT * FROM collected_items 
            WHERE collected_at >= %s 
            ORDER BY collected_at DESC
        """, (start_date,))
        data['collected_items'] = [dict(row) for row in cursor.fetchall()]
        
        # CVEs récentes
        cursor.execute("""
            SELECT * FROM cves 
            WHERE collected_at >= %s 
            ORDER BY cvss_score DESC, collected_at DESC
        """, (start_date,))
        data['cves'] = [dict(row) for row in cursor.fetchall()]
        
        # IoCs récents
        cursor.execute("""
            SELECT * FROM iocs 
            WHERE first_seen >= %s AND is_active = TRUE
            ORDER BY confidence_score DESC, first_seen DESC
        """, (start_date,))
        data['iocs'] = [dict(row) for row in cursor.fetchall()]
        
        # Alertes récentes
        cursor.execute("""
            SELECT * FROM alerts 
            WHERE created_at >= %s 
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 1 
                    WHEN 'high' THEN 2 
                    WHEN 'medium' THEN 3 
                    ELSE 4 
                END, created_at DESC
        """, (start_date,))
        data['alerts'] = [dict(row) for row in cursor.fetchall()]
        
        return data

    def _categorize_threats(self, collected_items):
        """Catégorise les menaces par type"""
        categories = {category: {'count': 0, 'items': []} for category in self.threat_keywords.keys()}
        
        for item in collected_items:
            text = f"{item.get('title', '')} {item.get('content', '')}".lower()
            
            for category, keywords in self.threat_keywords.items():
                if any(keyword in text for keyword in keywords):
                    categories[category]['count'] += 1
                    categories[category]['items'].append({
                        'id': item['id'],
                        'title': item.get('title', 'Sans titre'),
                        'source': item.get('source_name', 'Inconnu'),
                        'date': item.get('collected_at')
                    })
        
        # Trier par nombre d'occurrences
        return dict(sorted(categories.items(), key=lambda x: x[1]['count'], reverse=True))

    def _identify_sectors(self, collected_items):
        """Identifie les secteurs ciblés"""
        sectors = {sector: {'count': 0, 'items': []} for sector in self.sectors.keys()}
        
        for item in collected_items:
            text = f"{item.get('title', '')} {item.get('content', '')}".lower()
            
            for sector, keywords in self.sectors.items():
                if any(keyword in text for keyword in keywords):
                    sectors[sector]['count'] += 1
                    sectors[sector]['items'].append({
                        'id': item['id'],
                        'title': item.get('title', 'Sans titre'),
                        'source': item.get('source_name', 'Inconnu')
                    })
        
        return dict(sorted(sectors.items(), key=lambda x: x[1]['count'], reverse=True))

    def _analyze_cves(self, cves):
        """Analyse détaillée des CVEs"""
        if not cves:
            return {'total': 0}
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
        cvss_ranges = {'9.0-10.0': 0, '7.0-8.9': 0, '4.0-6.9': 0, '0.0-3.9': 0, 'unknown': 0}
        
        critical_cves = []
        trending_products = Counter()
        
        for cve in cves:
            # Analyse par sévérité
            severity = cve.get('severity', 'unknown').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['unknown'] += 1
            
            # Analyse par score CVSS
            cvss = cve.get('cvss_score')
            if cvss is not None:
                if cvss >= 9.0:
                    cvss_ranges['9.0-10.0'] += 1
                elif cvss >= 7.0:
                    cvss_ranges['7.0-8.9'] += 1
                elif cvss >= 4.0:
                    cvss_ranges['4.0-6.9'] += 1
                else:
                    cvss_ranges['0.0-3.9'] += 1
            else:
                cvss_ranges['unknown'] += 1
            
            # CVEs critiques
            if cvss and cvss >= 9.0:
                critical_cves.append({
                    'cve_id': cve['cve_id'],
                    'cvss_score': cvss,
                    'description': cve.get('description', '')[:200],
                    'affected_products': cve.get('affected_products', [])
                })
            
            # Produits affectés
            if cve.get('affected_products'):
                for product in cve['affected_products']:
                    trending_products[product] += 1
        
        return {
            'total': len(cves),
            'severity_distribution': severity_counts,
            'cvss_distribution': cvss_ranges,
            'critical_cves': sorted(critical_cves, key=lambda x: x['cvss_score'], reverse=True)[:10],
            'most_affected_products': dict(trending_products.most_common(10))
        }

    def _analyze_iocs_data(self, iocs):
        """Analyse des indicateurs de compromission"""
        if not iocs:
            return {'total': 0}
        
        ioc_types = Counter()
        confidence_ranges = {'high': 0, 'medium': 0, 'low': 0}  # >0.7, 0.3-0.7, <0.3
        
        high_confidence_iocs = []
        
        for ioc in iocs:
            # Types d'IoCs
            ioc_types[ioc.get('ioc_type', 'unknown')] += 1
            
            # Niveaux de confiance
            confidence = ioc.get('confidence_score', 0)
            if confidence >= 0.7:
                confidence_ranges['high'] += 1
                high_confidence_iocs.append({
                    'type': ioc['ioc_type'],
                    'value': ioc['ioc_value'][:100],  # Limiter la taille
                    'confidence': confidence,
                    'first_seen': ioc.get('first_seen')
                })
            elif confidence >= 0.3:
                confidence_ranges['medium'] += 1
            else:
                confidence_ranges['low'] += 1
        
        return {
            'total': len(iocs),
            'type_distribution': dict(ioc_types),
            'confidence_distribution': confidence_ranges,
            'high_confidence_iocs': sorted(high_confidence_iocs, 
                                         key=lambda x: x['confidence'], reverse=True)[:20]
        }

    def _analyze_alerts(self, alerts):
        """Analyse des alertes"""
        if not alerts:
            return {'total': 0}
        
        severity_counts = Counter()
        alert_types = Counter()
        unresolved_count = 0
        
        critical_alerts = []
        
        for alert in alerts:
            severity_counts[alert.get('severity', 'unknown')] += 1
            alert_types[alert.get('alert_type', 'unknown')] += 1
            
            if not alert.get('is_resolved', False):
                unresolved_count += 1
                
                if alert.get('severity') in ['critical', 'high']:
                    critical_alerts.append({
                        'id': alert['id'],
                        'title': alert.get('title', 'Sans titre'),
                        'severity': alert.get('severity'),
                        'created_at': alert.get('created_at')
                    })
        
        return {
            'total': len(alerts),
            'severity_distribution': dict(severity_counts),
            'type_distribution': dict(alert_types),
            'unresolved_count': unresolved_count,
            'resolution_rate': ((len(alerts) - unresolved_count) / len(alerts) * 100) if alerts else 0,
            'critical_unresolved': sorted(critical_alerts, 
                                        key=lambda x: x['created_at'], reverse=True)[:10]
        }

    def _extract_trending_keywords(self, collected_items, top_n=20):
        """Extrait les mots-clés tendance"""
        all_text = ""
        
        for item in collected_items:
            title = item.get('title', '')
            content = item.get('content', '')
            all_text += f" {title} {content}"
        
        # Nettoyage et extraction
        words = re.findall(r'\b[a-zA-Z]{4,}\b', all_text.lower())
        
        # Filtrer les mots communs
        stop_words = {
            'this', 'that', 'with', 'have', 'will', 'from', 'they', 'been', 'said', 
            'each', 'which', 'their', 'more', 'like', 'into', 'over', 'such', 'when',
            'after', 'before', 'through', 'during', 'about', 'against', 'security',
            'threat', 'attack', 'malware', 'vulnerability', 'data', 'system'
        }
        
        filtered_words = [word for word in words if word not in stop_words and len(word) > 4]
        word_counts = Counter(filtered_words)
        
        return dict(word_counts.most_common(top_n))

    def _calculate_risk_score(self, data):
        """Calcule un score de risque global"""
        risk_factors = {
            'critical_cves': 0,
            'high_confidence_iocs': 0,
            'unresolved_alerts': 0,
            'apt_activity': 0,
            'ransomware_activity': 0
        }
        
        # CVEs critiques
        critical_cves = [c for c in data['cves'] if c.get('cvss_score', 0) >= 9.0]
        risk_factors['critical_cves'] = len(critical_cves) * 10
        
        # IoCs haute confiance
        high_conf_iocs = [i for i in data['iocs'] if i.get('confidence_score', 0) >= 0.8]
        risk_factors['high_confidence_iocs'] = len(high_conf_iocs) * 5
        
        # Alertes non résolues
        unresolved = [a for a in data['alerts'] if not a.get('is_resolved', False)]
        risk_factors['unresolved_alerts'] = len(unresolved) * 3
        
        # Activité APT et ransomware
        for item in data['collected_items']:
            text = f"{item.get('title', '')} {item.get('content', '')}".lower()
            if any(keyword in text for keyword in self.threat_keywords['apt']):
                risk_factors['apt_activity'] += 8
            if any(keyword in text for keyword in self.threat_keywords['ransomware']):
                risk_factors['ransomware_activity'] += 6
        
        total_score = sum(risk_factors.values())
        
        # Normalisation (0-100)
        normalized_score = min(100, total_score)
        
        if normalized_score >= 80:
            risk_level = 'critical'
        elif normalized_score >= 60:
            risk_level = 'high'
        elif normalized_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'overall_score': normalized_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendations': self._get_risk_recommendations(risk_level, risk_factors)
        }

    def _get_risk_recommendations(self, risk_level, risk_factors):
        """Génère des recommandations basées sur le niveau de risque"""
        recommendations = []
        
        if risk_factors['critical_cves'] > 0:
            recommendations.append("Appliquer immédiatement les correctifs pour les CVEs critiques")
        
        if risk_factors['high_confidence_iocs'] > 0:
            recommendations.append("Intégrer les IoCs haute confiance dans les solutions de défense")
        
        if risk_factors['unresolved_alerts'] > 0:
            recommendations.append("Résoudre les alertes en attente, priorité aux alertes critiques")
        
        if risk_factors['apt_activity'] > 0:
            recommendations.append("Renforcer la surveillance contre les menaces persistantes avancées")
        
        if risk_factors['ransomware_activity'] > 0:
            recommendations.append("Vérifier les sauvegardes et mettre à jour les procédures anti-ransomware")
        
        # Recommandations générales selon le niveau
        if risk_level == 'critical':
            recommendations.append("Activer le centre de crise et notifier la direction")
        elif risk_level == 'high':
            recommendations.append("Augmenter le niveau de surveillance et alerter les équipes SOC")
        
        return recommendations

    def _analyze_temporal_patterns(self, data):
        """Analyse les patterns temporels"""
        patterns = {
            'daily_distribution': Counter(),
            'hourly_distribution': Counter(),
            'weekly_distribution': Counter()
        }
        
        for item in data['collected_items']:
            if item.get('collected_at'):
                dt = item['collected_at']
                if isinstance(dt, str):
                    dt = datetime.fromisoformat(dt.replace('Z', '+00:00'))
                
                patterns['daily_distribution'][dt.strftime('%Y-%m-%d')] += 1
                patterns['hourly_distribution'][dt.strftime('%H')] += 1
                patterns['weekly_distribution'][dt.strftime('%A')] += 1
        
        return {k: dict(v) for k, v in patterns.items()}

    def _analyze_sources(self, collected_items):
        """Analyse la répartition par sources"""
        source_stats = Counter()
        source_quality = {}
        
        for item in collected_items:
            source = item.get('source_name', 'Unknown')
            source_stats[source] += 1
            
            # Évaluation qualitative simple
            if source not in source_quality:
                source_quality[source] = {'items': 0, 'avg_content_length': 0}
            
            source_quality[source]['items'] += 1
            content_length = len(item.get('content', ''))
            source_quality[source]['avg_content_length'] = (
                (source_quality[source]['avg_content_length'] * (source_quality[source]['items'] - 1) + content_length) 
                / source_quality[source]['items']
            )
        
        return {
            'source_distribution': dict(source_stats),
            'top_sources': dict(source_stats.most_common(10)),
            'source_quality_metrics': source_quality
        }

    def _save_analysis_results(self, results):
        """Sauvegarde les résultats d'analyse"""
        # Créer le dossier de sortie
        output_dir = "output/analysis_results"
        os.makedirs(output_dir, exist_ok=True)
        
        # Fichier JSON détaillé
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_file = os.path.join(output_dir, f"threat_landscape_analysis_{timestamp}.json")
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        # Fichier résumé
        summary_file = os.path.join(output_dir, f"analysis_summary_{timestamp}.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"=== ANALYSE PAYSAGE DES MENACES ===\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Période: {results['analysis_period']['days_analyzed']} jours\n\n")
            
            f.write(f"RÉSUMÉ:\n")
            f.write(f"- Éléments collectés: {results['data_summary']['total_collected_items']}\n")
            f.write(f"- CVEs: {results['data_summary']['total_cves']}\n")
            f.write(f"- IoCs: {results['data_summary']['total_iocs']}\n")
            f.write(f"- Alertes: {results['data_summary']['total_alerts']}\n\n")
            
            f.write(f"NIVEAU DE RISQUE: {results['risk_assessment']['risk_level'].upper()}\n")
            f.write(f"Score: {results['risk_assessment']['overall_score']}/100\n\n")
            
            f.write("RECOMMANDATIONS:\n")
            for i, rec in enumerate(results['risk_assessment']['recommendations'], 1):
                f.write(f"{i}. {rec}\n")
        
        self.logger.info(f"Résultats sauvegardés: {json_file}")

    def generate_executive_summary(self, analysis_results):
        """Génère un résumé exécutif"""
        if not analysis_results:
            return "Aucune donnée disponible pour l'analyse."
        
        summary_parts = []
        
        # En-tête
        period = analysis_results.get('analysis_period', {})
        summary_parts.append(
            f"Analyse du paysage des menaces sur {period.get('days_analyzed', 'N/A')} jours "
            f"(du {period.get('start_date', 'N/A')} au {period.get('end_date', 'N/A')})."
        )
        
        # Données générales
        data_summary = analysis_results.get('data_summary', {})
        summary_parts.append(
            f"Au total, {data_summary.get('total_collected_items', 0)} éléments ont été collectés, "
            f"incluant {data_summary.get('total_cves', 0)} CVEs, "
            f"{data_summary.get('total_iocs', 0)} indicateurs de compromission, "
            f"et {data_summary.get('total_alerts', 0)} alertes."
        )
        
        # Niveau de risque
        risk_assessment = analysis_results.get('risk_assessment', {})
        risk_level = risk_assessment.get('risk_level', 'unknown')
        risk_score = risk_assessment.get('overall_score', 0)
        
        summary_parts.append(
            f"Le niveau de risque global est évalué comme {risk_level.upper()} "
            f"avec un score de {risk_score}/100."
        )
        
        # Menaces principales
        threat_categories = analysis_results.get('threat_categories', {})
        if threat_categories:
            top_threat = max(threat_categories.items(), key=lambda x: x[1]['count'])
            summary_parts.append(
                f"La catégorie de menace la plus prévalente est '{top_threat[0]}' "
                f"avec {top_threat[1]['count']} occurrences."
            )
        
        # CVEs critiques
        cve_analysis = analysis_results.get('cve_analysis', {})
        if cve_analysis.get('critical_cves'):
            critical_count = len(cve_analysis['critical_cves'])
            summary_parts.append(
                f"⚠️ {critical_count} CVE(s) critique(s) (CVSS ≥ 9.0) nécessitent une attention immédiate."
            )
        
        return " ".join(summary_parts)

# Fonction utilitaire pour exécution standalone
def main():
    """Fonction principale pour exécution directe"""
    try:
        analyzer = ThreatAnalyzer()
        
        # Lancer l'analyse (par défaut 7 derniers jours)
        results = analyzer.analyze_threat_landscape(days_back=7)
        
        if results:
            print("=== ANALYSE TERMINÉE ===")
            print(f"Éléments analysés: {results['data_summary']['total_collected_items']}")
            print(f"Niveau de risque: {results['risk_assessment']['risk_level'].upper()}")
            print(f"Score: {results['risk_assessment']['overall_score']}/100")
            
            # Afficher le résumé exécutif
            summary = analyzer.generate_executive_summary(results)
            print(f"\nRÉSUMÉ EXÉCUTIF:\n{summary}")
            
        else:
            print("Aucun résultat d'analyse disponible")
            
    except Exception as e:
        print(f"Erreur lors de l'exécution: {e}")

if __name__ == "__main__":
    main()