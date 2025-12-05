
"""
Risk Calculator pour l'analyse CTI
Version corrigée sans importation circulaire
"""

import psycopg2
import psycopg2.extras
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Union
from enum import Enum
import logging
import math

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Niveaux de risque standardisés"""
    LOW = "LOW"
    MEDIUM = "MEDIUM" 
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskScore:
    """Classe pour représenter un score de risque calculé"""
    
    def __init__(self, score: float, level: RiskLevel, confidence: float, 
                 factors: Dict = None, recommendations: List[str] = None):
        self.score = max(0.0, min(10.0, score))  # Score entre 0 et 10
        self.level = level
        self.confidence = max(0.0, min(1.0, confidence))  # Confiance entre 0 et 1
        self.factors = factors or {}
        self.recommendations = recommendations or []
    
    def __repr__(self):
        return f"RiskScore(score={self.score:.2f}, level={self.level.value}, confidence={self.confidence:.2f})"


class RiskCalculator:
    """Calculateur de risque pour CVEs et IoCs"""
    
    def __init__(self):
        self.cve_weights = {
            'cvss_score': 0.35,
            'exploits': 0.25,
            'age': 0.15,
            'affected_products': 0.10,
            'patch_available': 0.15
        }
        
        self.ioc_weights = {
            'reputation': 0.30,
            'confidence': 0.25,
            'age': 0.20,
            'source_reliability': 0.15,
            'threat_types': 0.10
        }
    
    def calculate_cve_risk(self, cve_data: Dict, context: Dict = None) -> RiskScore:
        """
        Calcule le risque d'une CVE
        
        Args:
            cve_data: Données de la CVE
            context: Contexte organisationnel
        """
        try:
            factors = {}
            total_score = 0.0
            
            # 1. Score CVSS (0-10)
            cvss_score = float(cve_data.get('cvss_score', 0))
            cvss_factor = cvss_score / 10.0
            factors['cvss_normalized'] = cvss_factor
            total_score += cvss_factor * self.cve_weights['cvss_score']
            
            # 2. Disponibilité d'exploits
            exploits = cve_data.get('exploits', [])
            exploit_factor = 0.0
            if exploits:
                # Plus d'exploits = risque plus élevé
                exploit_factor = min(1.0, len(exploits) * 0.3 + 0.4)
                
                # Type d'exploit
                for exploit in exploits:
                    if exploit.get('type') == 'public':
                        exploit_factor = min(1.0, exploit_factor + 0.3)
                    elif exploit.get('type') == 'weaponized':
                        exploit_factor = 1.0
                        break
            
            factors['exploit_availability'] = exploit_factor
            total_score += exploit_factor * self.cve_weights['exploits']
            
            # 3. Âge de la CVE
            pub_date = cve_data.get('published_date')
            age_factor = 0.0
            if pub_date:
                if isinstance(pub_date, str):
                    pub_date = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                
                days_old = (datetime.now() - pub_date.replace(tzinfo=None)).days
                
                # Plus c'est récent, plus c'est risqué (0-90 jours)
                if days_old <= 7:
                    age_factor = 1.0  # Très récent
                elif days_old <= 30:
                    age_factor = 0.8  # Récent
                elif days_old <= 90:
                    age_factor = 0.6  # Moyennement récent
                else:
                    age_factor = 0.3  # Ancien
            
            factors['age_factor'] = age_factor
            total_score += age_factor * self.cve_weights['age']
            
            # 4. Produits affectés
            affected_products = cve_data.get('affected_products', [])
            product_factor = 0.0
            if affected_products:
                # Plus de produits = plus de risque
                product_factor = min(1.0, len(affected_products) * 0.2)
                
                # Produits critiques (à adapter selon votre environnement)
                critical_products = ['windows', 'linux', 'apache', 'nginx', 'mysql', 'postgresql']
                for product in affected_products:
                    if any(cp in product.lower() for cp in critical_products):
                        product_factor = min(1.0, product_factor + 0.3)
            
            factors['affected_products_factor'] = product_factor
            total_score += product_factor * self.cve_weights['affected_products']
            
            # 5. Disponibilité du patch
            patch_available = cve_data.get('patch_available', False)
            patch_factor = 0.7 if not patch_available else 0.3  # Pas de patch = plus risqué
            factors['patch_factor'] = patch_factor
            total_score += patch_factor * self.cve_weights['patch_available']
            
            # Application du contexte organisationnel
            if context:
                context_multiplier = self._calculate_context_multiplier(context)
                total_score *= context_multiplier
                factors['context_multiplier'] = context_multiplier
            
            # Normalisation du score (0-10)
            final_score = total_score * 10.0
            
            # Détermination du niveau de risque
            risk_level = self._determine_risk_level(final_score)
            
            # Calcul de la confiance
            confidence = self._calculate_cve_confidence(cve_data, factors)
            
            # Génération des recommandations
            recommendations = self._generate_cve_recommendations(cve_data, factors, risk_level)
            
            return RiskScore(final_score, risk_level, confidence, factors, recommendations)
            
        except Exception as e:
            logger.error(f"Erreur dans le calcul du risque CVE: {e}")
            return RiskScore(5.0, RiskLevel.MEDIUM, 0.5, {}, ["Erreur de calcul - révision manuelle requise"])
    
    def calculate_ioc_risk(self, ioc_data: Dict) -> RiskScore:
        """
        Calcule le risque d'un IoC/Indicator
        
        Args:
            ioc_data: Données de l'IoC
        """
        try:
            factors = {}
            total_score = 0.0
            
            # 1. Réputation
            reputation = ioc_data.get('reputation', 'unknown').lower()
            reputation_scores = {
                'malicious': 1.0,
                'suspicious': 0.7,
                'unknown': 0.3,
                'clean': 0.1
            }
            reputation_factor = reputation_scores.get(reputation, 0.3)
            factors['reputation_factor'] = reputation_factor
            total_score += reputation_factor * self.ioc_weights['reputation']
            
            # 2. Niveau de confiance
            confidence_level = float(ioc_data.get('confidence', 0.5))
            factors['confidence_level'] = confidence_level
            total_score += confidence_level * self.ioc_weights['confidence']
            
            # 3. Âge de l'IoC
            last_seen = ioc_data.get('last_seen')
            age_factor = 0.5  # Valeur par défaut
            
            if last_seen:
                if isinstance(last_seen, str):
                    last_seen = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                
                days_since_seen = (datetime.now() - last_seen.replace(tzinfo=None)).days
                
                # Plus c'est récent, plus c'est risqué
                if days_since_seen <= 1:
                    age_factor = 1.0  # Très récent
                elif days_since_seen <= 7:
                    age_factor = 0.8  # Récent
                elif days_since_seen <= 30:
                    age_factor = 0.6  # Moyennement récent
                elif days_since_seen <= 90:
                    age_factor = 0.4  # Ancien
                else:
                    age_factor = 0.2  # Très ancien
            
            factors['age_factor'] = age_factor
            total_score += age_factor * self.ioc_weights['age']
            
            # 4. Fiabilité de la source
            source_type = ioc_data.get('source_type', 'unknown').lower()
            source_reliability = {
                'gov_cert': 0.9,
                'commercial_feed': 0.8,
                'threat_intel': 0.7,
                'open_source': 0.6,
                'community': 0.5,
                'social_media': 0.3,
                'unknown': 0.3
            }
            source_factor = source_reliability.get(source_type, 0.3)
            factors['source_reliability'] = source_factor
            total_score += source_factor * self.ioc_weights['source_reliability']
            
            # 5. Types de menaces
            threat_types = ioc_data.get('threat_types', [])
            threat_factor = 0.3  # Valeur de base
            
            if threat_types:
                high_risk_threats = ['malware', 'ransomware', 'apt', 'botnet', 'c2']
                medium_risk_threats = ['phishing', 'spam', 'suspicious']
                
                for threat_type in threat_types:
                    if threat_type.lower() in high_risk_threats:
                        threat_factor = min(1.0, threat_factor + 0.4)
                    elif threat_type.lower() in medium_risk_threats:
                        threat_factor = min(1.0, threat_factor + 0.2)
            
            factors['threat_types_factor'] = threat_factor
            total_score += threat_factor * self.ioc_weights['threat_types']
            
            # Normalisation du score (0-10)
            final_score = total_score * 10.0
            
            # Détermination du niveau de risque
            risk_level = self._determine_risk_level(final_score)
            
            # Calcul de la confiance globale
            confidence = self._calculate_ioc_confidence(ioc_data, factors)
            
            # Génération des recommandations
            recommendations = self._generate_ioc_recommendations(ioc_data, factors, risk_level)
            
            return RiskScore(final_score, risk_level, confidence, factors, recommendations)
            
        except Exception as e:
            logger.error(f"Erreur dans le calcul du risque IoC: {e}")
            return RiskScore(5.0, RiskLevel.MEDIUM, 0.5, {}, ["Erreur de calcul - révision manuelle requise"])
    
    def _calculate_context_multiplier(self, context: Dict) -> float:
        """Calcule un multiplicateur basé sur le contexte organisationnel"""
        multiplier = 1.0
        
        # Asset critique
        if context.get('critical_asset', False):
            multiplier *= 1.3
        
        # Exposition Internet
        if context.get('internet_facing', False):
            multiplier *= 1.2
        
        # Impact business
        business_impact = context.get('business_impact', 'medium').lower()
        impact_multipliers = {'low': 0.9, 'medium': 1.0, 'high': 1.2, 'critical': 1.4}
        multiplier *= impact_multipliers.get(business_impact, 1.0)
        
        # Paysage des menaces
        threat_landscape = context.get('threat_landscape', 'standard').lower()
        threat_multipliers = {'low': 0.8, 'standard': 1.0, 'elevated': 1.2, 'advanced': 1.4}
        multiplier *= threat_multipliers.get(threat_landscape, 1.0)
        
        return min(2.0, multiplier)  # Cap à 2.0 pour éviter les scores extrêmes
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Détermine le niveau de risque basé sur le score"""
        if score >= 8.5:
            return RiskLevel.CRITICAL
        elif score >= 6.5:
            return RiskLevel.HIGH
        elif score >= 4.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _calculate_cve_confidence(self, cve_data: Dict, factors: Dict) -> float:
        """Calcule la confiance du score CVE"""
        confidence = 0.8  # Base
        
        # CVSS disponible
        if cve_data.get('cvss_score', 0) > 0:
            confidence += 0.1
        
        # Exploits documentés
        if cve_data.get('exploits'):
            confidence += 0.1
        
        # Date de publication disponible
        if cve_data.get('published_date'):
            confidence += 0.05
        
        return min(1.0, confidence)
    
    def _calculate_ioc_confidence(self, ioc_data: Dict, factors: Dict) -> float:
        """Calcule la confiance du score IoC"""
        confidence = 0.7  # Base
        
        # Source fiable
        if factors.get('source_reliability', 0) > 0.7:
            confidence += 0.2
        
        # Confiance de l'indicateur élevée
        if ioc_data.get('confidence', 0) > 0.7:
            confidence += 0.1
        
        # Récent
        if factors.get('age_factor', 0) > 0.6:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _generate_cve_recommendations(self, cve_data: Dict, factors: Dict, risk_level: RiskLevel) -> List[str]:
        """Génère des recommandations pour une CVE"""
        recommendations = []
        
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("🚨 Priorité élevée - Appliquer les correctifs immédiatement")
            
            if factors.get('exploit_availability', 0) > 0.5:
                recommendations.append("⚠️ Exploits publics disponibles - Surveillance renforcée requise")
            
            if factors.get('patch_factor', 0) > 0.5:
                recommendations.append("🔧 Aucun patch disponible - Mettre en place des mesures compensatoires")
        
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append("📋 Planifier l'application des correctifs dans les prochains cycles")
            
        else:  # LOW
            recommendations.append("📅 Surveiller et inclure dans la maintenance régulière")
        
        # Recommandations spécifiques
        cvss = cve_data.get('cvss_score', 0)
        if cvss >= 9.0:
            recommendations.append("🔥 Score CVSS critique - Intervention d'urgence recommandée")
        
        return recommendations
    
    def _generate_ioc_recommendations(self, ioc_data: Dict, factors: Dict, risk_level: RiskLevel) -> List[str]:
        """Génère des recommandations pour un IoC"""
        recommendations = []
        
        if risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("🚫 Bloquer immédiatement sur tous les systèmes de sécurité")
            recommendations.append("🔍 Lancer une chasse aux menaces pour détecter d'éventuelles compromissions")
            
            if 'malware' in ioc_data.get('threat_types', []):
                recommendations.append("🦠 Analyser les échantillons de malware associés")
        
        elif risk_level == RiskLevel.MEDIUM:
            recommendations.append("⚠️ Ajouter à la surveillance et aux alertes")
            recommendations.append("📊 Monitor le trafic réseau associé")
            
        else:  # LOW
            recommendations.append("📝 Ajouter à la liste de veille pour surveillance passive")
        
        # Recommandations par type
        ioc_type = ioc_data.get('type', '').lower()
        if ioc_type == 'ip':
            recommendations.append("🌐 Vérifier les connexions réseau vers cette adresse IP")
        elif ioc_type == 'domain':
            recommendations.append("🔗 Bloquer au niveau DNS et proxy")
        elif ioc_type == 'hash':
            recommendations.append("🔐 Scanner les systèmes pour ce hash de fichier")
        
        return recommendations


class PostgreSQLRiskManager:
    """Gestionnaire de risques intégré avec PostgreSQL"""
    
    def __init__(self, db_config: Dict):
        """
        db_config = {
            'host': 'localhost',
            'database': 'cti_db',
            'user': 'your_user',
            'password': 'your_password',
            'port': 5432
        }
        """
        self.db_config = db_config
        self.risk_calculator = RiskCalculator()
        self.init_risk_tables()
    
    def get_connection(self):
        """Crée une connexion PostgreSQL"""
        return psycopg2.connect(**self.db_config)
    
    def init_risk_tables(self):
        """Initialise les tables pour stocker les scores de risque"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Table pour les scores de risque des CVEs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cve_risk_scores (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR UNIQUE NOT NULL,
                risk_score REAL NOT NULL,
                risk_level VARCHAR NOT NULL,
                confidence REAL NOT NULL,
                calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                factors JSONB,
                recommendations JSONB,
                context_hash VARCHAR,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
        """)
        
        # Table pour les scores de risque des IoCs/Indicators
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS indicator_risk_scores (
                id SERIAL PRIMARY KEY,
                indicator_value TEXT NOT NULL,
                indicator_type VARCHAR NOT NULL,
                risk_score REAL NOT NULL,
                risk_level VARCHAR NOT NULL,
                confidence REAL NOT NULL,
                calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                factors JSONB,
                recommendations JSONB,
                UNIQUE(indicator_value, indicator_type)
            )
        """)
        
        # Table pour l'historique des calculs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS risk_calculation_history (
                id SERIAL PRIMARY KEY,
                item_type VARCHAR NOT NULL,
                item_id VARCHAR NOT NULL,
                old_risk_score REAL,
                new_risk_score REAL,
                old_risk_level VARCHAR,
                new_risk_level VARCHAR,
                change_reason VARCHAR,
                calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Index pour les performances
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_risk_level ON cve_risk_scores(risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_indicator_risk_level ON indicator_risk_scores(risk_level)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_risk_calculated_at ON cve_risk_scores(calculated_at)")
        
        conn.commit()
        cursor.close()
        conn.close()
    
    def calculate_and_store_cve_risks(self, context: Optional[Dict] = None, batch_size: int = 100):
        """Calcule et stocke les risques pour toutes les CVEs en base"""
        conn = self.get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer toutes les CVEs de votre table
        cursor.execute("""
            SELECT cve_id, cvss_score, published_date, description, 
                   affected_products, cve_references, severity, metadata
            FROM cves 
            WHERE cve_id IS NOT NULL
        """)
        
        cves = cursor.fetchall()
        processed = 0
        
        print(f"🔄 Calcul des risques pour {len(cves)} CVEs...")
        
        for cve_row in cves:
            try:
                # Transformation des données DB vers format risk calculator
                cve_data = self._transform_cve_from_postgres(dict(cve_row))
                
                # Calcul du risque
                risk_score = self.risk_calculator.calculate_cve_risk(cve_data, context)
                
                # Stockage en base
                self._store_cve_risk(cve_data['cve_id'], risk_score, context)
                
                processed += 1
                if processed % batch_size == 0:
                    print(f"   ✅ {processed}/{len(cves)} CVEs traitées...")
                    
            except Exception as e:
                print(f"   ❌ Erreur pour {cve_row['cve_id']}: {e}")
                continue
        
        cursor.close()
        conn.close()
        print(f"✅ Terminé ! {processed} CVEs traitées avec succès.")
    
    def calculate_and_store_indicator_risks(self, batch_size: int = 200):
        """Calcule et stocke les risques pour tous les Indicators en base"""
        conn = self.get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        # Récupérer tous les indicators de votre table
        cursor.execute("""
            SELECT indicator_value, indicator_type, confidence_level, 
                   first_seen, last_seen, source, malware_family, tags, description
            FROM indicators 
            WHERE indicator_value IS NOT NULL AND processed = true
        """)
        
        indicators = cursor.fetchall()
        processed = 0
        
        print(f"🔄 Calcul des risques pour {len(indicators)} Indicators...")
        
        for indicator_row in indicators:
            try:
                # Transformation des données
                indicator_data = self._transform_indicator_from_postgres(dict(indicator_row))
                
                # Calcul du risque
                risk_score = self.risk_calculator.calculate_ioc_risk(indicator_data)
                
                # Stockage
                self._store_indicator_risk(indicator_data, risk_score)
                
                processed += 1
                if processed % batch_size == 0:
                    print(f"   ✅ {processed}/{len(indicators)} Indicators traités...")
                    
            except Exception as e:
                print(f"   ❌ Erreur pour {indicator_row['indicator_value']}: {e}")
                continue
        
        cursor.close()
        conn.close()
        print(f"✅ Terminé ! {processed} Indicators traités avec succès.")
    
    def _transform_cve_from_postgres(self, cve_row: Dict) -> Dict:
        """Transforme une ligne PostgreSQL en format CVE pour le risk calculator"""
        
        # Gestion des arrays PostgreSQL
        affected_products = cve_row.get('affected_products', []) or []
        if isinstance(affected_products, str):
            affected_products = [affected_products]
        
        cve_references = cve_row.get('cve_references', []) or []
        if isinstance(cve_references, str):
            cve_references = [cve_references]
        
        # Détection des exploits dans les références ou métadonnées
        exploits = []
        metadata = cve_row.get('metadata', {}) or {}
        
        # Recherche d'exploits dans les références
        for ref in cve_references:
            if any(keyword in ref.lower() for keyword in ['exploit', 'poc', 'metasploit', 'exploit-db']):
                exploits.append({'url': ref, 'type': 'public'})
        
        # Vérification de la disponibilité de patch (basé sur l'âge et les métadonnées)
        pub_date = cve_row.get('published_date')
        patch_available = False
        if pub_date:
            days_since_pub = (datetime.now() - pub_date).days
            patch_available = days_since_pub > 30  # Estimation simple
        
        return {
            'cve_id': cve_row['cve_id'],
            'cvss_score': float(cve_row.get('cvss_score', 0)) if cve_row.get('cvss_score') else 0.0,
            'published_date': cve_row.get('published_date'),
            'description': cve_row.get('description', ''),
            'affected_products': affected_products,
            'exploits': exploits,
            'patch_available': patch_available,
            'references': cve_references,
            'severity': cve_row.get('severity', 'UNKNOWN')
        }
    
    def _transform_indicator_from_postgres(self, indicator_row: Dict) -> Dict:
        """Transforme une ligne PostgreSQL en format IoC pour le risk calculator"""
        
        # Mapping des types d'indicators
        type_mapping = {
            'ip': 'ip',
            'domain': 'domain', 
            'url': 'url',
            'hash': 'hash',
            'email': 'email'
        }
        
        indicator_type = indicator_row.get('indicator_type', '').lower()
        mapped_type = type_mapping.get(indicator_type, indicator_type)
        
        # Calcul de reputation basé sur confidence_level et malware_family
        confidence = float(indicator_row.get('confidence_level', 50)) / 100.0
        malware = indicator_row.get('malware_family')
        
        # Reputation: malicious si malware détecté, sinon basé sur confidence
        if malware:
            reputation = 'malicious'
        elif confidence > 0.7:
            reputation = 'suspicious'
        else:
            reputation = 'unknown'
        
        # Extraction des threat_types depuis tags
        tags = indicator_row.get('tags', {}) or {}
        threat_types = []
        
        if isinstance(tags, dict):
            threat_types = list(tags.keys())[:5]  # Limiter à 5 types
        
        if malware:
            threat_types.append('malware')
        
        return {
            'value': indicator_row['indicator_value'],
            'type': mapped_type,
            'reputation': reputation,
            'confidence': confidence,
            'first_seen': indicator_row.get('first_seen'),
            'last_seen': indicator_row.get('last_seen'),
            'source_type': self._map_source_type(indicator_row.get('source', '')),
            'threat_types': threat_types,
            'malware_family': malware
        }
    
    def _map_source_type(self, source: str) -> str:
        """Mappe les sources vers les types reconnus par le risk calculator"""
        source_mapping = {
            'otx': 'open_source',
            'alienvault': 'open_source',
            'virustotal': 'commercial_feed',
            'shodan': 'commercial_feed',
            'abuseipdb': 'community',
            'cert': 'gov_cert',
            'twitter': 'social_media',
            'telegram': 'social_media'
        }
        return source_mapping.get(source.lower(), 'unknown')
    
    def _store_cve_risk(self, cve_id: str, risk_score, context: Optional[Dict]):
        """Stocke le score de risque d'une CVE"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Hash du contexte pour détecter les changements
        context_hash = str(hash(str(sorted(context.items())))) if context else None
        
        # Vérifier si un score existe déjà
        cursor.execute("SELECT risk_score, risk_level FROM cve_risk_scores WHERE cve_id = %s", (cve_id,))
        existing = cursor.fetchone()
        
        # Insérer ou mettre à jour
        cursor.execute("""
            INSERT INTO cve_risk_scores 
            (cve_id, risk_score, risk_level, confidence, factors, recommendations, context_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve_id) DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                confidence = EXCLUDED.confidence,
                factors = EXCLUDED.factors,
                recommendations = EXCLUDED.recommendations,
                context_hash = EXCLUDED.context_hash,
                calculated_at = CURRENT_TIMESTAMP
        """, (
            cve_id,
            risk_score.score,
            risk_score.level.value,
            risk_score.confidence,
            json.dumps(risk_score.factors),
            json.dumps(risk_score.recommendations),
            context_hash
        ))
        
        # Historique si changement significatif
        if existing and abs(existing[0] - risk_score.score) > 0.5:
            cursor.execute("""
                INSERT INTO risk_calculation_history 
                (item_type, item_id, old_risk_score, new_risk_score, old_risk_level, new_risk_level, change_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                'cve', cve_id, existing[0], risk_score.score, 
                existing[1], risk_score.level.value, 'recalculation'
            ))
        
        conn.commit()
        cursor.close()
        conn.close()
    
    def _store_indicator_risk(self, indicator_data: Dict, risk_score):
        """Stocke le score de risque d'un Indicator"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO indicator_risk_scores 
            (indicator_value, indicator_type, risk_score, risk_level, confidence, factors, recommendations)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (indicator_value, indicator_type) DO UPDATE SET
                risk_score = EXCLUDED.risk_score,
                risk_level = EXCLUDED.risk_level,
                confidence = EXCLUDED.confidence,
                factors = EXCLUDED.factors,
                recommendations = EXCLUDED.recommendations,
                calculated_at = CURRENT_TIMESTAMP
        """, (
            indicator_data['value'],
            indicator_data['type'],
            risk_score.score,
            risk_score.level.value,
            risk_score.confidence,
            json.dumps(risk_score.factors),
            json.dumps(risk_score.recommendations)
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
    
    def get_high_risk_items(self, item_type: str = 'cve', limit: int = 50) -> List[Dict]:
        """Récupère les éléments à haut risque depuis la DB"""
        conn = self.get_connection()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        if item_type == 'cve':
            cursor.execute("""
                SELECT c.cve_id, c.description, c.cvss_score, c.published_date, c.severity,
                       r.risk_score, r.risk_level, r.recommendations, r.calculated_at
                FROM cves c
                JOIN cve_risk_scores r ON c.cve_id = r.cve_id
                WHERE r.risk_level IN ('CRITICAL', 'HIGH')
                ORDER BY r.risk_score DESC
                LIMIT %s
            """, (limit,))
        else:  # indicators
            cursor.execute("""
                SELECT i.indicator_value, i.indicator_type, i.confidence_level, i.source, i.malware_family,
                       r.risk_score, r.risk_level, r.recommendations, r.calculated_at
                FROM indicators i
                JOIN indicator_risk_scores r ON i.indicator_value = r.indicator_value 
                    AND i.indicator_type = r.indicator_type
                WHERE r.risk_level IN ('CRITICAL', 'HIGH')
                ORDER BY r.risk_score DESC
                LIMIT %s
            """, (limit,))
        
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Formatage des résultats
        items = []
        for row in results:
            row_dict = dict(row)
            if item_type == 'cve':
                items.append({
                    'cve_id': row_dict['cve_id'],
                    'description': row_dict['description'][:200] + '...' if len(row_dict.get('description', '')) > 200 else row_dict.get('description', ''),
                    'cvss_score': row_dict.get('cvss_score'),
                    'published_date': row_dict.get('published_date'),
                    'severity': row_dict.get('severity'),
                    'risk_score': row_dict['risk_score'],
                    'risk_level': row_dict['risk_level'],
                    'recommendations': json.loads(row_dict['recommendations']),
                    'calculated_at': row_dict['calculated_at']
                })
            else:
                items.append({
                    'indicator_value': row_dict['indicator_value'],
                    'indicator_type': row_dict['indicator_type'],
                    'confidence_level': row_dict.get('confidence_level'),
                    'source': row_dict.get('source'),
                    'malware_family': row_dict.get('malware_family'),
                    'risk_score': row_dict['risk_score'],
                    'risk_level': row_dict['risk_level'],
                    'recommendations': json.loads(row_dict['recommendations']),
                    'calculated_at': row_dict['calculated_at']
                })
        
        return items
    
    def get_risk_statistics(self) -> Dict:
        """Génère des statistiques sur les risques"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Stats CVE
        cursor.execute("""
            SELECT risk_level, COUNT(*), AVG(risk_score), AVG(confidence)
            FROM cve_risk_scores
            GROUP BY risk_level
        """)
        cve_stats = {row[0]: {'count': row[1], 'avg_score': row[2], 'avg_confidence': row[3]} 
                     for row in cursor.fetchall()}
        
        # Stats Indicators
        cursor.execute("""
            SELECT risk_level, COUNT(*), AVG(risk_score), AVG(confidence)
            FROM indicator_risk_scores
            GROUP BY risk_level
        """)
        indicator_stats = {row[0]: {'count': row[1], 'avg_score': row[2], 'avg_confidence': row[3]} 
                          for row in cursor.fetchall()}
        
        # Tendances (derniers 30 jours)
        cursor.execute("""
            SELECT DATE(calculated_at) as calc_date, 
                   COUNT(*) as daily_count,
                   AVG(risk_score) as avg_daily_score
            FROM cve_risk_scores 
            WHERE calculated_at >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(calculated_at)
            ORDER BY calc_date DESC
        """)
        trends = [{'date': str(row[0]), 'count': row[1], 'avg_score': float(row[2]) if row[2] else 0} 
                  for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return {
            'cve_by_risk_level': cve_stats,
            'indicator_by_risk_level': indicator_stats,
            'trends_last_30_days': trends,
            'total_cves_analyzed': sum(stat['count'] for stat in cve_stats.values()),
            'total_indicators_analyzed': sum(stat['count'] for stat in indicator_stats.values()),
            'generated_at': datetime.now().isoformat()
        }
    
    def generate_risk_report(self) -> Dict:
        """Génère un rapport complet des risques pour vos rapports Word/Excel"""
        
        # Statistiques générales
        stats = self.get_risk_statistics()
        
        # Top risques
        high_risk_cves = self.get_high_risk_items('cve', 20)
        high_risk_indicators = self.get_high_risk_items('indicator', 20)
        
        # Analyse par source
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT i.source, COUNT(*), AVG(r.risk_score)
            FROM indicators i
            JOIN indicator_risk_scores r ON i.indicator_value = r.indicator_value
            GROUP BY i.source
            ORDER BY AVG(r.risk_score) DESC
        """)
        
        risk_by_source = [{'source': row[0], 'count': row[1], 'avg_risk': float(row[2])} 
                          for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return {
            'executive_summary': {
                'total_cves': stats['total_cves_analyzed'],
                'total_indicators': stats['total_indicators_analyzed'],
                'high_critical_cves': sum(stats['cve_by_risk_level'].get(level, {}).get('count', 0) 
                                        for level in ['HIGH', 'CRITICAL']),
                'high_critical_indicators': sum(stats['indicator_by_risk_level'].get(level, {}).get('count', 0) 
                                              for level in ['HIGH', 'CRITICAL'])
            },
            'detailed_statistics': stats,
            'top_risk_cves': high_risk_cves,
            'top_risk_indicators': high_risk_indicators,
            'risk_by_source': risk_by_source,
            'recommendations': self._generate_global_recommendations(high_risk_cves, high_risk_indicators),
            'report_generated_at': datetime.now().isoformat()
        }
    
    def _generate_global_recommendations(self, high_cves: List, high_indicators: List) -> List[str]:
        """Génère des recommandations globales"""
        recommendations = []
        
        if len(high_cves) > 10:
            recommendations.append("⚠️ Patch Management: Plus de 10 CVEs critiques détectées - prioriser les correctifs")
        
        if len(high_indicators) > 20:
            recommendations.append("🛡️ Network Security: Plus de 20 IoCs à haut risque - renforcer la surveillance réseau")
        
        # Analyse des types de menaces les plus fréquents
        malware_families = [ind.get('malware_family') for ind in high_indicators if ind.get('malware_family')]
        if malware_families:
            top_malware = max(set(malware_families), key=malware_families.count)
            recommendations.append(f"🦠 Malware Focus: Famille {top_malware} détectée fréquemment - surveiller")
        
        recommendations.append("📊 Continuity: Maintenir la surveillance continue et mettre à jour les règles de détection")
        
        return recommendations

def main():
    """Exemple d'utilisation avec votre configuration"""
    
    # Configuration de votre base PostgreSQL avec gestion de l'encodage
    db_config = {
        'host': 'localhost',  # Adaptez à votre configuration
        'database': 'cti_db',
        'user': 'your_username',     # Votre utilisateur
        'password': 'your_password', # Votre mot de passe
        'port': 5432,
        'client_encoding': 'utf8',   # Ajout pour forcer l'encodage UTF-8
        'options': '-c client_encoding=utf8'  # Option supplémentaire
    }
    
    try:
        # Test de connexion avant initialisation
        print("🔌 Test de connexion à PostgreSQL...")
        test_conn = psycopg2.connect(**db_config)
        test_conn.close()
        print("   ✅ Connexion PostgreSQL réussie")
        
        # Initialisation du gestionnaire de risques
        risk_manager = PostgreSQLRiskManager(db_config)
        
        # Contexte organisationnel (à adapter selon votre environnement)
        context = {
            'internet_facing': True,
            'critical_asset': True,
            'business_impact': 'high',
            'patch_availability': True,
            'organization_size': 'medium',
            'threat_landscape': 'advanced'
        }
        
        print("🚀 Démarrage de l'analyse de risques CTI...")
        
        # Étape 1: Calcul des risques CVE
        print("\n1️⃣ Calcul des risques pour les CVEs...")
        risk_manager.calculate_and_store_cve_risks(context, batch_size=50)
        
        # Étape 2: Calcul des risques Indicators
        print("\n2️⃣ Calcul des risques pour les Indicators...")
        risk_manager.calculate_and_store_indicator_risks(batch_size=100)
        
        # Étape 3: Génération du rapport complet
        print("\n3️⃣ Génération du rapport de risques...")
        risk_report = risk_manager.generate_risk_report()
        
        # Affichage des résultats principaux
        print(f"\n📊 RÉSULTATS DE L'ANALYSE:")
        print(f"   - CVEs analysées: {risk_report['executive_summary']['total_cves']}")
        print(f"   - Indicators analysés: {risk_report['executive_summary']['total_indicators']}")
        print(f"   - CVEs critiques/élevées: {risk_report['executive_summary']['high_critical_cves']}")
        print(f"   - Indicators critiques/élevés: {risk_report['executive_summary']['high_critical_indicators']}")
        
        # Top 5 CVEs les plus risquées
        print(f"\n🚨 TOP 5 CVEs À HAUT RISQUE:")
        for i, cve in enumerate(risk_report['top_risk_cves'][:5], 1):
            print(f"   {i}. {cve['cve_id']} - Score: {cve['risk_score']:.1f} ({cve['risk_level']})")
            print(f"      CVSS: {cve['cvss_score']} | {cve['description']}")
        
        # Recommandations globales
        print(f"\n💡 RECOMMANDATIONS:")
        for rec in risk_report['recommendations']:
            print(f"   - {rec}")
        
        # Le rapport complet peut être exporté en JSON pour vos rapports Word/Excel
        with open('risk_analysis_report.json', 'w', encoding='utf-8') as f:
            json.dump(risk_report, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n✅ Rapport complet sauvegardé dans 'risk_analysis_report.json'")
        print("   Ce fichier peut être utilisé pour générer vos rapports Word/Excel")
        
    except psycopg2.OperationalError as e:
        print(f"❌ Erreur de connexion PostgreSQL: {e}")
        print("   Vérifiez que PostgreSQL est démarré et que les paramètres de connexion sont corrects")
    except UnicodeDecodeError as e:
        print(f"❌ Erreur d'encodage: {e}")
        print("   Problème d'encodage des caractères - vérifiez la configuration PostgreSQL")
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        logger.error(f"Erreur dans main(): {e}")

# Alternative avec gestion d'erreur dans get_connection aussi
class PostgreSQLRiskManager:
    """Gestionnaire de risques intégré avec PostgreSQL - Version corrigée"""
    
    def get_connection(self):
        """Crée une connexion PostgreSQL avec gestion d'encodage"""
        try:
            conn = psycopg2.connect(**self.db_config)
            # Force l'encodage UTF-8 sur la connexion
            conn.set_client_encoding('UTF8')
            return conn
        except UnicodeDecodeError:
            # Fallback si problème d'encodage
            config_fallback = self.db_config.copy()
            config_fallback['client_encoding'] = 'latin1'
            conn = psycopg2.connect(**config_fallback)
            conn.set_client_encoding('UTF8')
            return conn
if __name__ == "__main__":
    main()