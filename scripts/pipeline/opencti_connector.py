#!/usr/bin/env python3
"""
OpenCTI Connector - Version avec intégration PostgreSQL et Système de Corrélations Avancées
Connecteur OpenCTI qui extrait les données de PostgreSQL, les envoie à OpenCTI et crée des corrélations intelligentes
"""

import os
import json
import logging
import time
import hashlib
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass

from pycti import OpenCTIApiClient
import requests
import urllib3
import psycopg2
from psycopg2.extras import RealDictCursor

# Désactiver les warnings SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class OpenCTIConfig:
    """Configuration for OpenCTI connection"""
    url: str
    token: str
    admin_email: str
    admin_password: str
    ssl_verify: bool = False
    timeout: int = 30

@dataclass
class DatabaseConfig:
    """Configuration for PostgreSQL connection"""
    host: str
    port: int
    database: str
    username: str
    password: str

@dataclass
class CorrelationRule:
    """Règle de corrélation personnalisée"""
    name: str
    description: str
    source_type: str
    target_type: str
    relationship_type: str
    confidence: int
    condition_func: callable

class EnhancedRelationManager:
    """Gestionnaire avancé des relations OpenCTI intégré"""
    
    def __init__(self, opencti_connector):
        self.connector = opencti_connector
        self.client = opencti_connector.client
        self.db_conn = opencti_connector.db_conn
        self.created_relations = set()
        self.correlation_rules = []
        self._init_correlation_rules()
        
    def _init_correlation_rules(self):
        """Initialiser les règles de corrélation intelligentes"""
        
        # Règle 1: CVE critique avec indicateurs récents
        self.correlation_rules.append(CorrelationRule(
            name="critical_cve_recent_iocs",
            description="Corrélation entre CVE critiques et IOCs récents",
            source_type="Vulnerability",
            target_type="Indicator", 
            relationship_type="related-to",
            confidence=80,
            condition_func=self._rule_critical_cve_recent_iocs
        ))
        
        # Règle 2: Indicateurs du même malware family
        self.correlation_rules.append(CorrelationRule(
            name="same_malware_family",
            description="Indicateurs liés à la même famille de malware",
            source_type="Indicator",
            target_type="Indicator",
            relationship_type="related-to", 
            confidence=75,
            condition_func=self._rule_same_malware_family
        ))
        
        # Règle 3: IOCs de même source et type
        self.correlation_rules.append(CorrelationRule(
            name="same_source_type_iocs",
            description="IOCs de même source et contexte",
            source_type="Indicator",
            target_type="Indicator",
            relationship_type="related-to",
            confidence=70,
            condition_func=self._rule_same_source_type
        ))
        
        # Règle 4: Vulnérabilités dans même produit
        self.correlation_rules.append(CorrelationRule(
            name="same_product_vulnerabilities", 
            description="Vulnérabilités affectant le même produit",
            source_type="Vulnerability",
            target_type="Vulnerability",
            relationship_type="related-to",
            confidence=85,
            condition_func=self._rule_same_product_vulns
        ))
        
        # Règle 5: Indicateurs exploitant des vulnérabilités
        self.correlation_rules.append(CorrelationRule(
            name="indicators_exploit_vulns",
            description="Indicateurs exploitant des vulnérabilités spécifiques",
            source_type="Indicator", 
            target_type="Vulnerability",
            relationship_type="exploits",
            confidence=90,
            condition_func=self._rule_indicators_exploit_vulns
        ))
        
        logger.info(f"✅ Initialized {len(self.correlation_rules)} correlation rules")
    
    def _rule_critical_cve_recent_iocs(self, entity1: Dict, entity2: Dict) -> bool:
     try:
        # Vérifier si l'une des entités est une vulnérabilité avec score élevé
        vuln_score = entity1.get('x_opencti_cvss_base_score') or entity2.get('x_opencti_cvss_base_score')
        if not vuln_score or vuln_score < 7.0:  # Réduire le seuil de 9.0 à 7.0
            return False
        
        created1 = datetime.fromisoformat(entity1['created_at'].replace('Z', '+00:00'))
        created2 = datetime.fromisoformat(entity2['created_at'].replace('Z', '+00:00'))
        
        time_diff = abs((created1 - created2).total_seconds() / 3600)
        return time_diff <= 72  # Augmenter de 24h à 72h
     except Exception as e:
        logger.debug(f"Rule critical_cve_recent_iocs failed: {e}")
        return False
    
    def _rule_same_malware_family(self, entity1: Dict, entity2: Dict) -> bool:
        """Règle: Indicateurs de la même famille de malware"""
        try:
            # Récupérer les métadonnées depuis la DB
            malware1 = self._get_indicator_malware_family(entity1)
            malware2 = self._get_indicator_malware_family(entity2)
            
            if malware1 and malware2 and malware1.lower() == malware2.lower():
                return True
                
            # Vérifier aussi dans les labels/tags
            labels1 = set(entity1.get('labels', []))
            labels2 = set(entity2.get('labels', []))
            
            malware_keywords = {'trojan', 'ransomware', 'botnet', 'backdoor', 'apt'}
            common_malware = labels1.intersection(labels2).intersection(malware_keywords)
            
            return len(common_malware) > 0
        except Exception as e:
            logger.debug(f"Rule same_malware_family failed: {e}")
            return False
    
    def _rule_same_source_type(self, entity1: Dict, entity2: Dict) -> bool:
     try:
        # Vérifier si même type d'observable
        type1 = entity1.get('x_opencti_main_observable_type', '')
        type2 = entity2.get('x_opencti_main_observable_type', '')
        
        if type1 == type2 and type1 in ['IPv4-Addr', 'Domain-Name', 'Url']:
            # Vérifier proximité temporelle (augmentée)
            created1 = datetime.fromisoformat(entity1['created_at'].replace('Z', '+00:00'))
            created2 = datetime.fromisoformat(entity2['created_at'].replace('Z', '+00:00'))
            
            time_diff = abs((created1 - created2).total_seconds() / 3600)
            return time_diff <= 24  # Augmenter de 6h à 24h
        return False
     except Exception as e:
        logger.debug(f"Rule same_source_type failed: {e}")
        return False
    
    def _rule_indicators_exploit_vulns(self, indicator: Dict, vulnerability: Dict) -> bool:
     try:
        # Recherche simple par proximité temporelle forte
        created_indicator = datetime.fromisoformat(indicator['created_at'].replace('Z', '+00:00'))
        created_vuln = datetime.fromisoformat(vulnerability['created_at'].replace('Z', '+00:00'))
        
        time_diff = abs((created_indicator - created_vuln).total_seconds() / 3600)
        
        # Si créés dans les 6h, probable corrélation
        if time_diff <= 6:
            return True
        
        # Vérifier aussi par nom/description si disponible
        vuln_name = vulnerability.get('name', '').lower()
        indicator_name = indicator.get('name', '').lower()
        indicator_desc = indicator.get('description', '').lower()
        
        # Recherche de mots-clés communs
        if vuln_name and (vuln_name in indicator_name or vuln_name in indicator_desc):
            return True
        
        return False
     except Exception as e:
        logger.debug(f"Rule indicators_exploit_vulns failed: {e}")
        return False
    
    def _rule_indicators_exploit_vulns(self, indicator: Dict, vulnerability: Dict) -> bool:
        """Règle: Indicateurs exploitant des vulnérabilités"""
        try:
            # Rechercher des références CVE dans les métadonnées de l'indicateur
            vuln_name = vulnerability.get('name', '')
            if not vuln_name.startswith('CVE-'):
                return False
            
            # Vérifier si le CVE est mentionné dans la description de l'indicateur
            indicator_desc = indicator.get('description', '').lower()
            cve_pattern = r'cve-\d{4}-\d{4,}'
            
            cves_in_indicator = re.findall(cve_pattern, indicator_desc)
            
            if vuln_name.lower() in [cve.lower() for cve in cves_in_indicator]:
                return True
            
            # Vérifier aussi par proximité temporelle forte (2h)
            created_indicator = datetime.fromisoformat(indicator['created_at'].replace('Z', '+00:00'))
            created_vuln = datetime.fromisoformat(vulnerability['created_at'].replace('Z', '+00:00'))
            
            time_diff = abs((created_indicator - created_vuln).total_seconds() / 3600)
            return time_diff <= 2
            
        except Exception as e:
            logger.debug(f"Rule indicators_exploit_vulns failed: {e}")
            return False
    
    def _get_indicator_malware_family(self, indicator: Dict) -> Optional[str]:
        """Récupérer la famille de malware d'un indicateur depuis la DB"""
        try:
            cursor = self.db_conn.cursor()
            
            # Rechercher par valeur d'indicateur
            pattern = indicator.get('pattern', '')
            if pattern:
                # Extraire la valeur du pattern STIX
                value_match = re.search(r"= '([^']+)'", pattern)
                if value_match:
                    value = value_match.group(1)
                    
                    cursor.execute("""
                        SELECT malware_family FROM indicators 
                        WHERE indicator_value = %s AND malware_family IS NOT NULL
                        LIMIT 1
                    """, (value,))
                    
                    result = cursor.fetchone()
                    if result:
                        return result['malware_family']
            
            return None
        except Exception as e:
            logger.debug(f"Failed to get malware family: {e}")
            return None
    
    def _get_vulnerability_products(self, vulnerability: Dict) -> List[str]:
        """Récupérer les produits affectés par une vulnérabilité"""
        try:
            cursor = self.db_conn.cursor()
            vuln_name = vulnerability.get('name', '')
            
            if vuln_name:
                cursor.execute("""
                    SELECT affected_products FROM cves 
                    WHERE cve_id = %s AND affected_products IS NOT NULL
                    LIMIT 1
                """, (vuln_name,))
                
                result = cursor.fetchone()
                if result and result['affected_products']:
                    products = result['affected_products']
                    if isinstance(products, list):
                        return products
                    elif isinstance(products, str):
                        # Parser la string des produits affectés
                        return [p.strip() for p in products.split(',') if p.strip()]
            
            return []
        except Exception as e:
            logger.debug(f"Failed to get vulnerability products: {e}")
            return []
    
    def get_entities_with_metadata(self, entity_type: str, limit: int = 100) -> List[Dict]:
     try:
        if entity_type == "Indicator":
            query = """
            query GetIndicators($first: Int) {
                indicators(first: $first, orderBy: created_at, orderMode: desc) {
                    edges {
                        node {
                            id
                            standard_id
                            created_at
                            updated_at
                            name
                            description
                            pattern
                            confidence
                            x_opencti_main_observable_type
                        }
                    }
                }
            }
            """
        elif entity_type == "Vulnerability":
            query = """
            query GetVulnerabilities($first: Int) {
                vulnerabilities(first: $first, orderBy: created_at, orderMode: desc) {
                    edges {
                        node {
                            id
                            standard_id
                            created_at
                            updated_at
                            name
                            description
                            x_opencti_cvss_base_score
                        }
                    }
                }
            }
            """
        else:
            return []
        
        variables = {"first": limit}
        headers = {
            'Authorization': f'Bearer {self.connector.config.token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{self.connector.config.url}/graphql",
            json={"query": query, "variables": variables},
            headers=headers,
            verify=self.connector.config.ssl_verify,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            # Vérifier s'il y a des erreurs GraphQL
            if 'errors' in result:
                logger.error(f"GraphQL errors for {entity_type}: {result['errors']}")
                return []
            
            # Vérifier la structure de la réponse
            if 'data' in result:
                if entity_type == "Indicator" and 'indicators' in result['data'] and result['data']['indicators']:
                    entities = [edge['node'] for edge in result['data']['indicators']['edges']]
                elif entity_type == "Vulnerability" and 'vulnerabilities' in result['data'] and result['data']['vulnerabilities']:
                    entities = [edge['node'] for edge in result['data']['vulnerabilities']['edges']]
                else:
                    logger.warning(f"No {entity_type} data found in GraphQL response")
                    entities = []
                
                # Ajouter des labels par défaut pour les indicateurs si manquants
                if entity_type == "Indicator":
                    for entity in entities:
                        if 'labels' not in entity:
                            entity['labels'] = ['malicious-activity']  # Label par défaut
                
                logger.info(f"Retrieved {len(entities)} {entity_type} entities with metadata")
                return entities
            else:
                logger.error(f"No data field in GraphQL response for {entity_type}")
                return []
        else:
            logger.error(f"HTTP error {response.status_code} for {entity_type}: {response.text}")
            return []
        
     except Exception as e:
        logger.error(f"Failed to get {entity_type} entities with metadata: {e}")
        return []
    
    def get_entities_with_pycti(self, entity_type: str, limit: int = 100) -> List[Dict]:
     try:
        entities = []
        
        if entity_type == "Indicator":
            # Utiliser l'API PyCTI avec paramètres basiques seulement
            try:
                indicators_data = self.client.indicator.list(first=limit)
                if indicators_data:
                    entities = indicators_data
                    # Ajouter des labels par défaut si manquants
                    for entity in entities:
                        if 'labels' not in entity or not entity['labels']:
                            entity['labels'] = ['malicious-activity']
                    logger.info(f"Retrieved {len(entities)} indicators via PyCTI API")
            except Exception as e:
                logger.error(f"PyCTI indicator.list failed: {e}")
                # Essayer une approche alternative
                indicators_data = self.client.stix_domain_object.list(
                    types=["Indicator"], 
                    first=limit
                )
                if indicators_data:
                    entities = indicators_data
                    for entity in entities:
                        if 'labels' not in entity or not entity['labels']:
                            entity['labels'] = ['malicious-activity']
                    logger.info(f"Retrieved {len(entities)} indicators via PyCTI stix_domain_object")
        
        elif entity_type == "Vulnerability":
            try:
                vulnerabilities_data = self.client.vulnerability.list(first=limit)
                if vulnerabilities_data:
                    entities = vulnerabilities_data
                    logger.info(f"Retrieved {len(entities)} vulnerabilities via PyCTI API")
            except Exception as e:
                logger.error(f"PyCTI vulnerability.list failed: {e}")
                # Essayer une approche alternative
                vulnerabilities_data = self.client.stix_domain_object.list(
                    types=["Vulnerability"], 
                    first=limit
                )
                if vulnerabilities_data:
                    entities = vulnerabilities_data
                    logger.info(f"Retrieved {len(entities)} vulnerabilities via PyCTI stix_domain_object")
        
        return entities
        
     except Exception as e:
        logger.error(f"Failed to get {entity_type} entities via PyCTI: {e}")
        return []
    
    
    def check_graphql_schema(self):
     try:
        # Requête d'introspection pour vérifier les champs disponibles
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        
        headers = {
            'Authorization': f'Bearer {self.connector.config.token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{self.connector.config.url}/graphql",
            json={"query": introspection_query},
            headers=headers,
            verify=self.connector.config.ssl_verify,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'data' in result and '__schema' in result['data']:
                # Chercher le type Indicator
                for type_def in result['data']['__schema']['types']:
                    if type_def['name'] == 'Indicator' and type_def['fields']:
                        field_names = [field['name'] for field in type_def['fields']]
                        logger.info(f"Available Indicator fields: {field_names}")
                        return field_names
        
        return []
        
     except Exception as e:
        logger.error(f"Failed to check GraphQL schema: {e}")
        return []
    
    def get_entities_generic(self, entity_type: str, limit: int = 100) -> List[Dict]:
     try:
        query = """
        query GetEntities($types: [String!], $first: Int) {
            stixDomainObjects(
                types: $types
                first: $first
                orderBy: created_at
                orderMode: desc
            ) {
                edges {
                    node {
                        id
                        standard_id
                        created_at
                        updated_at
                        entity_type
                        ... on Indicator {
                            name
                            description
                            pattern
                            indicator_types
                            x_opencti_main_observable_type
                            confidence
                        }
                        ... on Vulnerability {
                            name
                            description
                            x_opencti_cvss_base_score
                            x_opencti_cvss_base_severity
                        }
                    }
                }
            }
        }
        """
        
        variables = {"types": [entity_type], "first": limit}
        headers = {
            'Authorization': f'Bearer {self.connector.config.token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(
            f"{self.connector.config.url}/graphql",
            json={"query": query, "variables": variables},
            headers=headers,
            verify=self.connector.config.ssl_verify,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if 'errors' in result:
                logger.error(f"GraphQL errors: {result['errors']}")
                return []
            
            if 'data' in result and 'stixDomainObjects' in result['data']:
                entities = [edge['node'] for edge in result['data']['stixDomainObjects']['edges']]
                
                # Ajouter des labels par défaut pour les indicateurs
                if entity_type == "Indicator":
                    for entity in entities:
                        if 'labels' not in entity:
                            entity['labels'] = ['malicious-activity']
                
                logger.info(f"Retrieved {len(entities)} {entity_type} entities via generic query")
                return entities
        
        return []
        
     except Exception as e:
        logger.error(f"Failed to get {entity_type} entities via generic query: {e}")
        return []
    def create_relationship_if_not_exists(self, from_id: str, to_id: str, 
                                        relationship_type: str, description: str = "",
                                        confidence: int = 75, max_retries: int = 3) -> Optional[Dict]:
        """Créer une relation avec le bon type GraphQL"""
        for attempt in range(max_retries):
            try:
                # Générer une clé unique pour cette relation
                relation_key = f"{from_id}-{to_id}-{relationship_type}"
                reverse_key = f"{to_id}-{from_id}-{relationship_type}"
                
                # Vérifier si la relation existe déjà
                if relation_key in self.created_relations or reverse_key in self.created_relations:
                    logger.debug(f"Relation already exists: {relationship_type}")
                    return None
                
                # CORRECTION: Utiliser le bon type GraphQL
                mutation = """
                mutation StixRefRelationshipAdd($input: StixRefRelationshipAddInput!) {
                    stixRefRelationshipAdd(input: $input) {
                       id
                       relationship_type
                    }
                }
                """
                
                variables = {
                    "input": {
                        "fromId": from_id,
                        "toId": to_id,
                        "relationship_type": relationship_type,
                        "description": description,
                        "confidence": confidence,
                        "start_time": datetime.now().isoformat() + "Z"
                    }
                }
                
                headers = {
                    'Authorization': f'Bearer {self.connector.config.token}',
                    'Content-Type': 'application/json'
                }
                
                response = requests.post(
                    f"{self.connector.config.url}/graphql",
                    json={"query": mutation, "variables": variables},
                    headers=headers,
                    verify=self.connector.config.ssl_verify,
                    timeout=30
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if 'data' in result and result['data']['stixRefRelationshipAdd']:
                        relation = result['data']['stixRefRelationshipAdd']
                        self.created_relations.add(relation_key)
                        logger.info(f"✅ Created relation: {relationship_type} (ID: {relation.get('id', 'Unknown')})")
                        return relation
                    elif 'errors' in result:
                        error_msg = result['errors'][0].get('message', 'Unknown error')
                        if 'already exists' in error_msg.lower():
                            self.created_relations.add(relation_key)
                            return None  # Relation existe déjà
                        
                        # Si le type n'est toujours pas bon, essayer avec PyCTI
                        if 'Unknown type' in error_msg:
                            logger.warning(f"GraphQL schema issue, trying PyCTI method...")
                            return self._create_relation_with_pycti(from_id, to_id, relationship_type, description, confidence)
                        
                        logger.warning(f"GraphQL error (attempt {attempt + 1}): {error_msg}")
                    else:
                        logger.warning(f"Unexpected response (attempt {attempt + 1}): {result}")
                else:
                    logger.warning(f"HTTP error {response.status_code} (attempt {attempt + 1}): {response.text}")
                
                # Retry avec backoff
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    
            except Exception as e:
                logger.warning(f"Error creating relationship (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        
        # Fallback vers PyCTI si GraphQL échoue
        logger.info("Falling back to PyCTI method for relationship creation...")
        return self._create_relation_with_pycti(from_id, to_id, relationship_type, description, confidence)
    
    def _create_relation_with_pycti(self, from_id: str, to_id: str, 
                                   relationship_type: str, description: str, 
                                   confidence: int) -> Optional[Dict]:
        """Créer une relation en utilisant l'API PyCTI"""
        try:
            relation_key = f"{from_id}-{to_id}-{relationship_type}"
            
            if relation_key in self.created_relations:
                return None
            
            # Utiliser PyCTI pour créer la relation
            relation_data = {
                'fromId': from_id,
                'toId': to_id,
                'relationship_type': relationship_type,
                'description': description,
                'confidence': confidence,
                'start_time': datetime.now().isoformat() + "Z"
            }
            
            # Essayer différentes méthodes PyCTI
            relation = None
            try:
                # Méthode 1: stix_relation_object
                relation = self.client.stix_relation_object.create(**relation_data)
            except Exception as e1:
                logger.debug(f"PyCTI method 1 failed: {e1}")
                try:
                    # Méthode 2: stix_core_relationship
                    relation = self.client.stix_core_relationship.create(**relation_data)
                except Exception as e2:
                    logger.debug(f"PyCTI method 2 failed: {e2}")
                    try:
                        # Méthode 3: relation générique
                        relation = self.client.stix_domain_object.create(
                            type="relationship",
                            **relation_data
                        )
                    except Exception as e3:
                        logger.debug(f"PyCTI method 3 failed: {e3}")
            
            if relation:
                self.created_relations.add(relation_key)
                logger.info(f"✅ Created relation via PyCTI: {relationship_type} (ID: {relation.get('id', 'Unknown')})")
                return relation
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Failed to create relation with PyCTI: {e}")
            return None
    
    def check_available_relationship_types(self):
        """Vérifier les types de relations disponibles via introspection GraphQL"""
        try:
            introspection_query = """
            query IntrospectionQuery {
                __schema {
                    mutationType {
                        fields {
                            name
                            args {
                                name
                                type {
                                    name
                                    inputFields {
                                        name
                                        type {
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
            
            headers = {
                'Authorization': f'Bearer {self.connector.config.token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.connector.config.url}/graphql",
                json={"query": introspection_query},
                headers=headers,
                verify=self.connector.config.ssl_verify,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    mutations = result['data']['__schema']['mutationType']['fields']
                    relation_mutations = [m for m in mutations if 'relation' in m['name'].lower()]
                    logger.info("Available relationship mutations:")
                    for mutation in relation_mutations:
                        logger.info(f"  - {mutation['name']}")
                    return relation_mutations
            
            return []
            
        except Exception as e:
            logger.error(f"Failed to check relationship types: {e}")
            return []
    

    def create_intelligent_correlations_with_fallback(self, max_relations: int = 50) -> Dict[str, int]:
        """Version améliorée avec fallback et diagnostic"""
        logger.info("🧠 Starting intelligent correlations with fallback...")
        
        # Diagnostic initial
        self.check_available_relationship_types()
        
        results = {
            'total_relations': 0,
            'by_rule': {},
            'by_type': {},
            'method_used': 'unknown'
        }
        
        # Récupération des entités avec retry
        indicators = self._get_entities_with_retry("Indicator", limit=20)  # Réduire la limite
        vulnerabilities = self._get_entities_with_retry("Vulnerability", limit=15)
        
        logger.info(f"Analyzing {len(indicators)} indicators and {len(vulnerabilities)} vulnerabilities")
        
        if len(indicators) == 0 and len(vulnerabilities) == 0:
            logger.warning("⚠️ No entities found for correlation analysis!")
            return results
        
        relations_created = 0
        
        # Test avec une seule corrélation simple d'abord
        if indicators and vulnerabilities:
            logger.info("🔍 Testing simple correlation...")
            test_relation = self.create_relationship_if_not_exists(
                indicators[0]['id'], 
                vulnerabilities[0]['id'],
                "related-to",
                "Test correlation for debugging",
                60
            )
            
            if test_relation:
                relations_created += 1
                results['method_used'] = 'graphql_corrected'
                logger.info("✅ GraphQL method working, continuing...")
            else:
                logger.warning("⚠️ GraphQL method failed, trying alternative approach...")
                results['method_used'] = 'pycti_fallback'
        
        # Si le test réussit, continuer avec les autres corrélations
        if relations_created > 0 or results['method_used'] == 'pycti_fallback':
            # Corrélations simples basées sur la proximité temporelle
            for i, indicator in enumerate(indicators[:10]):  # Limiter à 10
                for j, vulnerability in enumerate(vulnerabilities[:5]):  # Limiter à 5
                    if relations_created >= max_relations:
                        break
                    
                    # Vérifier proximité temporelle (48h)
                    if self._is_temporal_correlation(indicator, vulnerability, hours=48):
                        relation = self.create_relationship_if_not_exists(
                            indicator['id'],
                            vulnerability['id'],
                            "related-to",
                            f"Temporal correlation: created within 48h",
                            65
                        )
                        
                        if relation:
                            relations_created += 1
                            time.sleep(0.5)  # Pause plus longue
                
                if relations_created >= max_relations:
                    break
        
        results['total_relations'] = relations_created
        results['by_type']['related-to'] = relations_created
        
        logger.info(f"🎉 Total relations created: {relations_created} (method: {results['method_used']})")
        return results
    
    def _is_temporal_correlation(self, entity1: Dict, entity2: Dict, hours: int = 48) -> bool:
        """Vérifier corrélation temporelle"""
        try:
            created1 = datetime.fromisoformat(entity1['created_at'].replace('Z', '+00:00'))
            created2 = datetime.fromisoformat(entity2['created_at'].replace('Z', '+00:00'))
            
            time_diff = abs((created1 - created2).total_seconds() / 3600)
            return time_diff <= hours
        except Exception as e:
            logger.debug(f"Temporal correlation check failed: {e}")
            return False

    
    
    def generate_correlation_report(self) -> Dict[str, any]:
        """Générer un rapport des corrélations créées"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_relations_created': len(self.created_relations),
            'rules_applied': len(self.correlation_rules),
            'relation_types': {},
            'recommendations': []
        }
        
        # Analyser les types de relations créées
        for relation_key in self.created_relations:
            parts = relation_key.split('-')
            if len(parts) >= 3:
                rel_type = parts[-1]
                report['relation_types'][rel_type] = report['relation_types'].get(rel_type, 0) + 1
        
        # Générer des recommandations
        if report['total_relations_created'] > 20:
            report['recommendations'].append("High correlation activity detected. Consider reviewing threat landscape.")
        
        if 'exploits' in report['relation_types']:
            report['recommendations'].append("Active exploitation indicators found. Prioritize vulnerability patching.")
        
        return report
    
    def diagnose_opencti_content(self):
      logger.info("🔍 Diagnosing OpenCTI content...")
    
      try:
        # Vérifier via des requêtes GraphQL simples
        headers = {
            'Authorization': f'Bearer {self.connector.config.token}',
            'Content-Type': 'application/json'
        }
        
        # Compter les indicateurs
        count_query = """
        query CountEntities {
            indicatorsNumber
            vulnerabilitiesNumber
        }
        """
        
        response = requests.post(
            f"{self.connector.config.url}/graphql",
            json={"query": count_query},
            headers=headers,
            verify=self.connector.config.ssl_verify,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'data' in result:
                indicators_count = result['data'].get('indicatorsNumber', 0)
                vulns_count = result['data'].get('vulnerabilitiesNumber', 0)
                
                logger.info(f"📊 OpenCTI Content Summary:")
                logger.info(f"   Indicators: {indicators_count}")
                logger.info(f"   Vulnerabilities: {vulns_count}")
                
                if indicators_count == 0:
                    logger.warning("⚠️ No indicators found in OpenCTI!")
                    logger.info("💡 Run the synchronization first to import indicators from database")
                
                return {'indicators': indicators_count, 'vulnerabilities': vulns_count}
        
        return {'indicators': 0, 'vulnerabilities': 0}
        
      except Exception as e:
        logger.error(f"Failed to diagnose OpenCTI content: {e}")
        return {'indicators': 0, 'vulnerabilities': 0}

    def diagnose_correlation_issues(self):
      logger.info("🔍 Diagnosing correlation issues...")
    
    # Vérifier les entités disponibles
      indicators = self._get_entities_with_retry("Indicator", limit=10)
      vulnerabilities = self._get_entities_with_retry("Vulnerability", limit=10)
    
      logger.info(f"Sample data available:")
      logger.info(f"  Indicators: {len(indicators)}")
      logger.info(f"  Vulnerabilities: {len(vulnerabilities)}")
    
      if indicators:
        sample_indicator = indicators[0]
        logger.info(f"  Sample indicator fields: {list(sample_indicator.keys())}")
        logger.info(f"  Sample indicator type: {sample_indicator.get('x_opencti_main_observable_type')}")
    
      if vulnerabilities:
        sample_vuln = vulnerabilities[0]
        logger.info(f"  Sample vulnerability fields: {list(sample_vuln.keys())}")
        logger.info(f"  Sample vulnerability score: {sample_vuln.get('x_opencti_cvss_base_score')}")
    
    # Tester les règles manuellement
      if indicators and vulnerabilities:
        logger.info("Testing correlation rules...")
        for rule in self.correlation_rules:
            if rule.source_type == "Indicator" and rule.target_type == "Vulnerability":
                result = rule.condition_func(indicators[0], vulnerabilities[0])
                logger.info(f"  Rule {rule.name}: {result}")
    
    def _rule_same_product_vulns(self, vulnerability1: Dict, vulnerability2: Dict) -> bool:
        """Règle: Vulnérabilités affectant le même produit"""
        try:
            # Récupérer les produits affectés pour chaque vulnérabilité
            products1 = self._get_vulnerability_products(vulnerability1)
            products2 = self._get_vulnerability_products(vulnerability2)
            
            if not products1 or not products2:
                return False
            
            # Vérifier s'il y a des produits en commun
            common_products = set(products1).intersection(set(products2))
            
            if len(common_products) > 0:
                # Vérifier aussi la proximité temporelle (dans les 30 jours)
                created1 = datetime.fromisoformat(vulnerability1['created_at'].replace('Z', '+00:00'))
                created2 = datetime.fromisoformat(vulnerability2['created_at'].replace('Z', '+00:00'))
                
                time_diff = abs((created1 - created2).total_seconds() / 86400)  # en jours
                return time_diff <= 30
            
            return False
        except Exception as e:
            logger.debug(f"Rule same_product_vulns failed: {e}")
            return False

    def _get_entities_with_retry(self, entity_type: str, limit: int = 100, max_retries: int = 3) -> List[Dict]:
        """Récupérer les entités avec retry automatique"""
        for attempt in range(max_retries):
            try:
                # Essayer d'abord avec GraphQL personnalisé
                entities = self.get_entities_with_metadata(entity_type, limit)
                if entities:
                    return entities
                
                # Fallback vers PyCTI
                entities = self.get_entities_with_pycti(entity_type, limit)
                if entities:
                    return entities
                
                # Fallback vers requête générique
                entities = self.get_entities_generic(entity_type, limit)
                if entities:
                    return entities
                
                logger.warning(f"No {entity_type} entities found (attempt {attempt + 1})")
                
            except Exception as e:
                logger.error(f"Error getting {entity_type} entities (attempt {attempt + 1}): {e}")
                
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Backoff exponentiel
        
        logger.error(f"Failed to get {entity_type} entities after {max_retries} attempts")
        return []

class OpenCTIConnector:
    """Connecteur OpenCTI avec intégration PostgreSQL et système de corrélations"""
    
    def __init__(self, config_path: str = None, db_config_path: str = None):
        """Initialize the OpenCTI connector with database integration"""
        # Load OpenCTI config
        if config_path is None:
            possible_paths = [
                "config/opencti_config.json",
                "../config/opencti_config.json", 
                "../../config/opencti_config.json",
                r"C:\Users\marou\OneDrive\Desktop\CTI_Project\config\opencti_config.json"
            ]
            
            config_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    config_path = path
                    break
            
            if config_path is None:
                raise FileNotFoundError(f"Config file not found. Searched in: {possible_paths}")
        
        # Load database config
        if db_config_path is None:
            db_possible_paths = [
                "config/database.json",
                "../config/database.json",
                "../../config/database.json",
                r"C:\Users\marou\OneDrive\Desktop\CTI_Project\config\database.json"
            ]
            
            for path in db_possible_paths:
                if os.path.exists(path):
                    db_config_path = path
                    break
        
        self.config = self._load_config(config_path)
        self.db_config = self._load_db_config(db_config_path)
        self.client = None
        self.db_conn = None
        self.enhanced_relation_manager = None
        
        self._connect_opencti()
        self._connect_database()
        
    def _load_config(self, config_path: str) -> OpenCTIConfig:
        """Load OpenCTI configuration from JSON file"""
        try:
            logger.info(f"Loading OpenCTI config from: {os.path.abspath(config_path)}")
            with open(config_path, 'r') as f:
                config_data = json.load(f)
                
            opencti_config = config_data.get('opencti', {})
            return OpenCTIConfig(
                url=opencti_config.get('url', 'http://localhost:8082'),
                token=opencti_config.get('token'),
                admin_email=opencti_config.get('admin', {}).get('email'),
                admin_password=opencti_config.get('admin', {}).get('password'),
                ssl_verify=opencti_config.get('ssl_verify', False),
                timeout=opencti_config.get('timeout', 30)
            )
        except Exception as e:
            logger.error(f"Failed to load OpenCTI config: {e}")
            raise
    
    def _load_db_config(self, config_path: str) -> DatabaseConfig:
        """Load database configuration"""
        try:
            if config_path and os.path.exists(config_path):
                logger.info(f"Loading database config from: {os.path.abspath(config_path)}")
                with open(config_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                pg_config = config_data.get('postgresql', {})
            else:
                # Use environment variables or defaults
                logger.info("Using environment variables for database config")
                pg_config = {
                    "host": os.getenv("DB_HOST", "localhost"),
                    "port": int(os.getenv("DB_PORT", "5432")),
                    "database": os.getenv("DB_NAME", "cti_db"),
                    "username": os.getenv("DB_USER", "cti_user"),
                    "password": os.getenv("DB_PASSWORD", "cti_password")
                }
            
            # Vérifier si on doit utiliser localhost au lieu de cti-postgres
            host = pg_config.get('host', 'localhost')
            if host == 'cti-postgres':
                logger.info("Docker host 'cti-postgres' detected, trying localhost first...")
                host = 'localhost'
            
            return DatabaseConfig(
                host=host,
                port=pg_config.get('port', 5432),
                database=pg_config.get('database', 'cti_db'),
                username=pg_config.get('username', 'cti_user'),
                password=pg_config.get('password', 'cti_password')
            )
        except Exception as e:
            logger.error(f"Failed to load database config: {e}")
            raise
    
    def _connect_opencti(self):
        """Establish connection to OpenCTI"""
        try:
            logger.info("Connecting to OpenCTI API...")
            
            self.client = OpenCTIApiClient(
                url=self.config.url,
                token=self.config.token,
                ssl_verify=self.config.ssl_verify,
                log_level='ERROR'
            )
            
            if self._verify_opencti_connection():
                logger.info("✅ Successfully connected to OpenCTI")
            else:
                raise Exception("OpenCTI connection verification failed")
                        
        except Exception as e:
            logger.error(f"Failed to connect to OpenCTI: {e}")
            raise
    
    def sync_with_dashboard(self, opencti_data):
    # Synchronisation bidirectionnelle
     dashboard_formatted = self.format_for_dashboard(opencti_data)
     self.dashboard_api.update_intelligence(dashboard_formatted)
    
    def _connect_database(self):
        """Establish connection to PostgreSQL"""
        try:
            logger.info(f"Connecting to PostgreSQL at {self.db_config.host}:{self.db_config.port}")
            
            self.db_conn = psycopg2.connect(
                host=self.db_config.host,
                port=self.db_config.port,
                database=self.db_config.database,
                user=self.db_config.username,
                password=self.db_config.password,
                cursor_factory=RealDictCursor,
                connect_timeout=10
            )
            self.db_conn.autocommit = True
            
            # Test simple de la connexion
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT version()")
            version = cursor.fetchone()
            version_info = version['version'] if 'version' in version else str(version)
            logger.info(f"✅ Successfully connected to PostgreSQL: {version_info[:50]}...")
            
            # Test des tables principales
            cursor.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name IN ('iocs', 'indicators', 'cves')
                ORDER BY table_name
            """)
            tables = cursor.fetchall()
            table_names = [t['table_name'] for t in tables]
            logger.info(f"Found tables: {table_names}")
            
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Error args: {e.args}")
            raise
    
    def _verify_opencti_connection(self) -> bool:
        """Verify OpenCTI connection"""
        try:
            response = requests.get(
                self.config.url,
                timeout=10,
                verify=self.config.ssl_verify
            )
            if response.status_code == 200:
                logger.info("OpenCTI web interface accessible")
                return True
        except Exception as e:
            logger.error(f"OpenCTI connection verification failed: {e}")
        
        return False
    
    def get_iocs_from_db(self, limit: int = 100, unprocessed_only: bool = False) -> List[Dict]:
        """Extract IoCs from database - CORRIGÉ selon la structure réelle"""
        try:
            cursor = self.db_conn.cursor()
            
            # Requête basée sur les colonnes réelles de la table iocs
            query = """
                SELECT id, ioc_type, ioc_value, source_id, confidence_score, 
                       first_seen, last_seen, is_active, tags, context
                FROM iocs 
                WHERE is_active = TRUE
                ORDER BY first_seen DESC 
                LIMIT %s
            """
            
            cursor.execute(query, (limit,))
            iocs = cursor.fetchall()
            
            logger.info(f"Retrieved {len(iocs)} IoCs from database")
            return [dict(ioc) for ioc in iocs]
            
        except Exception as e:
            logger.error(f"Failed to retrieve IoCs from database: {e}")
            return []
    
    def get_indicators_from_db(self, limit: int = 100, include_processed: bool = True) -> List[Dict]:
       
     try:
        cursor = self.db_conn.cursor()
        
        # Requête modifiée pour inclure TOUS les indicateurs ou seulement les non-traités
        if include_processed:
            # Récupérer TOUS les indicateurs
            query = """
                SELECT id, indicator_value, indicator_type, source, description,
                       malware_family, confidence_level, first_seen, last_seen,
                       tags, collected_at, processed
                FROM indicators 
                ORDER BY collected_at DESC 
                LIMIT %s
            """
            cursor.execute(query, (limit,))
        else:
            # Récupérer seulement les non-traités
            query = """
                SELECT id, indicator_value, indicator_type, source, description,
                       malware_family, confidence_level, first_seen, last_seen,
                       tags, collected_at, processed
                FROM indicators 
                WHERE (processed IS NULL OR processed = FALSE)
                ORDER BY collected_at DESC 
                LIMIT %s
            """
            cursor.execute(query, (limit,))
        
        indicators = cursor.fetchall()
        
        logger.info(f"Retrieved {len(indicators)} indicators from database (include_processed={include_processed})")
        return [dict(indicator) for indicator in indicators]
        
     except Exception as e:
        logger.error(f"Failed to retrieve indicators from database: {e}")
        return []

    def _mark_indicator_as_processed(self, indicator_id: int):
    
     try:
        cursor = self.db_conn.cursor()
        cursor.execute(
            "UPDATE indicators SET processed = TRUE WHERE id = %s",
            (indicator_id,)
        )
        logger.debug(f"Marked indicator {indicator_id} as processed")
     except Exception as e:
        logger.error(f"Failed to mark indicator {indicator_id} as processed: {e}")
    
    def get_cves_from_db(self, limit: int = 50) -> List[Dict]:
        """Extract CVEs from database - CORRIGÉ selon la structure réelle"""
        try:
            cursor = self.db_conn.cursor()
            
            # Requête basée sur les colonnes réelles de la table cves
            query = """
                SELECT id, cve_id, description, severity, cvss_score,
                       published_date, modified_date, affected_products,
                       cve_references, collected_at, analyzed_at, metadata
                FROM cves 
                ORDER BY published_date DESC 
                LIMIT %s
            """
            
            cursor.execute(query, (limit,))
            cves = cursor.fetchall()
            
            logger.info(f"Retrieved {len(cves)} CVEs from database")
            return [dict(cve) for cve in cves]
            
        except Exception as e:
            logger.error(f"Failed to retrieve CVEs from database: {e}")
            return []
    
    def create_indicator_from_ioc(self, ioc_data: Dict) -> Optional[Dict]:
        """Create OpenCTI indicator from database IoC"""
        try:
            # Map database IoC types to OpenCTI types
            type_mapping = {
                'ip': 'ip',
                'ipv4': 'ip', 
                'ipv6': 'ipv6',
                'domain': 'domain',
                'url': 'url',
                'hash_md5': 'hash_md5',
                'hash_sha1': 'hash_sha1', 
                'hash_sha256': 'hash_sha256',
                'email': 'email',
                'file_hash': 'hash_sha256'
            }
            
            ioc_type = type_mapping.get(str(ioc_data['ioc_type']).lower(), 'ip')
            
            # Extract context information
            context = ioc_data.get('context', {})
            if isinstance(context, str):
                try:
                    context = json.loads(context)
                except:
                    context = {}
            
            # Prepare labels
            labels = ioc_data.get('tags', [])
            if not labels:
                labels = ['malicious-activity']
            
            # Create description with source information
            description = f"IoC extracted from CTI database - Type: {ioc_data['ioc_type']}"
            if context.get('source'):
                description += f" - Source: {context['source']}"
            
            # Create indicator using the existing method
            indicator = self.create_indicator(
                value=str(ioc_data['ioc_value']),
                indicator_type=ioc_type,
                labels=labels,
                confidence=int((ioc_data.get('confidence_score', 0.5) * 100)),
                description=description,
                source=f"CTI_DB_IoC_{ioc_data['id']}"
            )
            
            if indicator:
                logger.info(f"✅ Created indicator from IoC {ioc_data['id']}: {ioc_data['ioc_value']}")
            
            return indicator
            
        except Exception as e:
            logger.error(f"❌ Failed to create indicator from IoC {ioc_data.get('id')}: {e}")
            return None
    
    def create_indicator_from_db_indicator(self, indicator_data: Dict) -> Optional[Dict]:
        """Create OpenCTI indicator from database indicator table - CORRIGÉ"""
        try:
            # Map confidence level to percentage - FIX pour gérer les types int et str
            confidence_level = indicator_data.get('confidence_level', 'medium')
            
            if isinstance(confidence_level, int):
                # Si c'est déjà un nombre, l'utiliser directement
                confidence = min(100, max(0, confidence_level))
            elif isinstance(confidence_level, str):
                # Si c'est une string, faire le mapping
                confidence_mapping = {
                    'low': 25,
                    'medium': 50,
                    'high': 75,
                    'very_high': 90
                }
                confidence = confidence_mapping.get(confidence_level.lower(), 50)
            else:
                confidence = 50
            
            # Gérer indicator_type - FIX pour gérer les types int et str
            indicator_type = indicator_data.get('indicator_type', 'ip')
            if isinstance(indicator_type, int):
                # Si c'est un entier, mapper vers un type de base
                type_mapping = {1: 'ip', 2: 'domain', 3: 'url', 4: 'hash_sha256', 5: 'email'}
                indicator_type = type_mapping.get(indicator_type, 'ip')
            
            # Prepare description
            description = indicator_data.get('description', '')
            if not description:
                description = f"Indicator from CTI database - {indicator_type}"
            
            if indicator_data.get('malware_family'):
                description += f" - Malware: {indicator_data['malware_family']}"
            
            # Create indicator
            indicator = self.create_indicator(
                value=str(indicator_data['indicator_value']),
                indicator_type=str(indicator_type),
                labels=indicator_data.get('tags', ['malicious-activity']),
                confidence=confidence,
                description=description,
                source=indicator_data.get('source', f"CTI_DB_Indicator_{indicator_data['id']}")
            )
            
            if indicator:
                # Mark as processed
                self._mark_indicator_as_processed(indicator_data['id'])
                logger.info(f"✅ Created indicator from DB indicator {indicator_data['id']}: {indicator_data['indicator_value']}")
            
            return indicator
            
        except Exception as e:
            logger.error(f"❌ Failed to create indicator from DB indicator {indicator_data.get('id')}: {e}")
            return None
    
    def create_vulnerability_from_cve(self, cve_data: Dict) -> Optional[Dict]:
        """Create OpenCTI vulnerability from database CVE - VERSION CORRIGÉE"""
        try:
         import uuid
         from datetime import datetime
        
        # Map severity to labels
         severity_labels = {
            'critical': ['critical', 'vulnerability'],
            'high': ['high', 'vulnerability'], 
            'medium': ['medium', 'vulnerability'],
            'low': ['low', 'vulnerability']
         }
        
         severity = str(cve_data.get('severity', 'medium')).lower()
         labels = severity_labels.get(severity, ['vulnerability'])
        
        # Prepare description
         description = cve_data.get('description', f"Vulnerability {cve_data['cve_id']}")
        
        # Add CVSS score to description
         if cve_data.get('cvss_score'):
              description += f" - CVSS Score: {cve_data['cvss_score']}"
        
        # Add affected products
         affected_products = cve_data.get('affected_products')
         if affected_products:
                if isinstance(affected_products, list) and affected_products:
                   description += f" - Affected: {', '.join(str(p) for p in affected_products[:3])}"
                elif isinstance(affected_products, str) and affected_products.strip():
                    description += f" - Affected: {affected_products.strip()}"
        
        # Create STIX vulnerability object manually
         stix_id = f"vulnerability--{str(uuid.uuid4())}"
         current_time = datetime.now().isoformat() + "Z"
        
        # STIX 2.1 Vulnerability object - minimal version
         stix_vulnerability = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": stix_id,
            "created": current_time,
            "modified": current_time,
            "name": cve_data['cve_id'],
            "description": description,
            "labels": labels
         }
        
        # Add external references if available
         if cve_data.get('cve_references'):
            references = cve_data['cve_references']
            if isinstance(references, list) and references:
                stix_vulnerability["external_references"] = []
                for ref in references[:3]:
                    stix_vulnerability["external_references"].append({
                        "source_name": "cve",
                        "external_id": cve_data['cve_id'],
                        "url": ref
                    })
        
         headers = {
            'Authorization': f'Bearer {self.config.token}',
             'Content-Type': 'application/json'
         }
       
        # Ajouter le score CVSS de base si disponible
          #  if cve_data.get('cvss_score'):
           #   try:
            #    cvss_score = float(cve_data['cvss_score'])
             #   vulnerability_data['x_opencti_cvss_base_score'] = cvss_score
                
                # Déterminer la sévérité basée sur le score CVSS
             #   if cvss_score >= 9.0:
            #        vulnerability_data['x_opencti_cvss_base_severity'] = 'CRITICAL'
              #  elif cvss_score >= 7.0:
               #     vulnerability_data['x_opencti_cvss_base_severity'] = 'HIGH'
               # elif cvss_score >= 4.0:
                #    vulnerability_data['x_opencti_cvss_base_severity'] = 'MEDIUM'
                #else:
               #     vulnerability_data['x_opencti_cvss_base_severity'] = 'LOW'
              #except (ValueError, TypeError):
               # logger.warning(f"Invalid CVSS score for {cve_data['cve_id']}: {cve_data.get('cvss_score')}")
        
        # Créer la vulnérabilité
            
             # GraphQL mutation for creating vulnerability with minimal fields
         graphql_query = """
         mutation CreateVulnerability($input: VulnerabilityAddInput!) {
            vulnerabilityAdd(input: $input) {
                id
                standard_id
                name
                description
            }
        }
        """
        
        # Minimal input with only required fields
         graphql_variables = {
            "input": {
                "name": cve_data['cve_id'],
                "description": description
            }
        }
         import requests
         response = requests.post(
            f"{self.config.url}/graphql",
            json={
                "query": graphql_query,
                "variables": graphql_variables
            },
            headers=headers,
            verify=self.config.ssl_verify,
            timeout=30
        )
         if response.status_code == 200:
            result = response.json()
            if 'data' in result and result['data']['vulnerabilityAdd']:
                vulnerability = result['data']['vulnerabilityAdd']
                logger.info(f"✅ Created vulnerability via REST API: {cve_data['cve_id']} (ID: {vulnerability.get('id')})")
                return vulnerability
            else:
                logger.error(f"GraphQL error: {result.get('errors', 'Unknown error')}")
                return None
         else:
            logger.error(f"HTTP error {response.status_code}: {response.text}")
            return None
        
        except Exception as e:
            logger.error(f"❌ Failed to create vulnerability from CVE {cve_data.get('cve_id')}: {e}")
            return None
    def sync_all_data_to_opencti(self, batch_size: int = 50, force_reprocess: bool = False) -> Dict[str, int]:
        """Synchronize all data from database to OpenCTI"""
        results = {
            'iocs_processed': 0,
            'indicators_processed': 0,
            'vulnerabilities_processed': 0,
            'total_success': 0,
            'total_failed': 0
        }
        
        logger.info("🚀 Starting full synchronization to OpenCTI...")
        
        # Process IoCs
        logger.info("📡 Processing IoCs...")
        iocs = self.get_iocs_from_db(limit=batch_size)
        for ioc in iocs:
            if self.create_indicator_from_ioc(ioc):
                results['iocs_processed'] += 1
                results['total_success'] += 1
            else:
                results['total_failed'] += 1
            time.sleep(0.1)
        
        # Process Indicators table
        logger.info("📡 Processing Indicators...")
        indicators = self.get_indicators_from_db(limit=batch_size, include_processed=force_reprocess)
    
        if not indicators:
          logger.warning("⚠️ No indicators found to process. All indicators may already be processed.")
          logger.info("💡 Tip: Use force_reprocess=True to reprocess all indicators")
    
        for indicator in indicators:
            # Si force_reprocess=False, on ne retraite pas les indicateurs déjà traités
          if not force_reprocess and indicator.get('processed', False):
             logger.debug(f"Skipping already processed indicator {indicator['id']}")
             continue
            
          if self.create_indicator_from_db_indicator(indicator):
            results['indicators_processed'] += 1
            results['total_success'] += 1
          else:
            results['total_failed'] += 1
          time.sleep(0.1) 
        
        # Process CVEs
        logger.info("📡 Processing CVEs...")
        cves = self.get_cves_from_db(limit=batch_size)
        for cve in cves:
            if self.create_vulnerability_from_cve(cve):
                results['vulnerabilities_processed'] += 1
                results['total_success'] += 1
            else:
                results['total_failed'] += 1
            time.sleep(0.1)
        
        logger.info("✅ Synchronization completed!")
        return results
    
    def create_indicator(self, 
                        value: str, 
                        indicator_type: str,
                        labels: List[str] = None,
                        confidence: int = 50,
                        description: str = None,
                        source: str = None) -> Optional[Dict]:
        """Create an indicator in OpenCTI"""
        try:
            # Map indicator types to OpenCTI observable types
            type_mapping = {
                'ip': 'IPv4-Addr',
                'ipv4': 'IPv4-Addr',
                'ipv6': 'IPv6-Addr',
                'domain': 'Domain-Name', 
                'url': 'Url',
                'hash_md5': 'File',
                'hash_sha1': 'File',
                'hash_sha256': 'File',
                'email': 'Email-Addr',
                'file': 'File'
            }
            
            observable_type = type_mapping.get(str(indicator_type).lower(), 'IPv4-Addr')
            
            # Create STIX2 pattern
            if str(indicator_type).lower() in ['hash_md5', 'hash_sha1', 'hash_sha256']:
                hash_type = str(indicator_type).lower().replace('hash_', '')
                pattern = f"[file:hashes.'{hash_type.upper()}' = '{value}']"
            elif str(indicator_type).lower() in ['ip', 'ipv4']:
                pattern = f"[ipv4-addr:value = '{value}']"
            elif str(indicator_type).lower() == 'ipv6':
                pattern = f"[ipv6-addr:value = '{value}']"
            elif str(indicator_type).lower() == 'domain':
                pattern = f"[domain-name:value = '{value}']"
            elif str(indicator_type).lower() == 'url':
                pattern = f"[url:value = '{value}']"
            elif str(indicator_type).lower() == 'email':
                pattern = f"[email-addr:value = '{value}']"
            else:
                pattern = f"[ipv4-addr:value = '{value}']"
            
            # Prepare description
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            final_description = description or f"Indicator of type {indicator_type} created on {timestamp}"
            if source:
                final_description += f" from {source}"
            
            # Create indicator
            indicator_data = {
                'name': f"{str(indicator_type).upper()}: {value}",
                'description': final_description,
                'pattern': pattern,
                'pattern_type': 'stix',
                'x_opencti_main_observable_type': observable_type,
                'labels': labels or ['malicious-activity'],
                'confidence': max(0, min(100, confidence))
            }
            
            logger.info(f"Creating indicator: {value} ({indicator_type})")
            indicator = self.client.indicator.create(**indicator_data)
            
            if indicator and isinstance(indicator, dict):
                indicator_id = indicator.get('id', 'Unknown')
                logger.info(f"✅ Created indicator: {value} (ID: {indicator_id})")
                return indicator
            else:
                logger.error(f"❌ Unexpected result from indicator creation: {indicator}")
                return None
            
        except Exception as e:
            logger.error(f"❌ Failed to create indicator {value}: {e}")
            return None
    
    def get_database_statistics(self) -> Dict[str, Any]:
        """Get statistics from the database - CORRIGÉ"""
        try:
            cursor = self.db_conn.cursor()
            
            stats = {}
            
            # IoCs statistics - basé sur les colonnes réelles
            cursor.execute("SELECT COUNT(*) as total FROM iocs WHERE is_active = TRUE")
            stats['active_iocs'] = cursor.fetchone()['total']
            
            # Indicators statistics
            cursor.execute("SELECT COUNT(*) as total FROM indicators")
            stats['total_indicators'] = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as total FROM indicators WHERE processed = TRUE")
            stats['processed_indicators'] = cursor.fetchone()['total']
            
            # CVEs statistics
            cursor.execute("SELECT COUNT(*) as total FROM cves")
            stats['total_cves'] = cursor.fetchone()['total']
            
            # IoCs by type
            cursor.execute("""
                SELECT ioc_type, COUNT(*) as count 
                FROM iocs 
                WHERE is_active = TRUE 
                GROUP BY ioc_type
                ORDER BY count DESC
            """)
            stats['iocs_by_type'] = dict(cursor.fetchall())
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database statistics: {e}")
            return {}
        
    def add_relation_capabilities(self):
        """Ajouter les capacités de gestion des relations au connecteur"""
        self.relation_manager = OpenCTIRelationManager(self)
        logger.info("✅ Relation management capabilities added to connector")

    def create_automatic_relations(self):
        """Créer automatiquement des relations entre entités"""
        if not hasattr(self, 'relation_manager'):
            self.add_relation_capabilities()
        
        return self.relation_manager.create_basic_correlations()

    def create_enhanced_correlations_fixed(self, max_relations: int = 30):
    
     try:
        logger.info("🧠 Initializing enhanced correlation manager (FIXED VERSION)...")
        
        if self.client is None:
            logger.error("❌ OpenCTI client is not initialized")
            return {'total_relations': 0, 'error': 'OpenCTI client not available'}
        
        if self.db_conn is None:
            logger.error("❌ Database connection is not available")
            return {'total_relations': 0, 'error': 'Database connection not available'}
        
        # Créer le gestionnaire de relations corrigé
        if not hasattr(self, 'enhanced_relation_manager') or self.enhanced_relation_manager is None:
            self.enhanced_relation_manager = EnhancedRelationManager(self)
            logger.info("✅ Enhanced relation manager initialized successfully")
        
        # Utiliser la méthode corrigée
        return self.enhanced_relation_manager.create_intelligent_correlations_with_fallback(max_relations)
        
     except Exception as e:
        logger.error(f"❌ Error in create_enhanced_correlations_fixed: {e}")
        return {'total_relations': 0, 'error': str(e)}
   
    def close_connections(self):
        """Close all connections"""
        if self.db_conn:
            self.db_conn.close()
            logger.info("🔌 PostgreSQL connection closed")

class OpenCTIRelationManager:
    """Gestionnaire des relations OpenCTI - Version intégrée"""
    
    def __init__(self, opencti_connector):
        """Initialize with existing OpenCTI connector"""
        self.connector = opencti_connector
        self.client = opencti_connector.client
        self.db_conn = opencti_connector.db_conn
        self.created_relations = set()
    
    def create_relationship_graphql(self, from_id: str, to_id: str, 
                                  relationship_type: str, description: str = "",
                                  confidence: int = 75) -> Optional[Dict]:
        """Créer une relation via l'API GraphQL d'OpenCTI"""
        try:
            mutation = """
            mutation RelationshipAdd($input: RelationshipAddInput!) {
                relationshipAdd(input: $input) {
                    id
                    relationship_type
                    description
                }
            }
            """
            
            variables = {
                "input": {
                    "fromId": from_id,
                    "toId": to_id,
                    "relationship_type": relationship_type,
                    "description": description,
                    "confidence": confidence,
                    "start_time": datetime.now().isoformat() + "Z"
                }
            }
            
            headers = {
                'Authorization': f'Bearer {self.connector.config.token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.connector.config.url}/graphql",
                json={"query": mutation, "variables": variables},
                headers=headers,
                verify=self.connector.config.ssl_verify,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'data' in result and result['data']['relationshipAdd']:
                    relation = result['data']['relationshipAdd']
                    relation_key = f"{from_id}-{to_id}-{relationship_type}"
                    self.created_relations.add(relation_key)
                    logger.info(f"✅ Created relation: {relationship_type} ({relation.get('id', 'Unknown ID')})")
                    return relation
                else:
                    logger.error(f"GraphQL error: {result.get('errors', 'Unknown error')}")
            else:
                logger.error(f"HTTP error {response.status_code}: {response.text}")
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Failed to create relationship {relationship_type}: {e}")
            return None
    
    def get_opencti_entities_by_type(self, entity_type: str, limit: int = 50) -> List[Dict]:
        """Récupérer les entités depuis OpenCTI"""
        try:
            query = """
            query GetEntities($types: [String!], $first: Int) {
                stixDomainObjects(
                    types: $types
                    first: $first
                    orderBy: created_at
                    orderMode: desc
                ) {
                    edges {
                        node {
                            id
                            standard_id
                            created_at
                            ... on Indicator {
                                name
                                pattern
                                indicator_types
                                x_opencti_main_observable_type
                            }
                            ... on Vulnerability {
                                name
                                description
                                x_opencti_cvss_base_score
                            }
                        }
                    }
                }
            }
            """
            
            variables = {"types": [entity_type], "first": limit}
            headers = {
                'Authorization': f'Bearer {self.connector.config.token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{self.connector.config.url}/graphql",
                json={"query": query, "variables": variables},
                headers=headers,
                verify=self.connector.config.ssl_verify,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'data' in result:
                    entities = [edge['node'] for edge in result['data']['stixDomainObjects']['edges']]
                    logger.info(f"Retrieved {len(entities)} {entity_type} entities")
                    return entities
            
            return []
            
        except Exception as e:
            logger.error(f"Failed to get {entity_type} entities: {e}")
            return []
    
    def create_basic_correlations(self) -> Dict[str, int]:
        """Créer des corrélations basiques entre entités"""
        logger.info("🔗 Creating basic correlations...")
        
        results = {'total_relations': 0}
        
        try:
            # Récupérer les entités récentes
            indicators = self.get_opencti_entities_by_type("Indicator", limit=30)
            vulnerabilities = self.get_opencti_entities_by_type("Vulnerability", limit=20)
            
            logger.info(f"Found {len(indicators)} indicators and {len(vulnerabilities)} vulnerabilities")
            
            # Corrélations simples basées sur la proximité temporelle
            correlations_created = 0
            
            for indicator in indicators[:10]:  # Limiter pour éviter trop de relations
                for vulnerability in vulnerabilities[:5]:
                    # Vérifier si créés dans les 48h
                    if self._is_recent_correlation(indicator, vulnerability):
                        description = "Automated correlation: temporal proximity and threat context"
                        
                        relation = self.create_relationship_graphql(
                            from_id=indicator['id'],
                            to_id=vulnerability['id'],
                            relationship_type="related-to",
                            description=description,
                            confidence=60
                        )
                        
                        if relation:
                            correlations_created += 1
                            time.sleep(0.3)  # Pause pour éviter la surcharge
                        
                        # Limiter le nombre de relations par indicateur
                        if correlations_created >= 5:
                            break
                
                if correlations_created >= 10:  # Limite globale
                    break
            
            results['total_relations'] = correlations_created
            logger.info(f"✅ Created {correlations_created} basic correlations")
            
        except Exception as e:
            logger.error(f"Error in basic correlations: {e}")
        
        return results
    
    def _is_recent_correlation(self, entity1: Dict, entity2: Dict, hours_threshold: int = 48) -> bool:
        """Vérifie si deux entités sont corrélées temporellement"""
        try:
            created1 = datetime.fromisoformat(entity1['created_at'].replace('Z', '+00:00'))
            created2 = datetime.fromisoformat(entity2['created_at'].replace('Z', '+00:00'))
            
            time_diff = abs((created1 - created2).total_seconds() / 3600)
            return time_diff <= hours_threshold
        except Exception as e:
            logger.debug(f"Temporal correlation check failed: {e}")
            return False

# Méthode à ajouter à la classe OpenCTIConnector
    def add_relation_capabilities(self):
        """Ajouter les capacités de gestion des relations au connecteur"""
        self.relation_manager = OpenCTIRelationManager(self)
        logger.info("✅ Relation management capabilities added to connector")

    def create_automatic_relations(self):
        """Créer automatiquement des relations entre entités"""
        if not hasattr(self, 'relation_manager'):
            self.add_relation_capabilities()
        
        return self.relation_manager.create_basic_correlations()

    def create_enhanced_correlations(self, max_relations: int = 50):
        """Créer des corrélations avancées entre entités"""
        try:
            logger.info("🧠 Initializing enhanced correlation manager...")
            
            # Vérifier les prérequis
            if self.client is None:
                logger.error("❌ OpenCTI client is not initialized")
                return {'total_relations': 0, 'error': 'OpenCTI client not available'}
            
            if self.db_conn is None:
                logger.error("❌ Database connection is not available")
                return {'total_relations': 0, 'error': 'Database connection not available'}
            
            # Créer le gestionnaire de relations avancées
            self.enhanced_relation_manager = EnhancedRelationManager(self)
            
            logger.info("✅ Enhanced relation manager initialized successfully")
            
            # Créer les corrélations intelligentes avec fallback
            return self.enhanced_relation_manager.create_intelligent_correlations_with_fallback(max_relations)
            
        except Exception as e:
            logger.error(f"❌ Error in create_enhanced_correlations: {e}")
            logger.exception("Full traceback:")
            
            # Fallback vers les corrélations basiques
            logger.info("🔄 Falling back to basic correlations...")
            try:
                return self.create_automatic_relations()
            except Exception as fallback_error:
                logger.error(f"❌ Fallback also failed: {fallback_error}")
                return {'total_relations': 0, 'error': str(e)} 
# Ajouter les méthodes à la classe OpenCTIConnector
# Example usage
if __name__ == "__main__":
    try:
        print("🚀 OpenCTI Database Connector - Production Ready")
        print("=" * 50)
        
        # Initialize connector
        connector = OpenCTIConnector()
        
        # Get database statistics
        print("\n📊 Database Statistics:")
        db_stats = connector.get_database_statistics()
        for key, value in db_stats.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for sub_key, sub_value in value.items():
                    print(f"    {sub_key}: {sub_value}")
            else:
                print(f"  {key}: {value}")
        
        # Demander si on veut reprocesser les indicateurs déjà traités
        print(f"\n⚠️  Warning: {db_stats.get('processed_indicators', 0)} indicators are already marked as processed.")
        reprocess = input("Do you want to reprocess ALL indicators anyway? (y/N): ").lower().strip()
        force_reprocess = reprocess in ['y', 'yes', 'oui']
        
        if force_reprocess:
            print("🔄 Will reprocess ALL indicators (including already processed ones)")
        else:
            print("🔄 Will only process unprocessed indicators")
        
        # Synchronize data to OpenCTI avec le paramètre force_reprocess
        print(f"\n🔄 Starting synchronization...")
        results = connector.sync_all_data_to_opencti(batch_size=50, force_reprocess=force_reprocess)
        
        print(f"\n📋 Synchronization Results:")
        print(f"  ✅ IoCs processed: {results['iocs_processed']}")
        print(f"  ✅ Indicators processed: {results['indicators_processed']}")
        print(f"  ✅ Vulnerabilities processed: {results['vulnerabilities_processed']}")
        print(f"  📊 Total success: {results['total_success']}")
        print(f"  ❌ Total failed: {results['total_failed']}")
        
        if results['indicators_processed'] == 0 and not force_reprocess:
            print(f"\n💡 Tip: If you want to resend indicators to OpenCTI, run again and choose 'y' when asked about reprocessing.")
        
        # Optionnel: Créer des corrélations automatiques
        create_correlations = input("\nDo you want to create automatic correlations? (y/N): ").lower().strip()
        if create_correlations in ['y', 'yes', 'oui']:
            print("\n🧠 Creating intelligent correlations...")
            correlation_results = connector.create_enhanced_correlations_fixed(max_relations=30)
            
            print(f"\n🔗 Correlation Results:")
            print(f"  ✅ Total relations created: {correlation_results['total_relations']}")
            
            if correlation_results.get('by_rule'):
                print("  📋 By rule:")
                for rule_name, count in correlation_results['by_rule'].items():
                    if count > 0:
                        print(f"    {rule_name}: {count}")
        
        print(f"\n🎉 Processing completed!")
        print(f"   Check your data at: {connector.config.url}/dashboard")
        
        # Close connections
        connector.close_connections()
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Process interrupted by user")
        if 'connector' in locals():
            connector.close_connections()
    except Exception as e:
        print(f"❌ Critical Error: {e}")
        logger.exception("Critical error occurred")
        if 'connector' in locals():
            connector.close_connections()