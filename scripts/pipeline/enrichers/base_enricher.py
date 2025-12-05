# pipeline/enrichers/base_enricher.py

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging
import json
import os
from datetime import datetime

class BaseEnricher(ABC):
    """Classe de base pour tous les enrichisseurs CTI"""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = self._load_config()
        self.metrics = {
            "total_processed": 0,
            "successful_enrichments": 0,
            "failed_enrichments": 0,
            "last_run": None,
            "average_processing_time": 0.0
        }
        
    def _load_config(self) -> Dict:
        """Charge la configuration de l'enrichisseur"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.logger.info(f"Configuration loaded from {self.config_path}")
                return config
            else:
                self.logger.warning(f"Config file not found: {self.config_path}, using defaults")
                return self._get_default_config()
                
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Retourne la configuration par défaut"""
        return {
            "enabled": True,
            "timeout": 30,
            "retry_attempts": 3,
            "batch_size": 100,
            "rate_limit": 10  # requêtes par minute
        }
    
    @abstractmethod
    async def enrich(self, data: Dict) -> Dict:
        """
        Méthode principale d'enrichissement
        
        Args:
            data: Données à enrichir
            
        Returns:
            Dict: Données enrichies
        """
        pass
    
    @abstractmethod
    def validate_data(self, data: Dict) -> bool:
        """
        Valide les données d'entrée
        
        Args:
            data: Données à valider
            
        Returns:
            bool: True si les données sont valides
        """
        pass
    
    async def process_batch(self, data_batch: List[Dict]) -> List[Dict]:
        """
        Traite un lot de données
        
        Args:
            data_batch: Liste de données à traiter
            
        Returns:
            List[Dict]: Liste des données enrichies
        """
        enriched_data = []
        start_time = datetime.now()
        
        for data in data_batch:
            try:
                if self.validate_data(data):
                    enriched = await self.enrich(data)
                    enriched_data.append(enriched)
                    self.metrics["successful_enrichments"] += 1
                else:
                    self.logger.warning(f"Invalid data skipped: {data.get('id', 'unknown')}")
                    self.metrics["failed_enrichments"] += 1
                    
            except Exception as e:
                self.logger.error(f"Error enriching data {data.get('id', 'unknown')}: {e}")
                self.metrics["failed_enrichments"] += 1
                # Ajouter les données non enrichies pour éviter la perte
                enriched_data.append(data)
        
        # Mettre à jour les métriques
        processing_time = (datetime.now() - start_time).total_seconds()
        self.metrics["total_processed"] += len(data_batch)
        self.metrics["last_run"] = datetime.now().isoformat()
        
        # Calculer le temps moyen de traitement
        if self.metrics["total_processed"] > 0:
            total_time = (self.metrics["average_processing_time"] * 
                         (self.metrics["total_processed"] - len(data_batch)) + processing_time)
            self.metrics["average_processing_time"] = total_time / self.metrics["total_processed"]
        
        return enriched_data
    
    def get_metrics(self) -> Dict:
        """Retourne les métriques de performance"""
        return self.metrics.copy()
    
    def reset_metrics(self):
        """Remet à zéro les métriques"""
        self.metrics = {
            "total_processed": 0,
            "successful_enrichments": 0,
            "failed_enrichments": 0,
            "last_run": None,
            "average_processing_time": 0.0
        }
        self.logger.info("Metrics reset")
    
    def is_enabled(self) -> bool:
        """Vérifie si l'enrichisseur est activé"""
        return self.config.get("enabled", True)
    
    def get_config(self) -> Dict:
        """Retourne la configuration actuelle"""
        return self.config.copy()
    
    def update_config(self, new_config: Dict):
        """Met à jour la configuration"""
        try:
            self.config.update(new_config)
            
            # Sauvegarder la nouvelle configuration
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
                
            self.logger.info("Configuration updated successfully")
            
        except Exception as e:
            self.logger.error(f"Error updating config: {e}")
    
    def get_health_status(self) -> Dict:
        """Retourne le statut de santé de l'enrichisseur"""
        try:
            # Calculer le taux de succès
            total_attempts = (self.metrics["successful_enrichments"] + 
                            self.metrics["failed_enrichments"])
            success_rate = (self.metrics["successful_enrichments"] / total_attempts * 100 
                          if total_attempts > 0 else 0)
            
            # Déterminer le statut
            if success_rate >= 95:
                status = "healthy"
            elif success_rate >= 80:
                status = "warning"
            else:
                status = "critical"
            
            return {
                "status": status,
                "success_rate": round(success_rate, 2),
                "total_processed": self.metrics["total_processed"],
                "last_run": self.metrics["last_run"],
                "enabled": self.is_enabled(),
                "average_processing_time": round(self.metrics["average_processing_time"], 3)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting health status: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def __str__(self) -> str:
        """Représentation string de l'enrichisseur"""
        return f"{self.__class__.__name__}(enabled={self.is_enabled()}, processed={self.metrics['total_processed']})"
    
    def __repr__(self) -> str:
        """Représentation détaillée de l'enrichisseur"""
        return (f"{self.__class__.__name__}("
                f"config_path='{self.config_path}', "
                f"enabled={self.is_enabled()}, "
                f"metrics={self.metrics})")

class EnrichmentError(Exception):
    """Exception personnalisée pour les erreurs d'enrichissement"""
    
    def __init__(self, message: str, enricher_name: str = None, data_id: str = None):
        self.enricher_name = enricher_name
        self.data_id = data_id
        super().__init__(message)
    
    def __str__(self):
        parts = [super().__str__()]
        if self.enricher_name:
            parts.append(f"Enricher: {self.enricher_name}")
        if self.data_id:
            parts.append(f"Data ID: {self.data_id}")
        return " | ".join(parts)
    
    def enrich_with_dashboard_notification(self, data):
     enriched = self.existing_enrich_method(data)
    
    # Notification dashboard
     dashboard_data = {
        'enrichment_type': self.enricher_type,
        'original_data': data,
        'enriched_data': enriched,
        'confidence_score': self.calculate_confidence(enriched)
    }
     self.notify_dashboard(dashboard_data)
     return enriched

class EnrichmentResult:
    """Classe pour encapsuler le résultat d'un enrichissement"""
    
    def __init__(self, original_data: Dict, enriched_data: Dict, 
                 success: bool, error: Optional[str] = None,
                 processing_time: float = 0.0, enricher_name: str = None):
        self.original_data = original_data
        self.enriched_data = enriched_data
        self.success = success
        self.error = error
        self.processing_time = processing_time
        self.enricher_name = enricher_name
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convertit le résultat en dictionnaire"""
        return {
            "success": self.success,
            "error": self.error,
            "processing_time": self.processing_time,
            "enricher_name": self.enricher_name,
            "timestamp": self.timestamp.isoformat(),
            "data_id": self.original_data.get("id", "unknown"),
            "enrichment_count": len(self.enriched_data) - len(self.original_data) if self.success else 0
        }