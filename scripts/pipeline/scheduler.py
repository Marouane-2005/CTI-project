#!/usr/bin/env python3
"""
Planificateur de tâches CTI pour l'automatisation des processus
Compatible avec l'architecture existante
"""

import os
import sys
import json
import time
import schedule
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
import subprocess
import signal

# Ajout du répertoire parent au chemin
sys.path.append(str(Path(__file__).parent.parent))

from utils.logger import get_logger
from scripts.utils.database import DatabaseManager


class CTIScheduler:
    """Planificateur principal pour les tâches CTI"""
    
    def __init__(self, config_path: str = "config/opencti_config.json"):
        """Initialisation du planificateur"""
        self.logger = get_logger(__name__)
        self.config_path = config_path
        self.config = self._load_config()
        self.db = DatabaseManager()
        
        # État du planificateur
        self.is_running = False
        self.tasks_status = {}
        self.scheduler_thread = None
        
        # Statistiques
        self.stats = {
            "tasks_executed": 0,
            "tasks_failed": 0,
            "last_execution": None,
            "uptime_start": datetime.now()
        }
        
        self.logger.info("✅ Planificateur CTI initialisé")
    
    def _load_config(self) -> Dict:
        """Chargement de la configuration"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                # Configuration par défaut
                return {
                    "scheduler": {
                        "enabled": True,
                        "timezone": "UTC",
                        "max_concurrent_tasks": 3,
                        "retry_failed_tasks": True,
                        "retry_delay_minutes": 15,
                        "health_check_interval": 60
                    },
                    "tasks": {
                        "sync_opencti": {
                            "enabled": True,
                            "schedule": "*/5 * * * *",  # Toutes les 5 minutes
                            "command": "python -m scripts.pipeline.opencti_connector --once",
                            "timeout": 300,
                            "retry_count": 3
                        },
                        "collect_feeds": {
                            "enabled": True,
                            "schedule": "0 */4 * * *",  # Toutes les 4 heures
                            "command": "python scripts/collectors/feed_collector.py",
                            "timeout": 1800,
                            "retry_count": 2
                        },
                        "analyze_threats": {
                            "enabled": True,
                            "schedule": "30 */6 * * *",  # Toutes les 6 heures
                            "command": "python scripts/analyzers/threat_analyzer.py",
                            "timeout": 3600,
                            "retry_count": 1
                        },
                        "generate_reports": {
                            "enabled": True,
                            "schedule": "0 8 * * *",  # Tous les jours à 8h
                            "command": "python scripts/generators/daily_report_generator.py",
                            "timeout": 1200,
                            "retry_count": 2
                        },
                        "cleanup_old_data": {
                            "enabled": True,
                            "schedule": "0 2 * * 0",  # Chaque dimanche à 2h
                            "command": "python scripts/utils/cleanup_manager.py",
                            "timeout": 7200,
                            "retry_count": 1
                        },
                        "health_check": {
                            "enabled": True,
                            "schedule": "*/1 * * * *",  # Chaque minute
                            "command": "python -m scripts.pipeline.health_check",
                            "timeout": 60,
                            "retry_count": 1
                        }
                    }
                }
        except Exception as e:
            self.logger.error(f"❌ Erreur chargement configuration: {e}")
            return {}
    
    def setup_tasks(self):
        """Configuration des tâches programmées"""
        try:
            self.logger.info("⚙️ Configuration des tâches programmées...")
            
            tasks_config = self.config.get("tasks", {})
            
            for task_name, task_config in tasks_config.items():
                if not task_config.get("enabled", False):
                    self.logger.info(f"⏸️ Tâche désactivée: {task_name}")
                    continue
                
                # Configuration de la tâche
                cron_schedule = task_config.get("schedule", "0 * * * *")
                command = task_config.get("command", "")
                timeout = task_config.get("timeout", 300)
                retry_count = task_config.get("retry_count", 1)
                
                if not command:
                    self.logger.warning(f"⚠️ Commande vide pour la tâche: {task_name}")
                    continue
                
                # Conversion du cron vers schedule
                self._schedule_task(task_name, cron_schedule, command, timeout, retry_count)
                
                # Initialisation du statut
                self.tasks_status[task_name] = {
                    "enabled": True,
                    "last_run": None,
                    "last_status": "pending",
                    "next_run": None,
                    "execution_count": 0,
                    "failure_count": 0,
                    "average_duration": 0
                }
            
            self.logger.info(f"✅ {len([t for t in tasks_config.values() if t.get('enabled')])} tâches configurées")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur configuration des tâches: {e}")
    
    def _schedule_task(self, task_name: str, cron_schedule: str, command: str, timeout: int, retry_count: int):
        """Planification d'une tâche individuelle"""
        try:
            # Parsing du cron (format: minute hour day month weekday)
            cron_parts = cron_schedule.split()
            if len(cron_parts) != 5:
                self.logger.error(f"❌ Format cron invalide pour {task_name}: {cron_schedule}")
                return
            
            minute, hour, day, month, weekday = cron_parts
            
            # Création de la fonction de tâche
            task_func = lambda: self._execute_task(task_name, command, timeout, retry_count)
            
            # Planification selon le format cron
            if minute.startswith("*/"):
                # Toutes les X minutes
                interval = int(minute[2:])
                schedule.every(interval).minutes.do(task_func).tag(task_name)
            elif hour.startswith("*/"):
                # Toutes les X heures
                interval = int(hour[2:])
                schedule.every(interval).hours.do(task_func).tag(task_name)
            elif hour.isdigit() and minute.isdigit():
                # Heure fixe quotidienne
                time_str = f"{hour.zfill(2)}:{minute.zfill(2)}"
                if weekday.isdigit() and weekday != "*":
                    # Jour spécifique de la semaine
                    weekdays = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
                    day_name = weekdays[int(weekday)]
                    getattr(schedule.every(), day_name).at(time_str).do(task_func).tag(task_name)
                else:
                    # Tous les jours
                    schedule.every().day.at(time_str).do(task_func).tag(task_name)
            else:
                # Planification par défaut (toutes les heures)
                schedule.every().hour.do(task_func).tag(task_name)
            
            self.logger.info(f"📅 Tâche planifiée: {task_name} -> {cron_schedule}")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur planification tâche {task_name}: {e}")
    
    def _execute_task(self, task_name: str, command: str, timeout: int, retry_count: int):
        """Exécution d'une tâche avec gestion des erreurs et des retries"""
        start_time = datetime.now()
        
        try:
            self.logger.info(f"🚀 Exécution de la tâche: {task_name}")
            
            # Mise à jour du statut
            self.tasks_status[task_name].update({
                "last_run": start_time,
                "last_status": "running"
            })
            
            # Tentatives d'exécution
            for attempt in range(retry_count + 1):
                try:
                    # Exécution de la commande
                    result = subprocess.run(
                        command,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                        cwd=Path(__file__).parent.parent.parent  # Répertoire racine du projet
                    )
                    
                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()
                    
                    if result.returncode == 0:
                        # Succès
                        self.logger.info(f"✅ Tâche réussie: {task_name} (durée: {duration:.2f}s)")
                        
                        self.tasks_status[task_name].update({
                            "last_status": "success",
                            "execution_count": self.tasks_status[task_name]["execution_count"] + 1,
                            "average_duration": self._update_average_duration(task_name, duration)
                        })
                        
                        self.stats["tasks_executed"] += 1
                        self.stats["last_execution"] = end_time
                        
                        # Log de la sortie si nécessaire
                        if result.stdout:
                            self.logger.debug(f"Sortie {task_name}: {result.stdout}")
                        
                        return True
                    else:
                        # Échec - tentative suivante
                        error_msg = result.stderr or "Erreur inconnue"
                        self.logger.warning(f"⚠️ Tentative {attempt + 1}/{retry_count + 1} échouée pour {task_name}: {error_msg}")
                        
                        if attempt < retry_count:
                            time.sleep(30)  # Attente avant retry
                        continue
                
                except subprocess.TimeoutExpired:
                    self.logger.error(f"⏰ Timeout de la tâche {task_name} (tentative {attempt + 1})")
                    if attempt < retry_count:
                        time.sleep(30)
                        continue
                except Exception as e:
                    self.logger.error(f"❌ Erreur exécution tâche {task_name} (tentative {attempt + 1}): {e}")
                    if attempt < retry_count:
                        time.sleep(30)
                        continue
            
            # Toutes les tentatives ont échoué
            self.logger.error(f"❌ Échec définitif de la tâche: {task_name}")
            
            self.tasks_status[task_name].update({
                "last_status": "failed",
                "failure_count": self.tasks_status[task_name]["failure_count"] + 1
            })
            
            self.stats["tasks_failed"] += 1
            return False
            
        except Exception as e:
            self.logger.error(f"❌ Erreur critique lors de l'exécution de {task_name}: {e}")
            
            self.tasks_status[task_name]["last_status"] = "error"
            self.stats["tasks_failed"] += 1
            return False
    
    def _update_average_duration(self, task_name: str, new_duration: float) -> float:
        """Mise à jour de la durée moyenne d'exécution"""
        current_avg = self.tasks_status[task_name]["average_duration"]
        execution_count = self.tasks_status[task_name]["execution_count"]
        
        if execution_count == 0:
            return new_duration
        else:
            return (current_avg * (execution_count - 1) + new_duration) / execution_count
    
    def start(self):
        """Démarrage du planificateur"""
        try:
            self.logger.info("🎯 Démarrage du planificateur CTI")
            
            # Configuration des tâches
            self.setup_tasks()
            
            # Démarrage du thread principal
            self.is_running = True
            self.scheduler_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.scheduler_thread.start()
            
            self.logger.info("✅ Planificateur démarré avec succès")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors du démarrage: {e}")
            self.stop()
    
    def _run_scheduler(self):
        """Boucle principale du planificateur"""
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"❌ Erreur dans la boucle du planificateur: {e}")
                time.sleep(60)  # Attente avant reprise
    
    def stop(self):
        """Arrêt du planificateur"""
        try:
            self.logger.info("🛑 Arrêt du planificateur...")
            
            self.is_running = False
            
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=10)
            
            # Nettoyage des tâches
            schedule.clear()
            
            self.logger.info("✅ Planificateur arrêté")
            
        except Exception as e:
            self.logger.error(f"❌ Erreur lors de l'arrêt: {e}")
    
    def get_status(self) -> Dict:
        """Récupération du statut du planificateur"""
        uptime = datetime.now() - self.stats["uptime_start"]
        
        return {
            "scheduler": {
                "is_running": self.is_running,
                "uptime_seconds": int(uptime.total_seconds()),
                "uptime_human": str(uptime)
            },
            "stats": self.stats.copy(),
            "tasks": self.tasks_status.copy(),
            "next_runs": self._get_next_runs()
        }
    
    def _get_next_runs(self) -> Dict:
        """Récupération des prochaines exécutions"""
        next_runs = {}
        
        for job in schedule.jobs:
            task_name = job.tags.pop() if job.tags else "unknown"
            next_run = job.next_run
            next_runs[task_name] = next_run.isoformat() if next_run else None
            
        return next_runs
    
    def pause_task(self, task_name: str) -> bool:
        """Suspension d'une tâche"""
        try:
            schedule.clear(task_name)
            if task_name in self.tasks_status:
                self.tasks_status[task_name]["enabled"] = False
            
            self.logger.info(f"⏸️ Tâche suspendue: {task_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Erreur suspension tâche {task_name}: {e}")
            return False
    
    def resume_task(self, task_name: str) -> bool:
        """Reprise d'une tâche"""
        try:
            # Reconfiguration de la tâche
            task_config = self.config.get("tasks", {}).get(task_name)
            if task_config:
                self._schedule_task(
                    task_name,
                    task_config["schedule"],
                    task_config["command"],
                    task_config.get("timeout", 300),
                    task_config.get("retry_count", 1)
                )
                
                if task_name in self.tasks_status:
                    self.tasks_status[task_name]["enabled"] = True
                
                self.logger.info(f"▶️ Tâche reprise: {task_name}")
                return True
            else:
                self.logger.error(f"❌ Configuration introuvable pour la tâche: {task_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Erreur reprise tâche {task_name}: {e}")
            return False
    
    def execute_task_now(self, task_name: str) -> bool:
        """Exécution immédiate d'une tâche"""
        try:
            task_config = self.config.get("tasks", {}).get(task_name)
            if not task_config:
                self.logger.error(f"❌ Tâche introuvable: {task_name}")
                return False
            
            self.logger.info(f"⚡ Exécution immédiate de la tâche: {task_name}")
            
            return self._execute_task(
                task_name,
                task_config["command"],
                task_config.get("timeout", 300),
                task_config.get("retry_count", 1)
            )
            
        except Exception as e:
            self.logger.error(f"❌ Erreur exécution immédiate {task_name}: {e}")
            return False


def signal_handler(signum, frame):
    """Gestionnaire de signaux pour arrêt propre"""
    global scheduler_instance
    print("\n🛑 Signal d'arrêt reçu...")
    if scheduler_instance:
        scheduler_instance.stop()
    sys.exit(0)


def main():
    """Point d'entrée principal"""
    global scheduler_instance
    
    import argparse
    
    parser = argparse.ArgumentParser(description="Planificateur CTI")
    parser.add_argument("--config", help="Chemin vers le fichier de configuration")
    parser.add_argument("--status", action="store_true", help="Affichage du statut")
    parser.add_argument("--execute", help="Exécution immédiate d'une tâche")
    parser.add_argument("--pause", help="Suspension d'une tâche")
    parser.add_argument("--resume", help="Reprise d'une tâche")
    
    args = parser.parse_args()
    
    # Création du planificateur
    scheduler_instance = CTIScheduler(config_path=args.config)
    
    # Gestion des signaux
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        if args.status:
            # Affichage du statut
            status = scheduler_instance.get_status()
            print(json.dumps(status, indent=2, default=str))
            
        elif args.execute:
            # Exécution immédiate
            success = scheduler_instance.execute_task_now(args.execute)
            sys.exit(0 if success else 1)
            
        elif args.pause:
            # Suspension d'une tâche
            success = scheduler_instance.pause_task(args.pause)
            sys.exit(0 if success else 1)
            
        elif args.resume:
            # Reprise d'une tâche
            success = scheduler_instance.resume_task(args.resume)
            sys.exit(0 if success else 1)
            
        else:
            # Mode normal - démarrage du planificateur
            scheduler_instance.start()
            
            # Attente infinie
            while scheduler_instance.is_running:
                time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n👋 Arrêt demandé par l'utilisateur")
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        sys.exit(1)
    finally:
        if scheduler_instance:
            scheduler_instance.stop()


if __name__ == "__main__":
    main()