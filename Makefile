.PHONY: help install test build deploy clean status logs shell

DOCKER_COMPOSE = docker-compose -f docker/docker-compose.yml
PROJECT_NAME = cti-project

help: ## 📋 Afficher cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## 🚀 Configuration initiale du projet
	@echo "🔧 Configuration initiale..."
	@cp .env.example .env
	@mkdir -p logs output/daily_feeds output/excel_reports
	@chmod +x scripts/pipeline/*.sh
	@echo "✅ Configuration terminée. Éditez le fichier .env avec vos valeurs."

install: ## 📦 Installer les dépendances
	python -m pip install --upgrade pip
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test: ## 🧪 Lancer les tests
	python -m pytest tests/ -v --cov=scripts --cov-report=html

lint: ## 🔍 Vérifier la qualité du code
	flake8 scripts/
	black --check scripts/

format: ## ✨ Formater le code
	black scripts/
	isort scripts/

build: ## 🏗️ Construire les images Docker
	$(DOCKER_COMPOSE) build

up: ## ▶️ Démarrer tous les services
	$(DOCKER_COMPOSE) up -d

down: ## ⏹️ Arrêter tous les services
	$(DOCKER_COMPOSE) down

restart: ## 🔄 Redémarrer les services
	$(DOCKER_COMPOSE) restart

logs: ## 📋 Voir les logs en temps réel
	$(DOCKER_COMPOSE) logs -f

status: ## 📊 Statut des services
	$(DOCKER_COMPOSE) ps

shell: ## 🖥️ Shell dans le conteneur principal
	$(DOCKER_COMPOSE) exec cti-app bash

opencti-shell: ## 🖥️ Shell OpenCTI
	docker exec -it opencti_opencti_1 bash

sync-now: ## ⚡ Synchronisation manuelle immédiate
	$(DOCKER_COMPOSE) exec cti-app python -m scripts.pipeline.opencti_connector --once

health: ## 🏥 Vérification de santé des services
	@echo "🏥 Vérification des services..."
	@$(DOCKER_COMPOSE) exec cti-app python -m scripts.pipeline.health_check

deploy: ## 🚀 Déploiement en production
	@echo "🚀 Déploiement en cours..."
	./scripts/pipeline/deploy.sh

backup: ## 💾 Sauvegarde des données
	@echo "💾 Création de la sauvegarde..."
	@mkdir -p backups/$(shell date +%Y%m%d_%H%M%S)
	@tar -czf backups/$(shell date +%Y%m%d_%H%M%S)/backup.tar.gz \
		--exclude=venv --exclude=venv312 --exclude=__pycache__ \
		--exclude=.git --exclude=logs/*.log .

clean: ## 🧹 Nettoyer les ressources
	$(DOCKER_COMPOSE) down -v --remove-orphans
	docker system prune -f
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -delete
	find . -name ".pytest_cache" -exec rm -rf {} +

init-opencti: ## 🔧 Initialiser OpenCTI
	@echo "🔧 Initialisation d'OpenCTI..."
	docker network create cti-network || true
	$(DOCKER_COMPOSE) -f docker/opencti/docker-compose.opencti.yml up -d

stop-opencti: ## ⏹️ Arrêter OpenCTI
	$(DOCKER_COMPOSE) -f docker/opencti/docker-compose.opencti.yml down

dev: ## 🛠️ Mode développement
	@echo "🛠️ Démarrage en mode développement..."
	export ENVIRONMENT=development && $(DOCKER_COMPOSE) up

prod: ## 🏭 Mode production
	@echo "🏭 Démarrage en mode production..."
	export ENVIRONMENT=production && $(DOCKER_COMPOSE) up -d

monitor: ## 📊 Monitoring des performances
	@echo "📊 Monitoring en cours..."
	htop || top
# MITRE ATT&CK commands
setup-mitre:
	@echo "Setting up MITRE ATT&CK integration..."
	@./scripts/setup_mitre.sh

sync-mitre:
	@echo "Syncing MITRE data..."
	@python -c "import asyncio; from pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher; asyncio.run(MitreAttackEnricher().update_mitre_data())"

test-mitre:
	@echo "Testing MITRE integration..."
	@pytest tests/test_mitre_integration.py -v

mitre-stats:
	@echo "Getting MITRE statistics..."
	@python -c "from pipeline.enrichers.mitre_attack_enricher import MitreAttackEnricher; import json; print(json.dumps(MitreAttackEnricher().get_attack_statistics(), indent=2))"	
