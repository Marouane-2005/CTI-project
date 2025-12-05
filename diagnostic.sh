#!/bin/bash

echo "🔍 DIAGNOSTIC PRE-BUILD - CTI Project"
echo "====================================="

# Fonction pour tester l'importation Python
test_import() {
    echo "🐍 Test d'importation de $1:"
    python -c "
import sys
sys.path.append('.')
try:
    import $1
    print('  ✅ $1 importable')
except ImportError as e:
    print('  ❌ Erreur import $1: ' + str(e))
except Exception as e:
    print('  ⚠️ Autre erreur $1: ' + str(e))
" 2>/dev/null
}

# 1. Vérification des fichiers critiques
echo "📁 Vérification des fichiers existants:"
echo "--------------------------------------"

files_to_check=(
    "pipeline/__init__.py"
    "pipeline/scheduler.py" 
    "pipeline/health_check.py"
    "pipeline/opencti_connector.py"
    "pipeline/data_processor.py"
    "scripts/collectors/main_collector.py"
    "scripts/analyzers/cve_analyzer.py"
    "scripts/generators/excel_generator.py"
    "requirements.txt"
    ".env"
)

for file in "${files_to_check[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file existe"
    else
        echo "  ❌ $file manquant"
    fi
done

echo ""

# 2. Test des imports Python
echo "🐍 Test d'importation des modules:"
echo "----------------------------------"

test_import "pipeline"
test_import "scripts.collectors"
test_import "scripts.analyzers"
test_import "scripts.generators"
test_import "utils"

echo ""

# 3. Vérification du contenu pipeline/__init__.py
echo "📋 Analyse de pipeline/__init__.py:"
echo "-----------------------------------"

if [ -f "pipeline/__init__.py" ]; then
    echo "Contenu (premières lignes):"
    head -20 "pipeline/__init__.py" | sed 's/^/  /'
    
    echo ""
    echo "Imports détectés:"
    grep "^from \." "pipeline/__init__.py" | sed 's/^/  /' || echo "  Aucun import relatif trouvé"
    grep "^import " "pipeline/__init__.py" | sed 's/^/  /' || echo "  Aucun import direct trouvé"
else
    echo "  ❌ pipeline/__init__.py n'existe pas"
fi

echo ""

# 4. Vérification des variables d'environnement
echo "🔐 Variables d'environnement critiques:"
echo "--------------------------------------"

env_vars=(
    "OPENCTI_URL"
    "OPENCTI_TOKEN"
    "DB_HOST"
    "DB_PASSWORD"
)

if [ -f ".env" ]; then
    echo "Fichier .env trouvé, vérification:"
    for var in "${env_vars[@]}"; do
        if grep -q "^${var}=" ".env"; then
            echo "  ✅ $var défini dans .env"
        else
            echo "  ❌ $var manquant dans .env"
        fi
    done
else
    echo "  ⚠️ Pas de fichier .env trouvé"
fi

echo ""

# 5. Test de construction minimale
echo "🔨 Test de construction Docker (dry-run):"
echo "-----------------------------------------"

echo "Vérification du Dockerfile:"
if [ -f "docker/Dockerfile" ]; then
    echo "  ✅ docker/Dockerfile existe"
    echo "  Lignes FROM détectées:"
    grep "^FROM" "docker/Dockerfile" | sed 's/^/    /'
else
    echo "  ❌ docker/Dockerfile manquant"
fi

echo ""

# 6. Recommandations
echo "💡 RECOMMANDATIONS:"
echo "==================="

echo "✅ ACTIONS SÛRES à effectuer:"
echo "  1. Utiliser le Dockerfile ultra-sécurisé"
echo "  2. Tester avec: docker-compose build --no-cache cti-scheduler"
echo "  3. En cas d'erreur, regarder les logs détaillés"

echo ""
echo "⚠️ SI VOUS AVEZ DES ERREURS D'IMPORT:"
echo "  1. Vérifiez que tous vos modules existent"
echo "  2. Corrigez les imports dans pipeline/__init__.py"
echo "  3. Puis utilisez le Dockerfile minimal"

echo ""
echo "🏁 Diagnostic terminé. Prêt pour docker-compose build!"