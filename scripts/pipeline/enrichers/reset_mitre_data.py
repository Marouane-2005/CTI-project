#!/usr/bin/env python3
import os
import sqlite3
from pathlib import Path

# Supprimer la base de données locale
db_path = "data/mitre_attack.db"
if os.path.exists(db_path):
    os.remove(db_path)
    print("✅ Base de données locale supprimée")

# Forcer les variables d'environnement
os.environ["FORCE_OPENCTI_UPDATE"] = "true"
os.environ["FORCE_RECREATE_ENTITIES"] = "true"
os.environ["OPENCTI_CLEANUP_FIRST"] = "true"
os.environ["MITRE_UPDATE_DATA"] = "true"

print("🔄 Redémarrage avec mise à jour forcée...")