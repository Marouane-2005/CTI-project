#!/usr/bin/env python3
"""
Script de diagnostic et correction de la base de données CTI
Corrige les problèmes de structure de table alerts
"""

import psycopg2
import json
from datetime import datetime
from psycopg2.extras import RealDictCursor

class CTIDatabaseFixer:
    def __init__(self):
        self.db_config = {
            'host': 'cti-postgres',
            'port': 5432,
            'database': 'cti_db',
            'user': 'cti_user',
            'password': 'cti_password'
        }
        self.connection = None
        self.connect_db()
    
    def connect_db(self):
        """Connexion à PostgreSQL"""
        try:
            self.connection = psycopg2.connect(**self.db_config)
            print("✅ Connexion DB réussie")
        except Exception as e:
            print(f"❌ Erreur connexion DB: {e}")
            return False
        return True
    
    def diagnose_alerts_table(self):
        """Diagnostic de la table alerts"""
        print("\n🔍 === DIAGNOSTIC TABLE ALERTS ===")
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Vérifier si la table existe
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'alerts'
                    );
                """)
                
                table_exists = cursor.fetchone()[0]
                print(f"Table 'alerts' existe: {table_exists}")
                
                if table_exists:
                    # Examiner la structure de la table
                    cursor.execute("""
                        SELECT column_name, data_type, is_nullable, column_default
                        FROM information_schema.columns 
                        WHERE table_name = 'alerts'
                        ORDER BY ordinal_position;
                    """)
                    
                    columns = cursor.fetchall()
                    print(f"Structure actuelle de la table alerts:")
                    for col in columns:
                        print(f"  - {col['column_name']}: {col['data_type']} (nullable: {col['is_nullable']})")
                    
                    # Compter les enregistrements
                    cursor.execute("SELECT COUNT(*) as count FROM alerts")
                    count = cursor.fetchone()['count']
                    print(f"Nombre d'enregistrements: {count}")
                    
                    if count > 0:
                        # Afficher quelques exemples
                        cursor.execute("SELECT * FROM alerts LIMIT 3")
                        samples = cursor.fetchall()
                        print(f"Exemples d'enregistrements:")
                        for i, sample in enumerate(samples, 1):
                            print(f"  [{i}] {dict(sample)}")
                else:
                    print("❌ Table 'alerts' n'existe pas")
                
                return table_exists, columns if table_exists else []
                
        except Exception as e:
            print(f"❌ Erreur diagnostic: {e}")
            return False, []
    
    def drop_and_recreate_alerts_table(self):
        """Supprime et recrée la table alerts avec la bonne structure"""
        print("\n🔧 === RECRÉATION TABLE ALERTS ===")
        
        try:
            with self.connection.cursor() as cursor:
                # Sauvegarder les données existantes si nécessaire
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_name = 'alerts'
                    );
                """)
                
                if cursor.fetchone()[0]:
                    print("⚠️ Table alerts existe, sauvegarde des données...")
                    
                    # Sauvegarder dans une table temporaire
                    cursor.execute("""
                        CREATE TABLE alerts_backup AS SELECT * FROM alerts;
                    """)
                    print("✅ Données sauvegardées dans alerts_backup")
                    
                    # Supprimer l'ancienne table
                    cursor.execute("DROP TABLE alerts;")
                    print("🗑️ Ancienne table supprimée")
                
                # Créer la nouvelle table avec la structure correcte
                cursor.execute("""
                    CREATE TABLE alerts (
                        id VARCHAR(255) PRIMARY KEY,
                        level VARCHAR(50) NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        acknowledged BOOLEAN DEFAULT FALSE,
                        source VARCHAR(100),
                        indicator_data JSONB,
                        mitre_data JSONB,
                        detection_method VARCHAR(100),
                        acknowledged_by VARCHAR(100),
                        acknowledged_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                print("✅ Nouvelle table alerts créée")
                
                # Créer des index pour les performances
                cursor.execute("""
                    CREATE INDEX idx_alerts_timestamp ON alerts(timestamp);
                    CREATE INDEX idx_alerts_level ON alerts(level);
                    CREATE INDEX idx_alerts_acknowledged ON alerts(acknowledged);
                    CREATE INDEX idx_alerts_source ON alerts(source);
                """)
                print("✅ Index créés")
                
                # Valider les changements
                self.connection.commit()
                print("✅ Structure de table mise à jour avec succès")
                
                return True
                
        except Exception as e:
            print(f"❌ Erreur recréation table: {e}")
            if self.connection:
                self.connection.rollback()
            return False
    
    def create_sample_alerts(self):
        """Crée des alertes d'exemple dans la nouvelle structure"""
        print("\n📝 === CRÉATION ALERTES D'EXEMPLE ===")
        
        sample_alerts = [
            {
                'id': f'sample_critical_{int(datetime.now().timestamp())}',
                'level': 'critical',
                'title': 'IOC Malveillant Détecté - IP Critique',
                'description': 'Adresse IP 192.168.100.50 identifiée comme serveur C&C APT28',
                'source': 'threat_intelligence',
                'indicator_data': {
                    'type': 'ip',
                    'value': '192.168.100.50',
                    'confidence': 95,
                    'malware_family': 'apt28'
                },
                'mitre_data': {
                    'techniques': ['T1071', 'T1055'],
                    'tactics': ['command-and-control', 'defense-evasion']
                },
                'detection_method': 'signature_match'
            },
            {
                'id': f'sample_high_{int(datetime.now().timestamp())}',
                'level': 'high',
                'title': 'Technique MITRE Détectée - Process Injection',
                'description': 'Activité suspecte utilisant la technique T1055 (Process Injection)',
                'source': 'behavioral_analysis',
                'mitre_data': {
                    'technique_id': 'T1055',
                    'technique_name': 'Process Injection',
                    'tactic': 'defense-evasion'
                },
                'detection_method': 'behavioral_analysis'
            },
            {
                'id': f'sample_medium_{int(datetime.now().timestamp())}',
                'level': 'medium',
                'title': 'Domaine Suspect Identifié',
                'description': 'Domaine malicious-site.evil détecté dans le trafic réseau',
                'source': 'network_monitoring',
                'indicator_data': {
                    'type': 'domain',
                    'value': 'malicious-site.evil',
                    'confidence': 75
                },
                'detection_method': 'dns_analysis'
            }
        ]
        
        try:
            with self.connection.cursor() as cursor:
                successful_inserts = 0
                
                for alert in sample_alerts:
                    try:
                        cursor.execute("""
                            INSERT INTO alerts (
                                id, level, title, description, timestamp, 
                                acknowledged, source, indicator_data, mitre_data, detection_method
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """, (
                            alert['id'],
                            alert['level'],
                            alert['title'],
                            alert['description'],
                            datetime.now().isoformat(),
                            False,
                            alert['source'],
                            json.dumps(alert.get('indicator_data', {})),
                            json.dumps(alert.get('mitre_data', {})),
                            alert['detection_method']
                        ))
                        successful_inserts += 1
                        print(f"  ✅ Alerte créée: {alert['title'][:50]}...")
                    except Exception as e:
                        print(f"  ❌ Erreur création alerte: {e}")
                
                self.connection.commit()
                print(f"✅ {successful_inserts} alertes d'exemple créées")
                
                return successful_inserts
                
        except Exception as e:
            print(f"❌ Erreur création alertes exemple: {e}")
            if self.connection:
                self.connection.rollback()
            return 0
    
    def verify_table_structure(self):
        """Vérifie que la structure de la table est correcte"""
        print("\n✅ === VÉRIFICATION STRUCTURE FINALE ===")
        
        try:
            with self.connection.cursor(cursor_factory=RealDictCursor) as cursor:
                # Vérifier les colonnes requises
                required_columns = [
                    'id', 'level', 'title', 'description', 'timestamp',
                    'acknowledged', 'source', 'indicator_data', 'mitre_data'
                ]
                
                cursor.execute("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'alerts'
                """)
                
                existing_columns = [row['column_name'] for row in cursor.fetchall()]
                
                print("Colonnes requises:")
                all_present = True
                for col in required_columns:
                    present = col in existing_columns
                    icon = "✅" if present else "❌"
                    print(f"  {icon} {col}")
                    if not present:
                        all_present = False
                
                # Test d'insertion simple
                if all_present:
                    test_alert = {
                        'id': 'test_structure_verification',
                        'level': 'low',
                        'title': 'Test Structure',
                        'description': 'Test de vérification structure',
                        'source': 'structure_test'
                    }
                    
                    cursor.execute("""
                        INSERT INTO alerts (id, level, title, description, source, acknowledged)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title
                    """, (
                        test_alert['id'], test_alert['level'], test_alert['title'],
                        test_alert['description'], test_alert['source'], False
                    ))
                    
                    self.connection.commit()
                    print("✅ Test d'insertion réussi")
                    
                    # Nettoyer le test
                    cursor.execute("DELETE FROM alerts WHERE id = 'test_structure_verification'")
                    self.connection.commit()
                
                return all_present
                
        except Exception as e:
            print(f"❌ Erreur vérification structure: {e}")
            return False
    
    def run_complete_fix(self):
        """Exécute la correction complète de la base de données"""
        print("🔧 === CORRECTION COMPLÈTE BASE DE DONNÉES CTI ===")
        print(f"⏰ Démarré à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if not self.connection:
            print("❌ Impossible de se connecter à la base de données")
            return False
        
        # 1. Diagnostic initial
        table_exists, columns = self.diagnose_alerts_table()
        
        # 2. Recréer la table si nécessaire
        needs_recreation = False
        if not table_exists:
            print("⚠️ Table alerts n'existe pas, création nécessaire")
            needs_recreation = True
        else:
            # Vérifier si la colonne 'level' existe
            column_names = [col['column_name'] for col in columns]
            if 'level' not in column_names:
                print("⚠️ Colonne 'level' manquante, recréation nécessaire")
                needs_recreation = True
        
        if needs_recreation:
            if not self.drop_and_recreate_alerts_table():
                print("❌ Échec de la recréation de la table")
                return False
        
        # 3. Vérifier la structure finale
        if not self.verify_table_structure():
            print("❌ Structure de table incorrecte après correction")
            return False
        
        # 4. Créer des alertes d'exemple
        sample_count = self.create_sample_alerts()
        
        # 5. Résultat final
        print(f"\n🎉 === CORRECTION TERMINÉE AVEC SUCCÈS ===")
        print(f"✅ Table 'alerts' correctement structurée")
        print(f"✅ {sample_count} alertes d'exemple créées")
        print(f"🌐 La table est maintenant compatible avec l'API Dashboard")
        print(f"⏱️ Terminé à: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return True

def main():
    """Point d'entrée principal"""
    print("🛠️ CTI Database Fixer - Correction Structure Alerts")
    print("=" * 60)
    
    fixer = CTIDatabaseFixer()
    
    try:
        success = fixer.run_complete_fix()
        if success:
            print(f"\n✅ CORRECTION RÉUSSIE!")
            print(f"Vous pouvez maintenant relancer le test de détection:")
            print(f"docker exec -it cti-dashboard-backend python /app/test_detection9.py")
        else:
            print(f"\n❌ CORRECTION ÉCHOUÉE")
            print(f"Vérifiez les logs et contactez l'administrateur")
    
    except KeyboardInterrupt:
        print("\n⏹️ Correction interrompue par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur inattendue: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if fixer.connection:
            fixer.connection.close()
            print("🔌 Connexion DB fermée")

if __name__ == "__main__":
    main()