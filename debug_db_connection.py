#!/usr/bin/env python3
# debug_db_connection.py

import os
import psycopg2
from psycopg2.extras import RealDictCursor

def debug_database_connection():
    """Diagnostique complet de la connexion PostgreSQL"""
    
    print("🔍 DIAGNOSTIC DE CONNEXION POSTGRESQL")
    print("=" * 50)
    
    # 1. Afficher la configuration
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', 5432)),
        'database': os.getenv('DB_NAME', 'cti_db'),
        'user': os.getenv('DB_USER', 'cti_user'),
        'password': os.getenv('DB_PASSWORD', 'cti_password')
    }
    
    print("📋 Configuration actuelle:")
    for key, value in db_config.items():
        if key == 'password':
            print(f"   {key}: {'*' * len(str(value))}")
        else:
            print(f"   {key}: {value}")
    print()
    
    # 2. Test de connexion
    try:
        print("🔌 Test de connexion...")
        conn = psycopg2.connect(**db_config)
        print("✅ Connexion réussie")
        
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Version PostgreSQL
            cursor.execute("SELECT version()")
            version = cursor.fetchone()['version']
            print(f"📊 Version PostgreSQL: {version[:50]}...")
            
            # Base de données actuelle
            cursor.execute("SELECT current_database(), current_user")
            db_info = cursor.fetchone()
            print(f"🗄️ Base actuelle: {db_info['current_database']}")
            print(f"👤 Utilisateur: {db_info['current_user']}")
            
            # Schéma actuel
            cursor.execute("SELECT current_schema()")
            schema = cursor.fetchone()['current_schema']
            print(f"📂 Schéma: {schema}")
            
            # Liste des tables
            cursor.execute("""
                SELECT table_name, table_type 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                ORDER BY table_name
            """)
            tables = cursor.fetchall()
            print(f"\n📋 Tables dans le schéma public ({len(tables)} trouvées):")
            for table in tables:
                print(f"   - {table['table_name']} ({table['table_type']})")
            
            # Vérifier spécifiquement les tables MITRE
            mitre_tables = ['mitre_techniques', 'mitre_groups', 'mitre_software', 
                           'cve_technique_mapping', 'ioc_technique_mapping']
            
            print(f"\n🎯 Vérification des tables MITRE:")
            for table in mitre_tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                    count = cursor.fetchone()['count']
                    print(f"   ✅ {table}: {count} enregistrements")
                except Exception as e:
                    print(f"   ❌ {table}: {e}")
            
            # Test d'écriture
            print(f"\n✍️ Test d'écriture...")
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS test_write (
                        id SERIAL PRIMARY KEY,
                        test_data TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    INSERT INTO test_write (test_data) 
                    VALUES (%s) RETURNING id
                """, ("Test insertion " + str(os.getpid()),))
                
                test_id = cursor.fetchone()['id']
                conn.commit()
                print(f"   ✅ Écriture réussie (ID: {test_id})")
                
                # Nettoyage
                cursor.execute("DROP TABLE test_write")
                conn.commit()
                print(f"   🧹 Nettoyage effectué")
                
            except Exception as e:
                print(f"   ❌ Erreur d'écriture: {e}")
                conn.rollback()
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False
    
    return True

def test_multiple_connections():
    """Test des connexions multiples comme dans le code MITRE"""
    print(f"\n🔄 TEST DE CONNEXIONS MULTIPLES")
    print("=" * 50)
    
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', 5432)),
        'database': os.getenv('DB_NAME', 'cti_db'),
        'user': os.getenv('DB_USER', 'cti_user'),
        'password': os.getenv('DB_PASSWORD', 'cti_password')
    }
    
    try:
        # Simulation du comportement de votre enricher
        print("🔌 Connexion 1: Lecture des données...")
        conn1 = psycopg2.connect(**db_config)
        conn1.autocommit = False
        
        with conn1.cursor() as cursor1:
            cursor1.execute("SELECT COUNT(*) FROM mitre_techniques")
            count1 = cursor1.fetchone()[0]
            print(f"   📊 Techniques trouvées: {count1}")
        
        print("🔌 Connexion 2: Test d'insertion...")
        conn2 = psycopg2.connect(**db_config)
        conn2.autocommit = False
        
        with conn2.cursor() as cursor2:
            cursor2.execute("""
                INSERT INTO mitre_techniques 
                (id, name, description, tactic, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            """, ("TEST001", "Test Technique", "Test description", "test", "now()"))
            
            print(f"   ✍️ Insertion effectuée (pas encore commitée)")
            
            # Vérifier dans la même connexion
            cursor2.execute("SELECT COUNT(*) FROM mitre_techniques WHERE id = %s", ("TEST001",))
            local_count = cursor2.fetchone()[0]
            print(f"   👁️ Visible dans la même connexion: {local_count}")
        
        # Vérifier depuis la première connexion (avant commit)
        with conn1.cursor() as cursor1:
            cursor1.execute("SELECT COUNT(*) FROM mitre_techniques WHERE id = %s", ("TEST001",))
            other_count = cursor1.fetchone()[0]
            print(f"   👁️ Visible depuis autre connexion (avant commit): {other_count}")
        
        # Commit
        conn2.commit()
        print(f"   ✅ Commit effectué")
        
        # Vérifier après commit
        with conn1.cursor() as cursor1:
            cursor1.execute("SELECT COUNT(*) FROM mitre_techniques WHERE id = %s", ("TEST001",))
            after_commit_count = cursor1.fetchone()[0]
            print(f"   👁️ Visible après commit: {after_commit_count}")
        
        # Nettoyage
        with conn2.cursor() as cursor2:
            cursor2.execute("DELETE FROM mitre_techniques WHERE id = %s", ("TEST001",))
            conn2.commit()
            print(f"   🧹 Nettoyage effectué")
        
        conn1.close()
        conn2.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur dans test de connexions multiples: {e}")
        return False

if __name__ == "__main__":
    print("🔍 DIAGNOSTIC COMPLET DE LA BASE POSTGRESQL")
    print("=" * 60)
    
    # Variables d'environnement pour le test
    test_env = {
        'DB_HOST': 'localhost',  # ou votre IP/hostname
        'DB_PORT': '5432',
        'DB_NAME': 'cti_db',
        'DB_USER': 'cti_user', 
        'DB_PASSWORD': 'cti_password'
    }
    
    print("⚙️ Variables d'environnement utilisées:")
    for key, default_value in test_env.items():
        actual_value = os.getenv(key, default_value)
        if key == 'DB_PASSWORD':
            print(f"   {key}={('*' * len(actual_value)) if actual_value else 'NOT_SET'}")
        else:
            print(f"   {key}={actual_value}")
    print()
    
    # Diagnostic principal
    if debug_database_connection():
        test_multiple_connections()
    else:
        print("❌ Diagnostic échoué - vérifiez votre configuration")