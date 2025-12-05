#!/usr/bin/env python3
"""
Script de diagnostic pour vérifier les données MITRE dans PostgreSQL
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor

def check_postgres_connection():
    """Vérifier la connexion PostgreSQL"""
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': int(os.getenv('DB_PORT', 5432)),
        'database': os.getenv('DB_NAME', 'cti_db'),
        'user': os.getenv('DB_USER', 'cti_user'),
        'password': os.getenv('DB_PASSWORD', 'cti_password')
    }
    
    try:
        print("🔍 Testing PostgreSQL connection...")
        print(f"   Host: {db_config['host']}")
        print(f"   Port: {db_config['port']}")
        print(f"   Database: {db_config['database']}")
        print(f"   User: {db_config['user']}")
        
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                # Vérifier la version PostgreSQL
                cursor.execute("SELECT version();")
                pg_version = cursor.fetchone()[0]
                print(f"✅ PostgreSQL Version: {pg_version}")
                
                # Vérifier les tables MITRE
                cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name LIKE 'mitre_%'
                    ORDER BY table_name
                """)
                
                tables = cursor.fetchall()
                print(f"\n📊 MITRE Tables found: {len(tables)}")
                for table in tables:
                    print(f"   - {table['table_name']}")
                
                # Vérifier le contenu des tables
                tables_to_check = ['mitre_techniques', 'mitre_groups', 'mitre_software', 'mitre_relationships']
                print(f"\n📈 Table Contents:")
                
                for table in tables_to_check:
                    try:
                        cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                        count = cursor.fetchone()['count']
                        print(f"   - {table}: {count} rows")
                        
                        # Montrer quelques exemples si la table n'est pas vide
                        if count > 0:
                            cursor.execute(f"SELECT * FROM {table} LIMIT 3")
                            examples = cursor.fetchall()
                            print(f"     Examples:")
                            for example in examples:
                                if table == 'mitre_techniques':
                                    print(f"       {example.get('id', 'N/A')} - {example.get('name', 'N/A')}")
                                elif table == 'mitre_groups':
                                    print(f"       {example.get('id', 'N/A')} - {example.get('name', 'N/A')}")
                                elif table == 'mitre_software':
                                    print(f"       {example.get('id', 'N/A')} - {example.get('name', 'N/A')}")
                                elif table == 'mitre_relationships':
                                    print(f"       {example.get('source_ref', 'N/A')} -> {example.get('target_ref', 'N/A')}")
                                    
                    except Exception as e:
                        print(f"   - {table}: ERROR - {e}")
                
                # Vérifier les logs de sync
                print(f"\n📋 Sync Logs:")
                try:
                    cursor.execute("""
                        SELECT sync_type, sync_status, total_processed, 
                               successful_inserts, errors, started_at, completed_at
                        FROM mitre_sync_log 
                        ORDER BY started_at DESC 
                        LIMIT 5
                    """)
                    
                    logs = cursor.fetchall()
                    for log in logs:
                        print(f"   - {log['sync_type']} | {log['sync_status']} | "
                              f"Processed: {log['total_processed']} | "
                              f"Inserted: {log['successful_inserts']} | "
                              f"Errors: {log['errors']} | "
                              f"Started: {log['started_at']}")
                        
                except Exception as e:
                    print(f"   Error reading sync logs: {e}")
                
                # Vérifier les index
                print(f"\n🔍 Database Indexes:")
                cursor.execute("""
                    SELECT indexname, tablename 
                    FROM pg_indexes 
                    WHERE tablename LIKE 'mitre_%'
                    ORDER BY tablename, indexname
                """)
                
                indexes = cursor.fetchall()
                current_table = ""
                for index in indexes:
                    if index['tablename'] != current_table:
                        print(f"   {index['tablename']}:")
                        current_table = index['tablename']
                    print(f"     - {index['indexname']}")
                
                # Test d'écriture
                print(f"\n✍️ Testing Write Access:")
                try:
                    cursor.execute("""
                        INSERT INTO mitre_techniques 
                        (id, name, description, tactic, is_subtechnique)
                        VALUES ('TEST-001', 'Test Technique', 'Test Description', 'test-tactic', FALSE)
                        ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
                    """)
                    
                    cursor.execute("DELETE FROM mitre_techniques WHERE id = 'TEST-001'")
                    conn.commit()
                    print("   ✅ Write access OK")
                    
                except Exception as e:
                    print(f"   ❌ Write access ERROR: {e}")
                    conn.rollback()
    
    except Exception as e:
        print(f"❌ PostgreSQL connection failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🔬 MITRE PostgreSQL Diagnostic Script")
    print("=" * 50)
    
    # Configuration des variables d'environnement par défaut
    os.environ.setdefault("DB_HOST", "localhost")
    os.environ.setdefault("DB_PORT", "5432")
    os.environ.setdefault("DB_NAME", "cti_db")
    os.environ.setdefault("DB_USER", "cti_user")
    os.environ.setdefault("DB_PASSWORD", "cti_password")
    
    check_postgres_connection()
    print("\n" + "=" * 50)
    print("🏁 Diagnostic completed")