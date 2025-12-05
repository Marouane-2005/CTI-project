#!/usr/bin/env python3
"""
Script de vérification des CVE stockées en base de données
"""

import sys
import os

# Ajouter le chemin pour les imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.utils.database import DatabaseManager

def check_cves_in_database():
    """Vérifie les CVE stockées en base"""
    
    try:
        print("=== Vérification des CVE en base de données ===\n")
        
        # Initialiser la connexion
        db = DatabaseManager()
        
        if not db.pg_conn:
            print("❌ Connexion PostgreSQL échouée")
            return
        
        cursor = db.pg_conn.cursor()
        
        # 1. Statistiques générales
        print("📊 STATISTIQUES GÉNÉRALES")
        print("-" * 40)
        
        cursor.execute("SELECT COUNT(*) as total FROM cves")
        total = cursor.fetchone()['total']
        print(f"Total CVE en base : {total}")
        
        # 2. CVE par sévérité
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM cves 
            GROUP BY severity 
            ORDER BY 
                CASE severity 
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
        """)
        
        print("\nRépartition par sévérité :")
        for row in cursor.fetchall():
            severity = row['severity']
            count = row['count']
            print(f"  {severity:<10}: {count}")
        
        # 3. CVE récentes (aujourd'hui)
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM cves 
            WHERE DATE(collected_at) = CURRENT_DATE
        """)
        today_count = cursor.fetchone()['count']
        print(f"\nCVE collectées aujourd'hui : {today_count}")
        
        # 4. Top 10 des CVE les plus critiques récentes
        print("\n🚨 TOP 10 CVE LES PLUS CRITIQUES (récentes)")
        print("-" * 60)
        
        cursor.execute("""
            SELECT cve_id, cvss_score, severity, 
                   LEFT(description, 80) as short_desc,
                   published_date::date as pub_date
            FROM cves 
            WHERE DATE(collected_at) = CURRENT_DATE
            ORDER BY cvss_score DESC 
            LIMIT 10
        """)
        
        recent_cves = cursor.fetchall()
        
        if recent_cves:
            for i, cve in enumerate(recent_cves, 1):
                print(f"{i:2d}. {cve['cve_id']:<15} | Score: {cve['cvss_score']:<4} | {cve['severity']:<8}")
                print(f"    📅 {cve['pub_date']} | {cve['short_desc']}...")
                print()
        else:
            print("Aucune CVE trouvée pour aujourd'hui")
        
        # 5. Vérification de la cohérence avec le fichier JSON
        print("🔍 VÉRIFICATION COHÉRENCE")
        print("-" * 40)
        
        # Chercher le fichier JSON le plus récent
        import glob
        json_files = glob.glob("output/daily_feeds/critical_cves_*.json")
        
        if json_files:
            latest_json = max(json_files, key=os.path.getctime)
            print(f"Dernier fichier JSON : {os.path.basename(latest_json)}")
            
            try:
                import json
                with open(latest_json, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                json_count = data.get('total_cves', 0)
                print(f"CVE dans le fichier JSON : {json_count}")
                print(f"CVE en base aujourd'hui : {today_count}")
                
                if json_count == today_count:
                    print("✅ Cohérence parfaite entre fichier et base !")
                elif today_count > 0:
                    print("⚠️  Différence détectée - vérifiez les logs d'erreur")
                else:
                    print("❌ Aucune CVE en base - problème de stockage")
                
            except Exception as e:
                print(f"Erreur lecture JSON : {e}")
        
        # 6. Dernières CVE ajoutées
        print(f"\n📝 DERNIÈRES CVE AJOUTÉES")
        print("-" * 40)
        
        cursor.execute("""
            SELECT cve_id, cvss_score, severity, collected_at
            FROM cves 
            ORDER BY collected_at DESC 
            LIMIT 5
        """)
        
        for cve in cursor.fetchall():
            print(f"{cve['cve_id']:<15} | Score: {cve['cvss_score']:<4} | "
                  f"{cve['severity']:<8} | {cve['collected_at'].strftime('%Y-%m-%d %H:%M')}")
        
        print(f"\n✅ Vérification terminée !")
        
        db.close_connections()
        
    except Exception as e:
        print(f"❌ Erreur lors de la vérification : {e}")

if __name__ == "__main__":
    check_cves_in_database()