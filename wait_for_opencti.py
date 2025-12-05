#!/usr/bin/env python3
"""
Test minimal pour identifier le problème exact
"""

import sys
print(f"Python version: {sys.version}")

try:
    import psycopg2
    print(f"✅ psycopg2 version: {psycopg2.__version__}")
except ImportError as e:
    print(f"❌ psycopg2 import error: {e}")
    sys.exit(1)

from psycopg2.extras import RealDictCursor

def test_connection():
    """Test de connexion le plus simple possible"""
    try:
        print("\n🔍 Testing connection...")
        
        # Connexion exactement comme dans votre diagnostic qui fonctionne
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            database='cti_db',
            user='cti_user',
            password='cti_password'
        )
        
        print("✅ Connection object created successfully")
        
        # Test autocommit
        conn.autocommit = True
        print("✅ Autocommit set successfully")
        
        # Test cursor
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        print("✅ Cursor created successfully")
        
        # Test query simple
        cursor.execute("SELECT 1 as test")
        result = cursor.fetchone()
        print(f"✅ Simple query successful: {result}")
        
        # Test version
        cursor.execute("SELECT version()")
        version = cursor.fetchone()
        version_info = version['version'] if isinstance(version, dict) and 'version' in version else str(version)
        print(f"✅ Version query successful: {version_info[:50]}...")
        conn.close()
        print("✅ Connection closed successfully")
        
        print("\n🎉 ALL TESTS PASSED! PostgreSQL connection works perfectly.")
        return True
        
    except Exception as e:
        print(f"\n❌ Error occurred:")
        print(f"   Type: {type(e).__name__}")
        print(f"   Message: {e}")
        print(f"   Args: {e.args}")
        
        # Debug info
        import traceback
        print(f"\n🔍 Full traceback:")
        traceback.print_exc()
        
        return False

if __name__ == "__main__":
    print("🧪 Minimal PostgreSQL Connection Test")
    print("=" * 40)
    
    success = test_connection()
    
    if success:
        print("\n✅ Your PostgreSQL setup is working correctly!")
        print("   The problem is likely in the OpenCTI connector logic.")
    else:
        print("\n❌ There's a fundamental issue with PostgreSQL connection.")
        print("   Check your PostgreSQL installation and credentials.")