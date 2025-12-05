#!/usr/bin/env python3
"""
Twitter Configuration Test
Verify Twitter API setup without making actual API calls
"""

import os
import sys
import json
import tweepy
from datetime import datetime

def find_config_file(filename):
    """Find configuration file"""
    possible_paths = [
        os.path.join(os.path.dirname(__file__), '..', '..', 'config', filename),
        os.path.join(os.path.dirname(__file__), '..', 'config', filename),
        os.path.join(os.getcwd(), 'config', filename),
        os.path.join(os.path.dirname(__file__), filename),
        filename
    ]
    
    for path in possible_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            return abs_path
    
    return None

def test_configuration():
    """Test Twitter configuration step by step"""
    
    print("=== Twitter Configuration Test ===\n")
    
    # Step 1: Check config files
    print("1️⃣ Checking configuration files...")
    
    api_keys_path = find_config_file('api_keys.json')
    sources_path = find_config_file('sources.json')
    
    if api_keys_path:
        print(f"✅ Found api_keys.json at: {api_keys_path}")
    else:
        print("❌ api_keys.json not found")
    
    if sources_path:
        print(f"✅ Found sources.json at: {sources_path}")
    else:
        print("❌ sources.json not found")
    
    if not api_keys_path and not sources_path:
        print("❌ No configuration files found!")
        return False
    
    # Step 2: Load and verify API keys
    print("\n2️⃣ Loading API configuration...")
    
    try:
        if api_keys_path:
            with open(api_keys_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        else:
            with open(sources_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        
        bearer_token = config.get('twitter_bearer_token', '')
        
        if not bearer_token:
            print("❌ No twitter_bearer_token found in configuration")
            return False
        
        if len(bearer_token.strip()) < 50:
            print("❌ Bearer token appears too short")
            return False
        
        # Don't show the full token for security
        masked_token = bearer_token[:20] + "..." + bearer_token[-10:]
        print(f"✅ Bearer token found: {masked_token}")
        
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")
        return False
    
    # Step 3: Test client initialization
    print("\n3️⃣ Testing client initialization...")
    
    try:
        client = tweepy.Client(
            bearer_token=bearer_token,
            wait_on_rate_limit=False
        )
        print("✅ Tweepy client initialized successfully")
        
    except Exception as e:
        print(f"❌ Client initialization failed: {e}")
        return False
    
    # Step 4: Check sources configuration
    print("\n4️⃣ Checking sources configuration...")
    
    try:
        if sources_path:
            with open(sources_path, 'r', encoding='utf-8') as f:
                sources_config = json.load(f)
            
            accounts = sources_config.get('twitter_accounts', [])
            keywords = sources_config.get('threat_keywords', [])
            
            print(f"✅ Twitter accounts to monitor: {len(accounts)}")
            if accounts:
                print(f"   Sample accounts: {accounts[:3]}")
            
            print(f"✅ Threat keywords: {len(keywords)}")
            if keywords:
                print(f"   Sample keywords: {keywords[:5]}")
        else:
            print("ℹ️  No sources.json found - will use defaults")
            
    except Exception as e:
        print(f"⚠️  Sources configuration issue: {e}")
    
    # Step 5: Check cache directory
    print("\n5️⃣ Checking cache directory...")
    
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cache_dir = os.path.join(script_dir, '..', 'cache')
        
        if os.path.exists(cache_dir):
            print(f"✅ Cache directory exists: {cache_dir}")
            
            # Check rate limit state
            state_file = os.path.join(cache_dir, 'rate_limit_state.json')
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state = json.load(f)
                
                blocked_until = state.get('blocked_until', 0)
                if blocked_until > datetime.now().timestamp():
                    remaining = blocked_until - datetime.now().timestamp()
                    print(f"⚠️  Rate limit block active: {remaining:.0f}s remaining")
                else:
                    print("✅ No active rate limit blocks")
            else:
                print("✅ No rate limit state file - clean start")
        else:
            print(f"ℹ️  Cache directory will be created: {cache_dir}")
            
    except Exception as e:
        print(f"⚠️  Cache directory check failed: {e}")
    
    # Step 6: Check output directory
    print("\n6️⃣ Checking output directory...")
    
    try:
        output_dir = os.path.join(os.path.dirname(__file__), '..', 'output', 'daily_feeds')
        
        if os.path.exists(output_dir):
            print(f"✅ Output directory exists: {output_dir}")
            
            # Count existing files
            json_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
            print(f"ℹ️  Existing output files: {len(json_files)}")
        else:
            print(f"ℹ️  Output directory will be created: {output_dir}")
            
    except Exception as e:
        print(f"⚠️  Output directory check failed: {e}")
    
    print("\n" + "="*50)
    print("✅ Configuration test completed!")
    print("\n💡 Next steps:")
    print("   1. If rate limited, use the reset utility")
    print("   2. Run twitter_collector.py with minimal settings")
    print("   3. Monitor rate limits carefully")
    
    return True

def show_environment_info():
    """Show relevant environment information"""
    print("\n🔧 Environment Information:")
    print(f"   Python version: {sys.version.split()[0]}")
    print(f"   Tweepy version: {tweepy.__version__}")
    print(f"   Current directory: {os.getcwd()}")
    print(f"   Script location: {os.path.dirname(os.path.abspath(__file__))}")

if __name__ == "__main__":
    show_environment_info()
    test_configuration()