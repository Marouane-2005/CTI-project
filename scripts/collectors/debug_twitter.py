#!/usr/bin/env python3
"""
Script de déblocage et test pour TwitterCollector V7.1
"""

import sys
import os
import json
import time
from datetime import datetime

# Ajouter le chemin vers le collector
base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(base_path)

def clear_rate_limit_cache():
    """Effacer tous les fichiers de cache et de state"""
    cache_patterns = [
        'cache/rate_limit_state.json',
        'cache/twitter_cache_*.pkl',
        '../cache/rate_limit_state.json',
        '../cache/twitter_cache_*.pkl'
    ]
    
    import glob
    cleared_files = []
    
    for pattern in cache_patterns:
        try:
            files = glob.glob(pattern)
            for file_path in files:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    cleared_files.append(file_path)
                    print(f"✅ Deleted: {file_path}")
        except Exception as e:
            print(f"⚠️ Could not clear {pattern}: {e}")
    
    # Also try direct paths
    direct_paths = [
        os.path.join(os.path.dirname(__file__), '..', 'cache', 'rate_limit_state.json'),
        os.path.join(os.path.dirname(__file__), 'cache', 'rate_limit_state.json'),
    ]
    
    for path in direct_paths:
        try:
            if os.path.exists(path):
                os.remove(path)
                cleared_files.append(path)
                print(f"✅ Deleted: {path}")
        except:
            pass
    
    if cleared_files:
        print(f"🧹 Cleared {len(cleared_files)} cache files")
    else:
        print("ℹ️ No cache files found to clear")

def test_minimal_search():
    """Test avec une recherche minimale"""
    try:
        # Import du collector
        from collectors.twitter_collector import TwitterCollector
        
        print("\n🔧 Initializing fresh collector...")
        collector = TwitterCollector()
        
        # Force reset des limites
        print("🔄 Resetting rate limits...")
        collector.clear_rate_limits()
        
        # Status initial
        status = collector.get_status_report()
        print(f"\n📊 Initial Status:")
        print(f"   • Blocked: {status['blocked']}")
        print(f"   • Consecutive errors: {status['consecutive_errors']}")
        print(f"   • Daily requests: {status['daily_requests_used']}/{status['daily_limit']}")
        
        if not status['blocked']:
            print(f"\n🎯 Attempting minimal test search...")
            
            # Test avec un seul tweet, mot-clé simple
            tweets = collector._safe_search_tweets(
                query="cybersecurity -is:retweet lang:en", 
                max_results=1
            )
            
            if tweets:
                print(f"✅ SUCCESS! Found {len(tweets)} tweet(s)")
                for tweet in tweets:
                    print(f"   • {tweet.get('text', '')[:100]}...")
                    print(f"   • Created: {tweet.get('created_at', 'N/A')}")
                    print(f"   • Metrics: {tweet.get('public_metrics', {})}")
            else:
                print("⚠️ No tweets found, but API call succeeded")
                
            # Status final
            final_status = collector.get_status_report()
            print(f"\n📊 Final Status:")
            print(f"   • Blocked: {final_status['blocked']}")
            print(f"   • Consecutive errors: {final_status['consecutive_errors']}")
            print(f"   • Daily requests: {final_status['daily_requests_used']}/{final_status['daily_limit']}")
        else:
            remaining = status.get('blocked_remaining_seconds', 0)
            print(f"🚫 Still blocked - {remaining:.0f}s remaining ({remaining/60:.1f} minutes)")
            
    except Exception as e:
        print(f"💥 Error during test: {e}")
        import traceback
        traceback.print_exc()

def manual_token_test():
    """Test manuel direct de l'API Twitter"""
    try:
        import tweepy
        import requests
        
        # Charger le token depuis la config
        config_files = ['api_keys.json', '../config/api_keys.json', '../../config/api_keys.json']
        bearer_token = None
        
        for config_file in config_files:
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    bearer_token = config.get('twitter_bearer_token', '').strip()
                    if bearer_token:
                        print(f"✅ Token loaded from: {config_file}")
                        break
        
        if not bearer_token:
            print("❌ No bearer token found")
            return
        
        # Test de connectivité basique
        print("\n🌐 Testing internet connectivity...")
        response = requests.get('https://httpbin.org/ip', timeout=10)
        if response.status_code == 200:
            print("✅ Internet connection OK")
        else:
            print("❌ Internet connection failed")
            return
        
        # Test direct de l'API
        print(f"\n🔑 Testing Twitter API directly...")
        print(f"   Token format: {bearer_token[:20]}...{bearer_token[-10:] if len(bearer_token) > 30 else ''}")
        
        client = tweepy.Client(bearer_token=bearer_token, wait_on_rate_limit=False)
        
        # Test ultra-minimal
        response = client.search_recent_tweets(
            query="twitter -is:retweet", 
            max_results=1
        )
        
        if response and response.data:
            print(f"✅ API Direct Test SUCCESS! Found {len(response.data)} tweet(s)")
        elif response:
            print("✅ API call succeeded but no tweets found")
        else:
            print("⚠️ Empty response from API")
            
    except tweepy.TooManyRequests as e:
        print(f"🚫 Rate limit hit in direct test")
        print(f"   Response: {e}")
        if hasattr(e, 'response') and e.response:
            headers = e.response.headers
            print(f"   Limit: {headers.get('x-rate-limit-limit', 'unknown')}")
            print(f"   Remaining: {headers.get('x-rate-limit-remaining', 'unknown')}")
            print(f"   Reset: {headers.get('x-rate-limit-reset', 'unknown')}")
    except tweepy.Unauthorized:
        print("🚫 Unauthorized - check your bearer token")
    except tweepy.Forbidden:
        print("🚫 Forbidden - API access may be restricted")
    except Exception as e:
        print(f"💥 Direct API test failed: {e}")

def main():
    print("🐦 Twitter Collector V7.1 - Debug & Reset Tool")
    print("=" * 50)
    
    print("\n1️⃣ Clearing cache and rate limit state...")
    clear_rate_limit_cache()
    
    print("\n2️⃣ Testing direct API access...")
    manual_token_test()
    
    print("\n3️⃣ Testing collector with fresh state...")
    test_minimal_search()
    
    print(f"\n✨ Debug session completed at {datetime.now()}")
    print("\nℹ️  If still blocked, either:")
    print("   • Wait for the block to expire naturally")
    print("   • Check if your API key has sufficient quota")
    print("   • Verify your bearer token is correct and active")

if __name__ == "__main__":
    main()