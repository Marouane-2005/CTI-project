#!/usr/bin/env python3
"""
Minimal Twitter API Test
Just test basic connectivity with a single, minimal API call
"""

import tweepy
import json
import os
from datetime import datetime

def find_config_file(filename):
    """Find configuration file"""
    possible_paths = [
        os.path.join('config', filename),
        os.path.join('..', 'config', filename),
        filename
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    return None

def minimal_twitter_test():
    """Absolute minimal Twitter API test"""
    
    print("=== Minimal Twitter API Test ===\n")
    
    # Load config
    try:
        config_path = find_config_file('api_keys.json')
        if not config_path:
            config_path = find_config_file('sources.json')
        
        if not config_path:
            print("❌ No configuration file found")
            return False
            
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        bearer_token = config.get('twitter_bearer_token')
        if not bearer_token:
            print("❌ No bearer token found")
            return False
            
        print("✅ Configuration loaded")
        
    except Exception as e:
        print(f"❌ Config error: {e}")
        return False
    
    # Initialize client
    try:
        client = tweepy.Client(bearer_token=bearer_token, wait_on_rate_limit=False)
        print("✅ Client initialized")
        
    except Exception as e:
        print(f"❌ Client initialization failed: {e}")
        return False
    
    # Make ONE minimal API call
    print("\n🔄 Making minimal API call...")
    print("Query: 'cybersecurity' (max 10 results)")
    
    try:
        response = client.search_recent_tweets(
            query="cybersecurity",
            max_results=10  # Absolute minimum
        )
        
        if response and response.data:
            tweet_count = len(response.data)
            print(f"✅ SUCCESS: Retrieved {tweet_count} tweets")
            
            # Show one sample tweet (first 100 chars)
            if response.data:
                sample_tweet = response.data[0].text[:100] + "..." if len(response.data[0].text) > 100 else response.data[0].text
                print(f"\n📝 Sample tweet: {sample_tweet}")
            
            return True
            
        elif response:
            print("✅ API call successful but no tweets returned")
            return True
            
        else:
            print("❌ No response from API")
            return False
            
    except tweepy.TooManyRequests as e:
        print("❌ RATE LIMIT HIT - Your API has very strict limits")
        print("   This suggests you might have a restricted API access level")
        
        # Try to extract reset time
        if hasattr(e, 'response') and e.response:
            reset_time = e.response.headers.get('x-rate-limit-reset')
            remaining = e.response.headers.get('x-rate-limit-remaining', 'unknown')
            limit = e.response.headers.get('x-rate-limit-limit', 'unknown')
            
            print(f"   Rate limit details:")
            print(f"   - Remaining: {remaining}")
            print(f"   - Limit: {limit}")
            print(f"   - Reset time: {reset_time}")
            
        return False
        
    except tweepy.Unauthorized as e:
        print(f"❌ UNAUTHORIZED: {e}")
        print("   Your bearer token might be invalid or expired")
        return False
        
    except tweepy.Forbidden as e:
        print(f"❌ FORBIDDEN: {e}")
        print("   Your API access might be restricted")
        return False
        
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def check_api_limits():
    """Check what kind of API access you have"""
    print("\n💡 API Access Information:")
    print("   If you're getting rate limits immediately, you might have:")
    print("   - Basic/Free Twitter API access (very limited)")
    print("   - Academic research access (more limits)")
    print("   - Or your token needs refresh")
    print()
    print("   Basic tier limits are typically:")
    print("   - 300 requests per 15 minutes for search")
    print("   - But could be much lower for new accounts")

if __name__ == "__main__":
    success = minimal_twitter_test()
    
    if not success:
        check_api_limits()
        print("\n🔧 Troubleshooting suggestions:")
        print("   1. Check your Twitter API access level")
        print("   2. Verify your bearer token is correct")
        print("   3. Wait a few hours before trying again")
        print("   4. Consider upgrading your Twitter API plan")
    else:
        print("\n✅ Your Twitter API is working!")
        print("   You can now run the full collector")
        
    print("\n=== Test Complete ===")