#!/usr/bin/env python3
"""
Rate Limit Reset Utility
Clears the persistent rate limit state for emergency recovery
"""

import os
import json
import shutil
from datetime import datetime

def reset_rate_limits():
    """Reset all rate limit states and cache"""
    
    # Find cache directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_dir = os.path.join(script_dir, '..', 'cache')
    
    if not os.path.exists(cache_dir):
        print("❌ Cache directory not found")
        return False
    
    try:
        # Backup current state
        backup_dir = os.path.join(cache_dir, f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}')
        os.makedirs(backup_dir, exist_ok=True)
        
        # Files to reset
        state_file = os.path.join(cache_dir, 'rate_limit_state.json')
        
        if os.path.exists(state_file):
            # Backup first
            shutil.copy2(state_file, backup_dir)
            
            # Show current state
            with open(state_file, 'r') as f:
                current_state = json.load(f)
                print("📊 Current rate limit state:")
                for key, value in current_state.items():
                    print(f"   - {key}: {value}")
            
            # Reset the state
            reset_state = {
                'consecutive_errors': 0,
                'blocked_until': 0,
                'last_error_time': 0,
                'timestamp': datetime.now().timestamp(),
                'reset_by': 'manual_reset_utility',
                'reset_at': datetime.now().isoformat()
            }
            
            with open(state_file, 'w') as f:
                json.dump(reset_state, f, indent=2)
            
            print("✅ Rate limit state reset successfully")
            print(f"📁 Backup saved to: {backup_dir}")
            
        else:
            print("ℹ️  No rate limit state file found - already clean")
        
        # Optionally clear old cache files (older than 24 hours)
        print("\n🧹 Cleaning old cache files...")
        cache_files_removed = 0
        
        for filename in os.listdir(cache_dir):
            if filename.startswith('twitter_cache_') and filename.endswith('.pkl'):
                file_path = os.path.join(cache_dir, filename)
                try:
                    # Check file age
                    file_age = datetime.now().timestamp() - os.path.getmtime(file_path)
                    if file_age > 24 * 3600:  # 24 hours
                        os.remove(file_path)
                        cache_files_removed += 1
                except Exception:
                    pass
        
        if cache_files_removed > 0:
            print(f"🗑️  Removed {cache_files_removed} old cache files")
        else:
            print("ℹ️  No old cache files to remove")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during reset: {e}")
        return False

def show_current_status():
    """Show current rate limit status without modifying anything"""
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cache_dir = os.path.join(script_dir, '..', 'cache')
    state_file = os.path.join(cache_dir, 'rate_limit_state.json')
    
    if not os.path.exists(state_file):
        print("ℹ️  No rate limit state file found - collector should be unblocked")
        return
    
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
        
        print("📊 Current Rate Limit State:")
        print("-" * 40)
        
        consecutive_errors = state.get('consecutive_errors', 0)
        blocked_until = state.get('blocked_until', 0)
        last_error_time = state.get('last_error_time', 0)
        
        print(f"Consecutive errors: {consecutive_errors}")
        print(f"Blocked until: {blocked_until}")
        
        if blocked_until > 0:
            current_time = datetime.now().timestamp()
            if current_time < blocked_until:
                remaining = blocked_until - current_time
                remaining_minutes = remaining / 60
                print(f"🚫 BLOCKED - {remaining:.0f} seconds remaining ({remaining_minutes:.1f} minutes)")
            else:
                print("✅ Block has expired - should be unblocked")
        else:
            print("✅ Not currently blocked")
        
        if last_error_time > 0:
            last_error = datetime.fromtimestamp(last_error_time)
            print(f"Last error: {last_error.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print("-" * 40)
        
    except Exception as e:
        print(f"❌ Error reading state: {e}")

if __name__ == "__main__":
    print("=== Twitter Rate Limit Reset Utility ===\n")
    
    # Show current status first
    show_current_status()
    
    # Ask for confirmation
    print("\n" + "="*50)
    response = input("\n⚠️  Reset rate limit state? This will clear all blocks. [y/N]: ").strip().lower()
    
    if response in ['y', 'yes']:
        print("\n🔄 Resetting rate limit state...")
        
        if reset_rate_limits():
            print("\n✅ Rate limit reset completed!")
            print("You can now run the Twitter collector again.")
        else:
            print("\n❌ Reset failed. Check the error messages above.")
    else:
        print("\n❌ Reset cancelled.")
    
    print("\n=== Done ===")