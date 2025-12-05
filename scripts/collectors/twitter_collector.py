"""
Enhanced Twitter/X Collector for CTI with improved rate limit management and debugging
Version V7.1 - Free Tier Optimized with smarter initialization
"""
import sys
import os
import tweepy
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import threading
from collections import deque
import hashlib
import pickle
import requests

# Add the base path to sys.path
base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(base_path)

try:
    from utils.logger import CTILogger
except ImportError:
    import logging
    
    class CTILogger:
        def __init__(self, name):
            self.logger = logging.getLogger(name)
            self.logger.setLevel(logging.INFO)
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        def info(self, msg): self.logger.info(msg)
        def error(self, msg): self.logger.error(msg)
        def warning(self, msg): self.logger.warning(msg)
        def debug(self, msg): self.logger.debug(msg)

class APITierDetector:
    """Detect Twitter API access tier WITHOUT making API calls"""
    
    TIER_LIMITS = {
        'free': {'search_per_month': 10000, 'requests_per_15min': 180},
        'basic': {'search_per_month': 10000, 'requests_per_15min': 300},
        'pro': {'search_per_month': 1000000, 'requests_per_15min': 300},
        'enterprise': {'search_per_month': 10000000, 'requests_per_15min': 300}
    }
    
    @classmethod
    def detect_tier_from_token(cls, bearer_token: str, logger) -> Dict:
        """Attempt to detect API tier from token characteristics"""
        try:
            # Check token format - this is heuristic and may not be 100% accurate
            if not bearer_token or len(bearer_token) < 50:
                return {'tier': 'unknown', 'confidence': 'low', 'reason': 'invalid_token'}
            
            # For safety, assume free tier unless we have clear indicators otherwise
            # This prevents making test API calls that consume quota
            logger.info("Assuming free tier to avoid quota consumption during detection")
            return {'tier': 'assumed_free', 'confidence': 'medium', 'reason': 'conservative_assumption'}
            
        except Exception as e:
            logger.error(f"Error in tier detection: {e}")
            return {'tier': 'assumed_free', 'confidence': 'low', 'reason': 'error_fallback'}

class CacheManager:
    """Enhanced file-based cache with better error handling"""
    
    def __init__(self, cache_dir: str = None):
        if cache_dir is None:
            cache_dir = os.path.join(os.path.dirname(__file__), '..', 'cache')
        
        self.cache_dir = cache_dir
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception as e:
            # Fallback to temp directory
            import tempfile
            self.cache_dir = tempfile.gettempdir()
        
    def _get_cache_path(self, key: str) -> str:
        """Generate cache file path from key"""
        # Sanitize key for filename
        safe_key = "".join(c for c in key if c.isalnum() or c in (' ', '-', '_')).rstrip()
        hash_key = hashlib.md5(safe_key.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"twitter_cache_{hash_key}.pkl")
    
    def get(self, key: str, max_age_hours: int = 6) -> Optional[Dict]:
        """Get cached data if not expired"""
        try:
            cache_path = self._get_cache_path(key)
            if not os.path.exists(cache_path):
                return None
            
            # Check file age
            file_age = time.time() - os.path.getmtime(cache_path)
            if file_age > max_age_hours * 3600:
                try:
                    os.remove(cache_path)  # Remove expired cache
                except:
                    pass
                return None
            
            with open(cache_path, 'rb') as f:
                return pickle.load(f)
                
        except Exception:
            return None
    
    def set(self, key: str, data: Dict):
        """Cache data with error handling"""
        try:
            cache_path = self._get_cache_path(key)
            with open(cache_path, 'wb') as f:
                pickle.dump(data, f)
        except Exception:
            pass  # Fail silently
    
    def clear_expired(self, max_age_hours: int = 24):
        """Clear expired cache files"""
        try:
            now = time.time()
            for filename in os.listdir(self.cache_dir):
                if filename.startswith('twitter_cache_'):
                    filepath = os.path.join(self.cache_dir, filename)
                    if os.path.getmtime(filepath) < now - (max_age_hours * 3600):
                        os.remove(filepath)
        except Exception:
            pass
    
    def clear_connection_cache(self):
        """Clear connection test cache to force fresh test"""
        try:
            cache_key = "connection_test_v71"
            cache_path = self._get_cache_path(cache_key)
            if os.path.exists(cache_path):
                os.remove(cache_path)
        except:
            pass

class RateLimitManager:
    """Enhanced rate limit manager with API tier awareness and daily quotas"""
    
    def __init__(self, api_tier='free', requests_per_window=15, window_seconds=900):
        self.api_tier = api_tier
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.request_times = deque()
        self.lock = threading.Lock()
        self.last_error_time = 0
        self.consecutive_errors = 0
        self.blocked_until = 0
        
        # Daily quota management - more conservative defaults
        self.daily_requests = 0
        self.last_quota_reset = datetime.now().date()
        self.DAILY_LIMIT = 20  # Even more conservative
        self.MIN_REQUEST_INTERVAL = 3600  # 1 hour minimum
        
        # Adjust limits based on API tier
        self._adjust_for_tier()
        
        # Load persistent state
        self._load_state()
        
    def _adjust_for_tier(self):
        """Adjust rate limits based on detected API tier"""
        if self.api_tier in ['free', 'assumed_free']:
            # ULTRA conservative for free tier
            self.requests_per_window = 1  # UN SEUL request par fenêtre
            self.window_seconds = 3600    # 1 hour = 3600 secondes
            self.MIN_REQUEST_INTERVAL = 3600  # Force 1 hour minimum
            self.DAILY_LIMIT = 20         # Limite quotidienne très conservative
        elif self.api_tier == 'basic':
            self.requests_per_window = 3
            self.window_seconds = 900
            self.MIN_REQUEST_INTERVAL = 300  # 5 minutes
            self.DAILY_LIMIT = 100
        else:
            # Pro/Enterprise - still conservative but more permissive
            self.requests_per_window = 10
            self.window_seconds = 900
            self.MIN_REQUEST_INTERVAL = 60   # 1 minute
            self.DAILY_LIMIT = 500
        
    def _get_state_file(self) -> str:
        """Get path to state file"""
        cache_dir = os.path.join(os.path.dirname(__file__), '..', 'cache')
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except:
            import tempfile
            cache_dir = tempfile.gettempdir()
        return os.path.join(cache_dir, 'rate_limit_state.json')
    
    def _load_state(self):
        """Load persistent rate limit state"""
        try:
            state_file = self._get_state_file()
            if os.path.exists(state_file):
                with open(state_file, 'r') as f:
                    state = json.load(f)
                
                self.consecutive_errors = state.get('consecutive_errors', 0)
                self.blocked_until = state.get('blocked_until', 0)
                self.last_error_time = state.get('last_error_time', 0)
                self.daily_requests = state.get('daily_requests', 0)
                
                # Check if we need to reset daily counter
                last_date = state.get('last_quota_reset', '')
                if last_date != str(datetime.now().date()):
                    self.daily_requests = 0
                    self.last_quota_reset = datetime.now().date()
                
                # Clear old blocks (older than 24 hours)
                if time.time() - self.last_error_time > 86400:
                    self.consecutive_errors = 0
                    self.blocked_until = 0
                
        except Exception:
            pass  # Start fresh if can't load
    
    def _save_state(self):
        """Save persistent rate limit state"""
        try:
            state = {
                'consecutive_errors': self.consecutive_errors,
                'blocked_until': self.blocked_until,
                'last_error_time': self.last_error_time,
                'api_tier': self.api_tier,
                'timestamp': time.time(),
                'daily_requests': self.daily_requests,
                'last_quota_reset': str(self.last_quota_reset)
            }
            
            with open(self._get_state_file(), 'w') as f:
                json.dump(state, f)
                
        except Exception:
            pass  # Fail silently
    
    def check_daily_quota(self) -> Tuple[bool, int]:
        """Vérifie si on a dépassé le quota quotidien"""
        today = datetime.now().date()
        if self.last_quota_reset != today:
            self.daily_requests = 0
            self.last_quota_reset = today
        
        remaining = max(0, self.DAILY_LIMIT - self.daily_requests)
        return self.daily_requests < self.DAILY_LIMIT, remaining

    def increment_daily_counter(self):
        """Incrémente le compteur quotidien"""
        today = datetime.now().date()
        if self.last_quota_reset != today:
            self.daily_requests = 0
            self.last_quota_reset = today
        
        self.daily_requests += 1
        self._save_state()  # Save after each increment
        
    def is_blocked(self) -> Tuple[bool, float]:
        """Check if we're currently blocked"""
        now = time.time()
        if now < self.blocked_until:
            return True, self.blocked_until - now
        return False, 0
    
    def wait_if_needed(self) -> float:
        """Calculate wait time with tier-aware conservation and daily quota"""
        with self.lock:
            now = time.time()
            
            # Vérifier le quota quotidien AVANT tout
            quota_ok, remaining_quota = self.check_daily_quota()
            if not quota_ok:
                # Calculer le temps jusqu'à minuit
                tomorrow = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
                return (tomorrow - datetime.now()).total_seconds()
            
            # Check if we're in a blocked state
            blocked, remaining_time = self.is_blocked()
            if blocked:
                return remaining_time
            
            # FORCER délai minimum pour free tier
            if self.api_tier in ['free', 'assumed_free'] and self.request_times:
                time_since_last = now - self.request_times[-1]
                if time_since_last < self.MIN_REQUEST_INTERVAL:
                    return self.MIN_REQUEST_INTERVAL - time_since_last
            
            # Remove old requests outside the window
            while self.request_times and self.request_times[0] < now - self.window_seconds:
                self.request_times.popleft()
            
            current_requests = len(self.request_times)
            
            # Apply conservation based on error history and tier
            if self.consecutive_errors > 3:
                effective_limit = 1  # Only 1 request per window after many errors
            elif self.consecutive_errors > 0:
                effective_limit = max(1, self.requests_per_window // 4)
            else:
                # Keep significant buffer even for higher tiers
                if self.api_tier in ['free', 'assumed_free']:
                    effective_limit = 1  # Always 1 for free tier
                else:
                    buffer = 3
                    effective_limit = max(1, self.requests_per_window - buffer)
            
            # Check if we need to wait
            if current_requests >= effective_limit:
                if self.request_times:
                    oldest_request = self.request_times[0]
                    wait_time = self.window_seconds - (now - oldest_request) + 300  # 5 minute buffer
                    
                    if wait_time > 0:
                        return min(wait_time, 7200)  # Max 2 hour wait
            
            # Record this request and increment daily counter
            self.request_times.append(now)
            self.increment_daily_counter()
            return 0
    
    def handle_rate_limit_error(self, reset_time=None) -> float:
        """Handle rate limit with exponential backoff"""
        with self.lock:
            now = time.time()
            self.last_error_time = now
            self.consecutive_errors += 1
            
            # Calculate block duration with exponential backoff
            if reset_time:
                # Use Twitter's reset time plus buffer
                block_duration = max(reset_time - now + 1200, 3600)  # At least 1h buffer
            else:
                # Exponential backoff based on tier and error count
                if self.api_tier in ['free', 'assumed_free']:
                    base_wait = 7200  # 2 hours for free tier
                else:
                    base_wait = 1800   # 30 minutes for paid tiers
                
                multiplier = min(2 ** (self.consecutive_errors - 1), 8)  # Cap at 8x
                block_duration = base_wait * multiplier
            
            # Cap maximum block time
            max_block = 86400 if self.api_tier in ['free', 'assumed_free'] else 21600  # 24h/6h
            block_duration = min(block_duration, max_block)
            
            self.blocked_until = now + block_duration
            self._save_state()  # Persist the block
            
            return block_duration
    
    def reset_error_counter(self):
        """Reset error counter after successful requests"""
        with self.lock:
            if self.consecutive_errors > 0:
                self.consecutive_errors = max(0, self.consecutive_errors - 1)
                if self.consecutive_errors == 0:
                    self.blocked_until = 0
                self._save_state()
    
    def reset_all_limits(self):
        """Reset all rate limits - use with caution"""
        with self.lock:
            self.request_times.clear()
            self.consecutive_errors = 0
            self.blocked_until = 0
            self.last_error_time = 0
            # Note: Don't reset daily_requests as that's a real quota
            self._save_state()

class TwitterCollector:
    def __init__(self):
        self.logger = CTILogger("Twitter_Collector_V7.1")
        self.cache_manager = CacheManager()
        
        # Clear old cache on startup
        self.cache_manager.clear_expired(max_age_hours=12)
        
        # Enhanced keywords with CTI focus
        self.enhanced_keywords = [
            'ransomware', 'malware', 'apt', 'cybersecurity', 'data breach',
            'vulnerability', 'zero-day', 'threat intel', 'phishing', 'botnet'
        ]
        
        # Load configuration FIRST
        self.monitored_accounts, self.threat_keywords, self.bearer_token = self._load_config()
        
        # Detect API tier WITHOUT making calls
        self.api_tier_info = self._detect_api_tier_safe()
        
        # Initialize rate manager with detected tier
        self.rate_manager = RateLimitManager(
            api_tier=self.api_tier_info.get('tier', 'free'),
            requests_per_window=1,  # Ultra conservative starting point
            window_seconds=3600
        )
        
        # Initialize client LAST (doesn't make API calls)
        self.client = self._initialize_client()
        
    def _find_config_file(self, filename: str) -> str:
        """Find configuration file in multiple possible locations"""
        possible_paths = [
            os.path.join(os.path.dirname(__file__), '..', '..', 'config', filename),
            os.path.join(os.path.dirname(__file__), '..', 'config', filename),
            os.path.join(os.getcwd(), 'config', filename),
            os.path.join(os.path.dirname(__file__), filename),
            os.path.join(os.getcwd(), filename),
            filename
        ]
        
        for path in possible_paths:
            abs_path = os.path.abspath(path)
            if os.path.exists(abs_path):
                return abs_path
        
        raise FileNotFoundError(f"Configuration file {filename} not found in: {possible_paths}")
    
    def _load_config(self) -> Tuple[List[str], List[str], str]:
        """Load configuration and return accounts, keywords, and token"""
        try:
            # Try to find configuration
            config_files = ['api_keys.json', 'sources.json']
            config_data = None
            config_file_used = None
            
            for config_file in config_files:
                try:
                    config_path = self._find_config_file(config_file)
                    with open(config_path, 'r', encoding='utf-8') as f:
                        config_data = json.load(f)
                    config_file_used = config_file
                    break
                except FileNotFoundError:
                    continue
            
            if not config_data:
                self.logger.error("No configuration file found")
                return [], self.enhanced_keywords, ""
            
            self.logger.info(f"Using configuration from: {config_file_used}")
            
            bearer_token = config_data.get('twitter_bearer_token', '').strip()
            
            # Also try to load sources.json for accounts/keywords
            accounts = []
            keywords = self.enhanced_keywords
            
            try:
                if config_file_used != 'sources.json':
                    sources_path = self._find_config_file('sources.json')
                    with open(sources_path, 'r', encoding='utf-8') as f:
                        sources_config = json.load(f)
                    
                    accounts = sources_config.get('twitter_accounts', [])
                    keywords = sources_config.get('threat_keywords', self.enhanced_keywords)
                else:
                    accounts = config_data.get('twitter_accounts', [])
                    keywords = config_data.get('threat_keywords', self.enhanced_keywords)
                    
            except FileNotFoundError:
                self.logger.warning("sources.json not found, using defaults")
            
            self.logger.info(f"Configuration loaded: {len(accounts)} accounts, {len(keywords)} keywords")
            return accounts, keywords, bearer_token
            
        except Exception as e:
            self.logger.error(f"Config loading failed: {e}")
            return [], self.enhanced_keywords, ""
    
    def _detect_api_tier_safe(self) -> Dict:
        """Detect API tier WITHOUT making API calls"""
        if not self.bearer_token:
            return {'tier': 'unknown', 'confidence': 'low', 'reason': 'no_token'}
        
        return APITierDetector.detect_tier_from_token(self.bearer_token, self.logger)
    
    def _initialize_client(self) -> Optional[tweepy.Client]:
        """Initialize Twitter client WITHOUT making test calls"""
        try:
            if not self.bearer_token:
                self.logger.error("No bearer token available")
                return None
            
            # Validate token format
            if not self.bearer_token.startswith('AAAAAAAAAAAAAAAAAAAA'):
                self.logger.warning("Bearer token format looks unusual")
            
            # Test internet connectivity first (doesn't use Twitter API)
            if not self._test_connectivity():
                self.logger.error("No internet connectivity detected")
                return None
            
            # Initialize client WITHOUT making API calls
            client = tweepy.Client(
                bearer_token=self.bearer_token,
                wait_on_rate_limit=False  # We handle this manually
            )
            
            self.logger.info("Twitter client initialized successfully (no API calls made)")
            return client
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Twitter client: {e}")
            return None
    
    def _test_connectivity(self) -> bool:
        """Test basic internet connectivity"""
        try:
            response = requests.get('https://httpbin.org/ip', timeout=10)
            return response.status_code == 200
        except:
            try:
                # Fallback test
                response = requests.get('https://google.com', timeout=10)
                return response.status_code == 200
            except:
                return False
    
    def _safe_search_tweets(self, query: str, max_results: int = 3, start_time=None) -> List[Dict]:
        """Ultra-safe tweet search with enhanced error handling"""
        if not self.client:
            self.logger.error("Twitter client not initialized")
            return []
        
        # Check cache first
        cache_key = f"search_v71_{query}_{max_results}_{start_time}"
        cached_result = self.cache_manager.get(cache_key, max_age_hours=12)  # Longer cache
        if cached_result:
            self.logger.info(f"Using cached results for: {query[:50]}...")
            return cached_result
        
        # Check if we're blocked
        blocked, remaining_time = self.rate_manager.is_blocked()
        if blocked:
            self.logger.warning(f"Rate limit block active - {remaining_time:.0f}s remaining")
            return []
        
        # Check daily quota
        quota_ok, remaining_quota = self.rate_manager.check_daily_quota()
        if not quota_ok:
            self.logger.warning(f"Daily quota exhausted ({self.rate_manager.daily_requests}/{self.rate_manager.DAILY_LIMIT})")
            return []
        
        collected_tweets = []
        max_retries = 1  # Only one retry to be safe
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Wait if needed
                wait_time = self.rate_manager.wait_if_needed()
                if wait_time > 0:
                    self.logger.warning(f"Preventive wait: {wait_time:.1f}s...")
                    if wait_time > 3600:  # Don't wait more than 1 hour in this session
                        self.logger.warning("Wait time too long, skipping request")
                        break
                    time.sleep(min(wait_time, 60))  # Cap actual wait at 1 minute for demo
                
                self.logger.info(f"Searching Twitter: {query[:50]}...")
                
                # Make the actual API call
                response = self.client.search_recent_tweets(
                    query=query,
                    tweet_fields=['author_id', 'created_at', 'public_metrics', 'context_annotations'],
                    max_results=min(max_results, 3),  # Cap at 3
                    start_time=start_time
                )
                
                if response and response.data:
                    for tweet in response.data:
                        tweet_data = {
                            'id': str(tweet.id),
                            'text': tweet.text,
                            'author_id': str(tweet.author_id),
                            'created_at': tweet.created_at.isoformat() if tweet.created_at else '',
                            'public_metrics': tweet.public_metrics or {},
                            'context_annotations': getattr(tweet, 'context_annotations', []),
                            'collected_at': datetime.now().isoformat()
                        }
                        collected_tweets.append(tweet_data)
                    
                    self.logger.info(f"✅ Collected {len(response.data)} tweets")
                    self.rate_manager.reset_error_counter()
                    
                    # Cache the results
                    self.cache_manager.set(cache_key, collected_tweets)
                    
                elif response:
                    self.logger.info("Search successful but no tweets found")
                    self.rate_manager.reset_error_counter()
                    # Cache empty result
                    self.cache_manager.set(cache_key, [])
                
                break  # Success, exit retry loop
                
            except tweepy.TooManyRequests as e:
                retry_count += 1
                self.logger.error(f"❌ RATE LIMIT HIT (attempt {retry_count})")
                
                # Extract reset time from headers
                reset_time = None
                if hasattr(e, 'response') and e.response and e.response.headers:
                    try:
                        reset_time = int(e.response.headers.get('x-rate-limit-reset', 0))
                        remaining = e.response.headers.get('x-rate-limit-remaining', 'unknown')
                        limit = e.response.headers.get('x-rate-limit-limit', 'unknown')
                        self.logger.info(f"Rate limit info - Limit: {limit}, Remaining: {remaining}, Reset: {reset_time}")
                    except (ValueError, TypeError, AttributeError):
                        pass
                
                block_duration = self.rate_manager.handle_rate_limit_error(reset_time)
                
                if retry_count < max_retries:
                    wait_time = min(block_duration, 300)  # Cap at 5 minutes for immediate retry
                    self.logger.warning(f"Waiting {wait_time:.0f}s before retry...")
                    time.sleep(wait_time)
                else:
                    self.logger.error("Maximum retries reached, giving up")
                    break
                
            except tweepy.Unauthorized as e:
                self.logger.error(f"❌ Authentication error: {e}")
                break
                
            except tweepy.Forbidden as e:
                self.logger.error(f"❌ Forbidden: {e}")
                break
                
            except Exception as e:
                retry_count += 1
                self.logger.error(f"❌ Search error (attempt {retry_count}): {e}")
                if retry_count < max_retries:
                    time.sleep(60)  # Wait before retry
        
        return collected_tweets
    
    def collect_threat_tweets(self, days_back: int = 1, max_per_keyword: int = 1) -> List[Dict]:
        """Collect cybersecurity tweets with extreme safety for free tier"""
        if not self.client:
            self.logger.error("Twitter client unavailable")
            return []
        
        # Check if we're blocked at the start
        blocked, remaining_time = self.rate_manager.is_blocked()
        if blocked:
            self.logger.error(f"Rate limit block active - {remaining_time:.0f}s remaining")
            return []
        
        # Check daily quota
        quota_ok, remaining_quota = self.rate_manager.check_daily_quota()
        if not quota_ok:
            self.logger.error(f"Daily quota exhausted ({self.rate_manager.daily_requests}/{self.rate_manager.DAILY_LIMIT})")
            return []
            
        self.logger.info(f"🚀 Starting CTI tweet collection (last {days_back} days)")
        self.logger.info(f"🔧 API Tier: {self.api_tier_info.get('tier', 'unknown')} (reason: {self.api_tier_info.get('reason', 'unknown')})")
        self.logger.info(f"📊 Daily quota: {self.rate_manager.daily_requests}/{self.rate_manager.DAILY_LIMIT}")
        
        collected_tweets = []
        since_date = datetime.now() - timedelta(days=days_back)
        
        # Use only ONE keyword to minimize API calls for free tier
        priority_keywords = ['ransomware']  # UN SEUL mot-clé pour free tier
        
        for i, keyword in enumerate(priority_keywords):
            try:
                # Check block status before each keyword
                blocked, remaining_time = self.rate_manager.is_blocked()
                if blocked:
                    self.logger.warning(f"Blocked before keyword '{keyword}' - {remaining_time:.0f}s remaining")
                    break
                
                # Check quota again
                quota_ok, remaining_quota = self.rate_manager.check_daily_quota()
                if not quota_ok:
                    self.logger.warning(f"Daily quota reached before keyword '{keyword}'")
                    break
                
                self.logger.info(f"🔍 Searching keyword: {keyword}")
                
                # Highly optimized query for CTI
                query = f'"{keyword}" -is:retweet -is:reply lang:en min_retweets:1 min_faves:2'
                
                keyword_tweets = self._safe_search_tweets(
                    query=query,
                    max_results=max_per_keyword,
                    start_time=since_date
                )
                
                # Add metadata
                for tweet in keyword_tweets:
                    tweet['keyword'] = keyword
                    tweet['source'] = 'keyword_search'
                    tweet['relevance_score'] = self._calculate_relevance(tweet, keyword)
                
                collected_tweets.extend(keyword_tweets)
                self.logger.info(f"📊 Total for '{keyword}': {len(keyword_tweets)} tweets")
                
            except Exception as e:
                self.logger.error(f"❌ Error collecting '{keyword}': {e}")
                time.sleep
        # Délai entre mots-clés pour éviter la surcharge
                if i < len(priority_keywords) - 1:  # Pas de délai après le dernier mot-clé
                    delay = 60  # 1 minute entre les mots-clés
                    self.logger.info(f"⏳ Waiting {delay}s between keywords...")
                    time.sleep(delay)
                    
            except Exception as e:
                self.logger.error(f"❌ Error collecting '{keyword}': {e}")
                time.sleep(60)  # Wait before continuing
        
        # Filtrer et trier les tweets collectés
        filtered_tweets = self._filter_quality_tweets(collected_tweets)
        
        self.logger.info(f"🎯 Collection completed: {len(filtered_tweets)} high-quality tweets")
        self.logger.info(f"📊 Quota used: {self.rate_manager.daily_requests}/{self.rate_manager.DAILY_LIMIT}")
        
        return filtered_tweets
    
    def _calculate_relevance(self, tweet: Dict, keyword: str) -> float:
        """Calculate relevance score for a tweet"""
        try:
            text = tweet.get('text', '').lower()
            score = 0.0
            
            # Keyword presence (base score)
            if keyword.lower() in text:
                score += 1.0
            
            # CTI-related terms boost
            cti_terms = ['apt', 'malware', 'attack', 'breach', 'vulnerability', 
                        'exploit', 'threat', 'security', 'cyber']
            for term in cti_terms:
                if term in text:
                    score += 0.2
            
            # Engagement metrics boost
            metrics = tweet.get('public_metrics', {})
            retweets = metrics.get('retweet_count', 0)
            likes = metrics.get('like_count', 0)
            
            if retweets > 5:
                score += 0.3
            if likes > 10:
                score += 0.3
            
            # Context annotations boost (if available)
            if tweet.get('context_annotations'):
                score += 0.2
            
            return min(score, 3.0)  # Cap at 3.0
            
        except Exception:
            return 0.5  # Default score if calculation fails
    
    def _filter_quality_tweets(self, tweets: List[Dict]) -> List[Dict]:
        """Filter and sort tweets by quality and relevance"""
        if not tweets:
            return []
        
        # Remove duplicates by ID
        seen_ids = set()
        unique_tweets = []
        for tweet in tweets:
            tweet_id = tweet.get('id')
            if tweet_id and tweet_id not in seen_ids:
                seen_ids.add(tweet_id)
                unique_tweets.append(tweet)
        
        # Filter by minimum relevance score
        quality_tweets = [t for t in unique_tweets if t.get('relevance_score', 0) >= 1.0]
        
        # Sort by relevance score (highest first)
        quality_tweets.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        
        return quality_tweets[:10]  # Return top 10
    
    def get_status_report(self) -> Dict:
        """Get detailed status report"""
        blocked, remaining_time = self.rate_manager.is_blocked()
        quota_ok, remaining_quota = self.rate_manager.check_daily_quota()
        
        return {
            'client_status': '✅ initialized' if self.client else '❌ failed',
            'blocked': blocked,
            'blocked_remaining_seconds': remaining_time,
            'current_window_requests': len(self.rate_manager.request_times),
            'max_requests_per_window': self.rate_manager.requests_per_window,
            'consecutive_errors': self.rate_manager.consecutive_errors,
            'api_tier': self.api_tier_info.get('tier', 'unknown'),
            'strategy': '🛡️ ultra_conservative_v7_free_tier_optimized',
            'cache_enabled': '✅ active',
            'daily_requests_used': self.rate_manager.daily_requests,
            'daily_limit': self.rate_manager.DAILY_LIMIT,
            'daily_quota_ok': quota_ok,
            'daily_remaining': remaining_quota
        }
    
    def test_connection(self) -> Dict:
        """Test connection with caching"""
        cache_key = "connection_test_v71"
        cached_result = self.cache_manager.get(cache_key, max_age_hours=1)
        
        if cached_result:
            self.logger.info("Using cached connection test result")
            return cached_result
        
        # Perform actual connection test
        result = {
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'error': None
        }
        
        try:
            if not self.client:
                result['error'] = 'Client not initialized'
                return result
            
            # Simple test with minimal quota impact
            test_query = "twitter -is:retweet"
            tweets = self._safe_search_tweets(test_query, max_results=1)
            
            result['success'] = True
            result['tweets_found'] = len(tweets)
            
        except Exception as e:
            result['error'] = str(e)
            self.logger.error(f"Connection test failed: {e}")
        
        # Cache result
        self.cache_manager.set(cache_key, result)
        return result
    
    def clear_rate_limits(self):
        """Clear rate limits - use with extreme caution"""
        self.logger.warning("🚨 CLEARING ALL RATE LIMITS - USE WITH CAUTION!")
        self.rate_manager.reset_all_limits()
        self.cache_manager.clear_connection_cache()

def main():
    """Main execution function"""
    print("🐦 Twitter CTI Collector V7.1 - Free Tier Ultra-Conservative")
    print("=" * 60)
    
    try:
        # Initialize collector
        collector = TwitterCollector()
        
        # Test connection
        print("🔍 Testing Twitter connection...")
        connection_result = collector.test_connection()
        
        if connection_result['success']:
            print("✅ Connection successful")
            
            # Collect tweets
            print("\n🚀 Starting tweet collection...")
            tweets = collector.collect_threat_tweets(days_back=1, max_per_keyword=1)
            
            if tweets:
                print(f"\n📊 Collection Summary:")
                print(f"   • Total tweets: {len(tweets)}")
                print(f"   • Top keywords: {', '.join(set(t.get('keyword', '') for t in tweets[:3]))}")
                
                # Show sample tweets
                print(f"\n📋 Sample tweets:")
                for i, tweet in enumerate(tweets[:3], 1):
                    print(f"   {i}. {tweet.get('text', '')[:100]}...")
                    print(f"      Score: {tweet.get('relevance_score', 0):.1f}, Keyword: {tweet.get('keyword', 'N/A')}")
            else:
                print("⚠️ No tweets collected")
        else:
            print(f"❌ Connection failed: {connection_result.get('error', 'Unknown error')}")
    
    except KeyboardInterrupt:
        print("\n🛑 Collection interrupted by user")
    except Exception as e:
        print(f"\n💥 Fatal error: {e}")
    finally:
        # Show final status
        if 'collector' in locals():
            print(f"\n=== Final Status ===")
            status = collector.get_status_report()
            for key, value in status.items():
                print(f"{key}: {value}")

if __name__ == "__main__":
    main()        