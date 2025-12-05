"""
Enhanced Telegram Collector for CTI Monitoring
- Improved error handling and debugging
- Better channel management
- Support for public channels without admin access
"""
import sys
import os
import json
import asyncio
from datetime import datetime, timedelta
import aiohttp
from typing import List, Dict, Optional

class TelegramCollector:
    def __init__(self):
        # Configure paths
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        
        # Load API keys
        try:
            with open(os.path.join(base_path, '../config/api_keys.json'), 'r') as f:
                api_keys = json.load(f)
            self.bot_token = api_keys.get('telegram_bot_token')
            
            if not self.bot_token:
                raise ValueError("Token bot Telegram manquant dans api_keys.json")
                
        except FileNotFoundError:
            raise ValueError("Fichier api_keys.json non trouvé")
        
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}"
        
        # Load channels configuration
        try:
            with open(os.path.join(base_path, '../config/telegram_channels.json'), 'r') as f:
                channels_data = json.load(f)
                self.channels = channels_data.get('channels', [])
        except FileNotFoundError:
            print("Warning: telegram_channels.json not found. Using default configuration.")
            self.channels = self._get_default_channels()
        
        self.session = None
        self.update_offset = 0
    
    def _get_default_channels(self) -> List[Dict]:
        """Retourne une configuration par défaut de canaux CTI publics"""
        return [
            {
                "name": "CyberSecurity News",
                "username": "@cybersecuritynews",
                "category": "news",
                "description": "General cybersecurity news"
            },
            {
                "name": "Malware Research",
                "username": "@malwareresearch",
                "category": "malware",
                "description": "Malware analysis and research"
            },
            {
                "name": "Threat Intelligence",
                "username": "@threatintelligence",
                "category": "intelligence",
                "description": "Threat intelligence feeds"
            }
        ]
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Retourne une session HTTP réutilisable"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def close_session(self):
        """Ferme la session HTTP"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def get_bot_info(self) -> Dict:
        """Récupère les informations du bot"""
        try:
            session = await self._get_session()
            url = f"{self.base_url}/getMe"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('result', {})
                else:
                    print(f"Erreur API (getMe): {response.status}")
                    return {}
                    
        except Exception as e:
            print(f"Erreur lors de la récupération des infos bot: {e}")
            return {}
    
    async def get_updates(self, limit: int = 100, offset: int = None) -> List[Dict]:
        """Récupère les mises à jour du bot"""
        try:
            session = await self._get_session()
            url = f"{self.base_url}/getUpdates"
            
            params = {
                'limit': limit,
                'allowed_updates': ['message', 'channel_post', 'edited_channel_post']
            }
            
            if offset:
                params['offset'] = offset
            elif self.update_offset > 0:
                params['offset'] = self.update_offset
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    updates = data.get('result', [])
                    
                    # Update offset for next call
                    if updates:
                        self.update_offset = updates[-1]['update_id'] + 1
                    
                    return updates
                else:
                    print(f"Erreur API (getUpdates): {response.status}")
                    text = await response.text()
                    print(f"Response: {text}")
                    return []
                    
        except Exception as e:
            print(f"Erreur lors de la récupération des updates: {e}")
            return []
    
    async def get_chat_info(self, chat_id: str) -> Dict:
        """Récupère les informations d'un chat/canal"""
        try:
            session = await self._get_session()
            url = f"{self.base_url}/getChat"
            
            params = {'chat_id': chat_id}
            
            async with session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('result', {})
                else:
                    print(f"Erreur API (getChat): {response.status} pour {chat_id}")
                    return {}
                    
        except Exception as e:
            print(f"Erreur lors de la récupération des infos chat {chat_id}: {e}")
            return {}
    
    async def check_bot_permissions(self) -> Dict[str, bool]:
        """Vérifie les permissions du bot sur les canaux configurés"""
        permissions = {}
        
        print("\n🔍 Vérification des permissions du bot...")
        
        for channel in self.channels:
            username = channel['username']
            print(f"  Vérification: {username}")
            
            try:
                # Try to get chat info
                chat_info = await self.get_chat_info(username)
                
                if chat_info:
                    chat_type = chat_info.get('type', 'unknown')
                    permissions[username] = {
                        'accessible': True,
                        'type': chat_type,
                        'title': chat_info.get('title', 'Unknown'),
                        'member_count': chat_info.get('members_count', 0)
                    }
                    print(f"    ✅ Accessible - Type: {chat_type}")
                else:
                    permissions[username] = {
                        'accessible': False,
                        'error': 'Cannot access chat'
                    }
                    print(f"    ❌ Non accessible")
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                permissions[username] = {
                    'accessible': False,
                    'error': str(e)
                }
                print(f"    ❌ Erreur: {e}")
        
        return permissions
    
    async def collect_recent_messages(self, days_back: int = 1) -> List[Dict]:
        """Collecte les messages récents via getUpdates"""
        try:
            print(f"\n📡 Collecte des messages des {days_back} derniers jours...")
            
            all_messages = []
            since_date = datetime.now() - timedelta(days=days_back)
            
            # Get recent updates
            print("  Récupération des updates récentes...")
            updates = await self.get_updates(limit=100)
            
            print(f"  {len(updates)} updates trouvées")
            
            for update in updates:
                try:
                    message_data = None
                    
                    # Handle channel posts
                    if 'channel_post' in update:
                        post = update['channel_post']
                        message_data = await self._process_message(post, 'channel_post', since_date)
                    
                    # Handle regular messages (if bot is in groups)
                    elif 'message' in update:
                        message = update['message']
                        message_data = await self._process_message(message, 'message', since_date)
                    
                    # Handle edited channel posts
                    elif 'edited_channel_post' in update:
                        post = update['edited_channel_post']
                        message_data = await self._process_message(post, 'edited_channel_post', since_date)
                    
                    if message_data:
                        all_messages.append(message_data)
                        
                except Exception as e:
                    print(f"    Erreur traitement update: {e}")
                    continue
            
            # Save messages
            if all_messages:
                await self._save_messages(all_messages)
            
            print(f"✅ {len(all_messages)} messages collectés et sauvegardés")
            
            return all_messages
            
        except Exception as e:
            print(f"❌ Erreur lors de la collecte: {e}")
            return []
    
    async def _process_message(self, message: Dict, message_type: str, since_date: datetime) -> Optional[Dict]:
        """Traite un message individuel"""
        try:
            post_date = datetime.fromtimestamp(message.get('date', 0))
            
            # Skip old messages
            if post_date < since_date:
                return None
            
            chat = message.get('chat', {})
            chat_type = chat.get('type', '')
            chat_username = chat.get('username', '').replace('@', '')
            
            # Only process channel messages or messages from monitored chats
            if chat_type not in ['channel', 'supergroup'] and not chat_username:
                return None
            
            # Find matching channel configuration
            channel_info = None
            for ch in self.channels:
                if ch['username'].replace('@', '') == chat_username:
                    channel_info = ch
                    break
            
            # Create message data
            message_data = {
                'id': message.get('message_id'),
                'text': message.get('text', ''),
                'caption': message.get('caption', ''),
                'date': post_date.isoformat(),
                'chat_id': chat.get('id'),
                'chat_title': chat.get('title', ''),
                'chat_username': chat_username,
                'chat_type': chat_type,
                'message_type': message_type,
                'views': message.get('views', 0),
                'forwards': message.get('forward_from_message_id', 0),
                'collected_at': datetime.now().isoformat(),
                'source': 'bot_api'
            }
            
            # Add channel info if found
            if channel_info:
                message_data.update({
                    'channel_name': channel_info['name'],
                    'channel_category': channel_info['category'],
                    'monitored_channel': True
                })
            else:
                message_data['monitored_channel'] = False
            
            # Extract entities (URLs, mentions, hashtags)
            entities = message.get('entities', []) + message.get('caption_entities', [])
            if entities:
                message_data['entities'] = await self._extract_entities(message, entities)
            
            # Extract media info
            if 'photo' in message or 'document' in message or 'video' in message:
                message_data['has_media'] = True
                message_data['media_type'] = self._get_media_type(message)
            
            return message_data
            
        except Exception as e:
            print(f"    Erreur traitement message: {e}")
            return None
    
    async def _extract_entities(self, message: Dict, entities: List[Dict]) -> Dict:
        """Extrait les entités du message (URLs, hashtags, etc.)"""
        extracted = {
            'urls': [],
            'hashtags': [],
            'mentions': [],
            'bot_commands': []
        }
        
        text = message.get('text', '') or message.get('caption', '')
        
        for entity in entities:
            entity_type = entity.get('type', '')
            offset = entity.get('offset', 0)
            length = entity.get('length', 0)
            entity_text = text[offset:offset+length]
            
            if entity_type == 'url':
                extracted['urls'].append(entity_text)
            elif entity_type == 'hashtag':
                extracted['hashtags'].append(entity_text)
            elif entity_type == 'mention':
                extracted['mentions'].append(entity_text)
            elif entity_type == 'bot_command':
                extracted['bot_commands'].append(entity_text)
        
        return extracted
    
    def _get_media_type(self, message: Dict) -> str:
        """Détermine le type de média dans le message"""
        if 'photo' in message:
            return 'photo'
        elif 'document' in message:
            return 'document'
        elif 'video' in message:
            return 'video'
        elif 'audio' in message:
            return 'audio'
        elif 'voice' in message:
            return 'voice'
        elif 'sticker' in message:
            return 'sticker'
        return 'unknown'
    
    async def _save_messages(self, messages: List[Dict]):
        """Sauvegarde les messages collectés"""
        try:
            # Create output directory
            output_dir = "output/daily_feeds"
            os.makedirs(output_dir, exist_ok=True)
            
            # Save with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(output_dir, f"telegram_messages_{timestamp}.json")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(messages, f, indent=2, ensure_ascii=False)
            
            print(f"  💾 Messages sauvegardés dans: {output_file}")
            
        except Exception as e:
            print(f"  ❌ Erreur sauvegarde: {e}")
    
    async def search_keywords(self, keywords: List[str], days_back: int = 7) -> List[Dict]:
        """Recherche par mots-clés dans les messages récents"""
        try:
            print(f"\n🔍 Recherche pour: {', '.join(keywords)}")
            
            # Collect recent messages
            messages = await self.collect_recent_messages(days_back)
            
            search_results = []
            keywords_lower = [k.lower() for k in keywords]
            
            for message in messages:
                text = (message.get('text', '') + ' ' + message.get('caption', '')).lower()
                
                for i, keyword in enumerate(keywords_lower):
                    if keyword in text:
                        result = message.copy()
                        result['matched_keyword'] = keywords[i]  # Original case
                        result['search_date'] = datetime.now().isoformat()
                        search_results.append(result)
                        break
            
            print(f"✅ {len(search_results)} résultats trouvés")
            
            # Save search results
            if search_results:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                search_file = f"output/searches/telegram_search_{timestamp}.json"
                os.makedirs(os.path.dirname(search_file), exist_ok=True)
                
                with open(search_file, 'w', encoding='utf-8') as f:
                    json.dump({
                        'keywords': keywords,
                        'search_date': datetime.now().isoformat(),
                        'results_count': len(search_results),
                        'results': search_results
                    }, f, indent=2, ensure_ascii=False)
                
                print(f"  💾 Résultats sauvegardés dans: {search_file}")
            
            return search_results
            
        except Exception as e:
            print(f"❌ Erreur lors de la recherche: {e}")
            return []
    
    async def run_diagnostics(self):
        """Lance un diagnostic complet du collecteur"""
        print("🔧 Diagnostic du collecteur Telegram\n")
        
        # 1. Test connexion bot
        print("1️⃣ Test de connexion du bot...")
        bot_info = await self.get_bot_info()
        
        if bot_info:
            print(f"   ✅ Bot connecté: @{bot_info.get('username')}")
            print(f"   📝 Nom: {bot_info.get('first_name')}")
            print(f"   🆔 ID: {bot_info.get('id')}")
        else:
            print("   ❌ Impossible de se connecter au bot")
            return
        
        # 2. Vérification des canaux
        print("\n2️⃣ Vérification des canaux configurés...")
        permissions = await self.check_bot_permissions()
        
        accessible_channels = sum(1 for p in permissions.values() if p.get('accessible', False))
        print(f"\n   📊 Résumé: {accessible_channels}/{len(permissions)} canaux accessibles")
        
        # 3. Test de collecte
        print("\n3️⃣ Test de collecte récente...")
        messages = await self.collect_recent_messages(days_back=1)
        
        if messages:
            print(f"   ✅ {len(messages)} messages collectés")
        else:
            print("   ⚠️ Aucun message récent trouvé")
            print("   💡 Suggestions:")
            print("      - Ajoutez le bot aux canaux comme administrateur")
            print("      - Vérifiez que les canaux sont actifs")
            print("      - Augmentez la période de collecte")
        
        # 4. Configuration
        print("\n4️⃣ Configuration actuelle...")
        print(f"   📋 Canaux surveillés: {len(self.channels)}")
        for channel in self.channels[:5]:  # Show first 5
            status = "✅" if permissions.get(channel['username'], {}).get('accessible', False) else "❌"
            print(f"      {status} {channel['username']} ({channel['category']})")
        
        if len(self.channels) > 5:
            print(f"      ... et {len(self.channels) - 5} autres")
        
        await self.close_session()
    
    # Wrapper methods for synchronous usage
    def run_collect(self, days_back: int = 1) -> List[Dict]:
        """Version synchrone de la collecte"""
        return asyncio.run(self._run_async_collect(days_back))
    
    def run_search(self, keywords: List[str], days_back: int = 7) -> List[Dict]:
        """Version synchrone de la recherche"""
        return asyncio.run(self._run_async_search(keywords, days_back))
    
    def run_diagnosis(self):
        """Version synchrone du diagnostic"""
        asyncio.run(self.run_diagnostics())
    
    async def _run_async_collect(self, days_back: int) -> List[Dict]:
        try:
            messages = await self.collect_recent_messages(days_back)
            return messages
        finally:
            await self.close_session()
    
    async def _run_async_search(self, keywords: List[str], days_back: int) -> List[Dict]:
        try:
            results = await self.search_keywords(keywords, days_back)
            return results
        finally:
            await self.close_session()


# CLI Interface
def main():
    try:
        collector = TelegramCollector()
        
        if len(sys.argv) < 2:
            print("🤖 Enhanced Telegram CTI Collector")
            print("\nCommandes disponibles:")
            print("  diagnose  - Lance un diagnostic complet")
            print("  collect   - Collecte les messages récents")
            print("  search    - Recherche par mots-clés")
            print("  info      - Affiche les infos du bot")
            print("\nExemples:")
            print("  python telegram_collector.py diagnose")
            print("  python telegram_collector.py collect --days 3")
            print("  python telegram_collector.py search malware,ransomware")
            return
        
        command = sys.argv[1].lower()
        
        if command == "diagnose":
            collector.run_diagnosis()
            
        elif command == "collect":
            days = 1
            if "--days" in sys.argv:
                try:
                    days = int(sys.argv[sys.argv.index("--days") + 1])
                except (IndexError, ValueError):
                    print("⚠️ Paramètre --days invalide, utilisation de 1 jour par défaut")
            
            messages = collector.run_collect(days)
            print(f"\n📊 Résultat final: {len(messages)} messages collectés")
            
        elif command == "search":
            if len(sys.argv) < 3:
                print("❌ Veuillez spécifier des mots-clés")
                print("Exemple: python telegram_collector.py search malware,phishing")
                return
            
            keywords = [k.strip() for k in sys.argv[2].split(',')]
            days = 7
            
            if "--days" in sys.argv:
                try:
                    days = int(sys.argv[sys.argv.index("--days") + 1])
                except (IndexError, ValueError):
                    print("⚠️ Paramètre --days invalide, utilisation de 7 jours par défaut")
            
            results = collector.run_search(keywords, days)
            print(f"\n📊 Résultat final: {len(results)} résultats trouvés")
            
        elif command == "info":
            # Just get bot info
            async def get_info():
                try:
                    info = await collector.get_bot_info()
                    if info:
                        print("🤖 Informations du bot:")
                        print(f"   Username: @{info.get('username')}")
                        print(f"   Name: {info.get('first_name')}")
                        print(f"   ID: {info.get('id')}")
                        print(f"   Can join groups: {info.get('can_join_groups')}")
                        print(f"   Can read all messages: {info.get('can_read_all_group_messages')}")
                    else:
                        print("❌ Impossible de récupérer les informations du bot")
                finally:
                    await collector.close_session()
            
            asyncio.run(get_info())
            
        else:
            print(f"❌ Commande inconnue: {command}")
            print("Utilisez 'diagnose', 'collect', 'search' ou 'info'")
            
    except Exception as e:
        print(f"❌ Erreur: {e}")
        print("\n🔧 Vérifiez votre configuration:")
        print("  1. Token bot dans config/api_keys.json")
        print("  2. Fichier config/telegram_channels.json")
        print("  3. Permissions du bot sur les canaux")


if __name__ == "__main__":
    main()