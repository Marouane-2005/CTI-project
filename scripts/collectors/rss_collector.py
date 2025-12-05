import sys
import os

# Ajoute le dossier scripts/ à sys.path
base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(base_path)

import feedparser
import json
import os
from datetime import datetime
from scripts.utils.database import DatabaseManager
from utils.logger import CTILogger

class RSSCollector:
    def __init__(self):
        self.db = DatabaseManager()
        self.logger = CTILogger("RSS_Collector")
        
        # Charger les sources RSS
        with open('../config/sources.json', 'r') as f:
            self.sources = json.load(f)['rss_feeds']
    
    def collect_feed(self, feed_config):
        """Collecte un feed RSS spécifique"""
        try:
            self.logger.info(f"Collecte du feed : {feed_config['name']}")
            
            # Parser le feed
            feed = feedparser.parse(feed_config['url'])
            
            collected_items = []
            
            for entry in feed.entries:
                item = {
                    'title': entry.title,
                    'link': entry.link,
                    'description': entry.get('description', ''),
                    'published': entry.get('published', ''),
                    'source': feed_config['name'],
                    'category': feed_config['category'],
                    'collected_at': datetime.now().isoformat()
                }
                collected_items.append(item)
            
            # Sauvegarder dans un fichier JSON
            output_file = f"output/daily_feeds/{feed_config['name']}_{datetime.now().strftime('%Y%m%d')}.json"
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(collected_items, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Feed {feed_config['name']} collecté : {len(collected_items)} items")
            return collected_items
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte du feed {feed_config['name']}: {e}")
            return []
    
    def collect_all_feeds(self):
        """Collecte tous les feeds RSS configurés"""
        all_items = []
        
        for feed_config in self.sources:
            items = self.collect_feed(feed_config)
            all_items.extend(items)
        
        # Sauvegarder le résumé global
        summary = {
            'total_items': len(all_items),
            'sources_count': len(self.sources),
            'collection_date': datetime.now().isoformat(),
            'items': all_items
        }
        
        summary_file = f"output/daily_feeds/daily_summary_{datetime.now().strftime('%Y%m%d')}.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Collecte terminée : {len(all_items)} items au total")
        return all_items

# Test du collecteur
if __name__ == "__main__":
    collector = RSSCollector()
    collector.collect_all_feeds()