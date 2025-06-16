#!/usr/bin/env python3

import requests
import csv
import os
import logging
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import argparse
import json
from ioc_database import IOCDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class IOCFeedManager:
    def __init__(self, db_path: str = "data/ioc_database.db", config_path: str = "ioc_feeds_config.json"):
        """Initialize IOC feed manager"""
        self.db = IOCDatabase(db_path)
        self.config_path = config_path
        self.feeds_dir = "ioc_feeds"
        
        # Create feeds directory
        os.makedirs(self.feeds_dir, exist_ok=True)
        
        # Default feed configuration
        self.default_feeds = {
            "abuse_ch_malware": {
                "name": "Abuse.ch Malware Hashes",
                "url": "https://bazaar.abuse.ch/export/csv/recent/",
                "format": "csv",
                "enabled": True,
                "frequency": "daily",
                "mapping": {
                    "ioc_value": "sha256_hash",
                    "ioc_type": "sha256",
                    "threat_type": "malware",
                    "malware_family": "signature",
                    "source": "abuse.ch",
                    "first_seen": "first_seen"
                },
                "confidence": 85,
                "severity": "high"
            },
            "blocklist_de_ips": {
                "name": "Blocklist.de IP Addresses",
                "url": "https://lists.blocklist.de/lists/all.txt",
                "format": "txt",
                "enabled": True,
                "frequency": "daily",
                "mapping": {
                    "ioc_value": "ip",
                    "ioc_type": "ip",
                    "threat_type": "malicious_activity",
                    "source": "blocklist.de"
                },
                "confidence": 75,
                "severity": "medium"
            },
            "phishtank_urls": {
                "name": "PhishTank URLs",
                "url": "http://data.phishtank.com/data/online-valid.csv",
                "format": "csv",
                "enabled": False,  # Requires API key
                "frequency": "daily",
                "mapping": {
                    "ioc_value": "url",
                    "ioc_type": "url",
                    "threat_type": "phishing",
                    "source": "phishtank",
                    "first_seen": "submission_time"
                },
                "confidence": 90,
                "severity": "high"
            },
            "malware_domains": {
                "name": "Malware Domain List",
                "url": "http://www.malwaredomainlist.com/mdlcsv.php",
                "format": "csv",
                "enabled": True,
                "frequency": "daily",
                "mapping": {
                    "ioc_value": "domain",
                    "ioc_type": "domain",
                    "threat_type": "malware",
                    "source": "malwaredomainlist.com",
                    "description": "description"
                },
                "confidence": 80,
                "severity": "high"
            }
        }
        
        self.load_config()
    
    def load_config(self):
        """Load feed configuration from file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    self.feeds = config.get('feeds', self.default_feeds)
                    self.settings = config.get('settings', {})
                logger.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
                self.feeds = self.default_feeds
                self.settings = {}
        else:
            self.feeds = self.default_feeds
            self.settings = {}
            self.save_config()
    
    def save_config(self):
        """Save feed configuration to file"""
        try:
            config = {
                'feeds': self.feeds,
                'settings': self.settings,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
                
            logger.info(f"Configuration saved to {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
    
    def download_feed(self, feed_name: str, feed_config: Dict) -> Optional[str]:
        """Download a single IOC feed"""
        try:
            logger.info(f"Downloading feed: {feed_config['name']}")
            
            # Create filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.feeds_dir}/{feed_name}_{timestamp}.txt"
            
            # Download feed
            headers = {
                'User-Agent': 'SOC-Analyst-Bot/1.0'
            }
            
            response = requests.get(feed_config['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            # Save to file
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            logger.info(f"Downloaded {len(response.text)} bytes to {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to download feed {feed_name}: {e}")
            return None
    
    def parse_csv_feed(self, filename: str, feed_config: Dict) -> List[Dict]:
        """Parse CSV format IOC feed"""
        iocs = []
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                # Skip comments and empty lines
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if not lines:
                    return iocs
                
                # Try to detect if first line is header
                first_line = lines[0]
                has_header = any(field in first_line.lower() for field in ['hash', 'ip', 'domain', 'url'])
                
                reader = csv.DictReader(lines) if has_header else csv.reader(lines)
                
                mapping = feed_config.get('mapping', {})
                
                for row in reader:
                    try:
                        if isinstance(row, dict):
                            # CSV with headers
                            ioc_data = self.map_csv_fields(row, mapping, feed_config)
                        else:
                            # CSV without headers - assume first column is IOC value
                            ioc_data = {
                                'ioc_value': row[0] if row else '',
                                'ioc_type': feed_config.get('default_type', 'unknown'),
                                'source': feed_config.get('mapping', {}).get('source', 'unknown'),
                                'threat_type': feed_config.get('mapping', {}).get('threat_type', 'unknown'),
                                'confidence': feed_config.get('confidence', 50),
                                'severity': feed_config.get('severity', 'medium')
                            }
                        
                        if ioc_data.get('ioc_value'):
                            iocs.append(ioc_data)
                            
                    except Exception as e:
                        logger.warning(f"Failed to parse row: {e}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to parse CSV feed {filename}: {e}")
        
        return iocs
    
    def parse_txt_feed(self, filename: str, feed_config: Dict) -> List[Dict]:
        """Parse plain text IOC feed"""
        iocs = []
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    
                    # Extract IOC value (first word/token)
                    ioc_value = line.split()[0]
                    
                    if ioc_value:
                        ioc_data = {
                            'ioc_value': ioc_value,
                            'ioc_type': self.auto_detect_type(ioc_value),
                            'source': feed_config.get('mapping', {}).get('source', 'unknown'),
                            'threat_type': feed_config.get('mapping', {}).get('threat_type', 'unknown'),
                            'confidence': feed_config.get('confidence', 50),
                            'severity': feed_config.get('severity', 'medium'),
                            'description': f"From {feed_config.get('name', 'unknown')} feed"
                        }
                        
                        iocs.append(ioc_data)
                        
        except Exception as e:
            logger.error(f"Failed to parse text feed {filename}: {e}")
        
        return iocs
    
    def map_csv_fields(self, row: Dict, mapping: Dict, feed_config: Dict) -> Dict:
        """Map CSV fields to IOC database fields"""
        ioc_data = {}
        
        # Map configured fields
        for db_field, csv_field in mapping.items():
            if csv_field in row:
                ioc_data[db_field] = row[csv_field]
        
        # Add defaults
        if 'confidence' not in ioc_data:
            ioc_data['confidence'] = feed_config.get('confidence', 50)
            
        if 'severity' not in ioc_data:
            ioc_data['severity'] = feed_config.get('severity', 'medium')
        
        # Auto-detect IOC type if not specified
        if 'ioc_type' not in ioc_data and 'ioc_value' in ioc_data:
            ioc_data['ioc_type'] = self.auto_detect_type(ioc_data['ioc_value'])
        
        return ioc_data
    
    def auto_detect_type(self, ioc_value: str) -> str:
        """Auto-detect IOC type based on value"""
        import re
        
        ioc_value = str(ioc_value).strip()
        
        # Hash patterns
        if re.match(r'^[a-fA-F0-9]{32}$', ioc_value):
            return 'md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc_value):
            return 'sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc_value):
            return 'sha256'
        
        # IP patterns
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_value):
            return 'ip'
        
        # URL pattern
        elif ioc_value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # Domain pattern (basic check)
        elif '.' in ioc_value and not '/' in ioc_value and not ' ' in ioc_value:
            return 'domain'
        
        # Email pattern
        elif '@' in ioc_value and '.' in ioc_value:
            return 'email'
        
        # Default
        return 'unknown'
    
    def process_feed(self, feed_name: str) -> Dict:
        """Download and process a single feed"""
        feed_config = self.feeds.get(feed_name)
        
        if not feed_config:
            return {'success': False, 'error': f'Feed {feed_name} not found'}
        
        if not feed_config.get('enabled', False):
            return {'success': False, 'error': f'Feed {feed_name} is disabled'}
        
        # Download feed
        filename = self.download_feed(feed_name, feed_config)
        
        if not filename:
            return {'success': False, 'error': 'Download failed'}
        
        # Parse feed based on format
        feed_format = feed_config.get('format', 'txt')
        
        if feed_format == 'csv':
            iocs = self.parse_csv_feed(filename, feed_config)
        else:
            iocs = self.parse_txt_feed(filename, feed_config)
        
        if not iocs:
            return {'success': False, 'error': 'No IOCs found in feed'}
        
        # Import to database
        added_count, failed_count = self.db.add_iocs_batch(iocs)
        
        # Clean up downloaded file
        try:
            os.remove(filename)
        except:
            pass
        
        result = {
            'success': True,
            'feed_name': feed_name,
            'total_iocs': len(iocs),
            'added': added_count,
            'failed': failed_count,
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info(f"Processed feed {feed_name}: {added_count} added, {failed_count} failed")
        return result
    
    def update_all_feeds(self) -> Dict:
        """Update all enabled feeds"""
        results = {
            'success': True,
            'feeds_processed': 0,
            'total_added': 0,
            'total_failed': 0,
            'feed_results': {},
            'start_time': datetime.now().isoformat()
        }
        
        for feed_name, feed_config in self.feeds.items():
            if feed_config.get('enabled', False):
                logger.info(f"Processing feed: {feed_name}")
                
                result = self.process_feed(feed_name)
                results['feed_results'][feed_name] = result
                
                if result['success']:
                    results['feeds_processed'] += 1
                    results['total_added'] += result['added']
                    results['total_failed'] += result['failed']
                else:
                    logger.error(f"Feed {feed_name} failed: {result.get('error', 'Unknown error')}")
        
        results['end_time'] = datetime.now().isoformat()
        logger.info(f"Feed update completed: {results['feeds_processed']} feeds processed, {results['total_added']} IOCs added")
        
        return results
    
    def list_feeds(self):
        """List all configured feeds"""
        print("\n🌐 Configured IOC Feeds")
        print("=" * 50)
        
        for feed_name, feed_config in self.feeds.items():
            status = "✅ Enabled" if feed_config.get('enabled', False) else "❌ Disabled"
            print(f"📡 {feed_config.get('name', feed_name)}")
            print(f"   Status: {status}")
            print(f"   URL: {feed_config.get('url', 'N/A')}")
            print(f"   Format: {feed_config.get('format', 'txt')}")
            print(f"   Frequency: {feed_config.get('frequency', 'manual')}")
            print()
    
    def enable_feed(self, feed_name: str):
        """Enable a feed"""
        if feed_name in self.feeds:
            self.feeds[feed_name]['enabled'] = True
            self.save_config()
            print(f"✅ Feed '{feed_name}' enabled")
        else:
            print(f"❌ Feed '{feed_name}' not found")
    
    def disable_feed(self, feed_name: str):
        """Disable a feed"""
        if feed_name in self.feeds:
            self.feeds[feed_name]['enabled'] = False
            self.save_config()
            print(f"❌ Feed '{feed_name}' disabled")
        else:
            print(f"❌ Feed '{feed_name}' not found")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='IOC Feed Manager')
    parser.add_argument('--update', '-u', action='store_true', help='Update all enabled feeds')
    parser.add_argument('--feed', '-f', help='Update specific feed')
    parser.add_argument('--list', '-l', action='store_true', help='List all feeds')
    parser.add_argument('--enable', help='Enable a feed')
    parser.add_argument('--disable', help='Disable a feed')
    parser.add_argument('--config', default='ioc_feeds_config.json', help='Config file path')
    parser.add_argument('--db-path', default='data/ioc_database.db', help='Database path')
    
    args = parser.parse_args()
    
    manager = IOCFeedManager(args.db_path, args.config)
    
    if args.list:
        manager.list_feeds()
    
    elif args.enable:
        manager.enable_feed(args.enable)
    
    elif args.disable:
        manager.disable_feed(args.disable)
    
    elif args.feed:
        result = manager.process_feed(args.feed)
        if result['success']:
            print(f"✅ Feed '{args.feed}' updated: {result['added']} IOCs added")
        else:
            print(f"❌ Feed '{args.feed}' failed: {result['error']}")
    
    elif args.update:
        print("🌐 Updating all enabled IOC feeds...")
        results = manager.update_all_feeds()
        
        print(f"\n📊 Update Summary:")
        print(f"Feeds processed: {results['feeds_processed']}")
        print(f"Total IOCs added: {results['total_added']}")
        print(f"Total failures: {results['total_failed']}")
        
        if results['feed_results']:
            print(f"\n📋 Feed Details:")
            for feed_name, result in results['feed_results'].items():
                status = "✅" if result['success'] else "❌"
                print(f"{status} {feed_name}: {result.get('added', 0)} added")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
