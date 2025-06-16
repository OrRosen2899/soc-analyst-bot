import sqlite3
import logging
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import os

logger = logging.getLogger(__name__)

class IOCDatabase:
    def __init__(self, db_path: str = "data/ioc_database.db"):
        """Initialize IOC database"""
        self.db_path = db_path
        
        # Create data directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Create database tables if they don't exist"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create IOCs table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS iocs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc_type TEXT NOT NULL,
                        ioc_value TEXT NOT NULL UNIQUE,
                        threat_type TEXT,
                        malware_family TEXT,
                        source TEXT,
                        description TEXT,
                        confidence INTEGER DEFAULT 50,
                        severity TEXT DEFAULT 'medium',
                        first_seen DATE,
                        last_seen DATE,
                        tags TEXT,
                        reference_url TEXT,
                        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active BOOLEAN DEFAULT 1,
                        false_positive BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(ioc_value)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_type ON iocs(threat_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_active ON iocs(is_active)')
                
                # Create IOC hits table for tracking matches
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ioc_hits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc_id INTEGER,
                        hit_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source_info TEXT,
                        user_id TEXT,
                        FOREIGN KEY (ioc_id) REFERENCES iocs (id)
                    )
                ''')
                
                conn.commit()
                logger.info("IOC database initialized successfully")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def add_ioc(self, ioc_data: Dict) -> bool:
        """Add single IOC to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Normalize IOC value
                ioc_value = str(ioc_data.get('ioc_value', '')).strip().lower()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO iocs 
                    (ioc_type, ioc_value, threat_type, malware_family, source, 
                     description, confidence, severity, first_seen, last_seen, 
                     tags, reference_url)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc_data.get('ioc_type', '').lower(),
                    ioc_value,
                    ioc_data.get('threat_type', ''),
                    ioc_data.get('malware_family', ''),
                    ioc_data.get('source', ''),
                    ioc_data.get('description', ''),
                    int(ioc_data.get('confidence', 50)),
                    ioc_data.get('severity', 'medium').lower(),
                    ioc_data.get('first_seen', ''),
                    ioc_data.get('last_seen', ''),
                    ioc_data.get('tags', ''),
                    ioc_data.get('reference_url', '')
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to add IOC {ioc_value}: {e}")
            return False
    
    def add_iocs_batch(self, iocs_list: List[Dict]) -> Tuple[int, int]:
        """Add multiple IOCs to database"""
        added_count = 0
        failed_count = 0
        
        for ioc_data in iocs_list:
            if self.add_ioc(ioc_data):
                added_count += 1
            else:
                failed_count += 1
        
        logger.info(f"IOC batch import: {added_count} added, {failed_count} failed")
        return added_count, failed_count
    
    def search_ioc(self, ioc_value: str, ioc_type: str = None) -> Optional[Dict]:
        """Search for IOC in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Normalize search value
                ioc_value = str(ioc_value).strip().lower()
                
                if ioc_type:
                    query = '''
                        SELECT * FROM iocs 
                        WHERE ioc_value = ? AND ioc_type = ? AND is_active = 1
                    '''
                    cursor.execute(query, (ioc_value, ioc_type.lower()))
                else:
                    query = '''
                        SELECT * FROM iocs 
                        WHERE ioc_value = ? AND is_active = 1
                    '''
                    cursor.execute(query, (ioc_value,))
                
                result = cursor.fetchone()
                
                if result:
                    # Record the hit
                    self.record_hit(result['id'], f"Search for {ioc_value}")
                    
                    return dict(result)
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to search IOC {ioc_value}: {e}")
            return None
    
    def search_iocs_wildcard(self, pattern: str, ioc_type: str = None) -> List[Dict]:
        """Search IOCs with wildcard pattern"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if ioc_type:
                    query = '''
                        SELECT * FROM iocs 
                        WHERE ioc_value LIKE ? AND ioc_type = ? AND is_active = 1
                        LIMIT 50
                    '''
                    cursor.execute(query, (f"%{pattern}%", ioc_type.lower()))
                else:
                    query = '''
                        SELECT * FROM iocs 
                        WHERE ioc_value LIKE ? AND is_active = 1
                        LIMIT 50
                    '''
                    cursor.execute(query, (f"%{pattern}%",))
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Failed to search IOCs with pattern {pattern}: {e}")
            return []
    
    def get_iocs_by_type(self, ioc_type: str, limit: int = 100) -> List[Dict]:
        """Get IOCs by type"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM iocs 
                    WHERE ioc_type = ? AND is_active = 1
                    ORDER BY added_date DESC
                    LIMIT ?
                ''', (ioc_type.lower(), limit))
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Failed to get IOCs by type {ioc_type}: {e}")
            return []
    
    def record_hit(self, ioc_id: int, source_info: str = "", user_id: str = ""):
        """Record IOC hit for analytics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO ioc_hits (ioc_id, source_info, user_id)
                    VALUES (?, ?, ?)
                ''', (ioc_id, source_info, user_id))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to record IOC hit: {e}")
    
    def get_database_stats(self) -> Dict:
        """Get database statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total IOCs by type
                cursor.execute('''
                    SELECT ioc_type, COUNT(*) as count 
                    FROM iocs 
                    WHERE is_active = 1 
                    GROUP BY ioc_type
                ''')
                ioc_counts = dict(cursor.fetchall())
                
                # Total active IOCs
                cursor.execute('SELECT COUNT(*) FROM iocs WHERE is_active = 1')
                total_active = cursor.fetchone()[0]
                
                # Total hits
                cursor.execute('SELECT COUNT(*) FROM ioc_hits')
                total_hits = cursor.fetchone()[0]
                
                # Recent hits (last 24 hours)
                cursor.execute('''
                    SELECT COUNT(*) FROM ioc_hits 
                    WHERE hit_timestamp > datetime('now', '-1 day')
                ''')
                recent_hits = cursor.fetchone()[0]
                
                return {
                    'total_active_iocs': total_active,
                    'ioc_counts_by_type': ioc_counts,
                    'total_hits': total_hits,
                    'recent_hits_24h': recent_hits,
                    'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                }
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}
    
    def mark_false_positive(self, ioc_value: str) -> bool:
        """Mark IOC as false positive"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE iocs 
                    SET false_positive = 1 
                    WHERE ioc_value = ?
                ''', (ioc_value.lower(),))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to mark false positive {ioc_value}: {e}")
            return False
    
    def deactivate_ioc(self, ioc_value: str) -> bool:
        """Deactivate IOC"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE iocs 
                    SET is_active = 0 
                    WHERE ioc_value = ?
                ''', (ioc_value.lower(),))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to deactivate IOC {ioc_value}: {e}")
            return False
    
    def cleanup_old_hits(self, days: int = 30):
        """Clean up old hit records"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    DELETE FROM ioc_hits 
                    WHERE hit_timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                logger.info(f"Cleaned up {deleted_count} old hit records")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Failed to cleanup old hits: {e}")
            return 0
    
    def export_iocs(self, filename: str, ioc_type: str = None) -> bool:
        """Export IOCs to CSV file"""
        try:
            import csv
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if ioc_type:
                    cursor.execute('''
                        SELECT * FROM iocs 
                        WHERE ioc_type = ? AND is_active = 1
                        ORDER BY added_date DESC
                    ''', (ioc_type.lower(),))
                else:
                    cursor.execute('''
                        SELECT * FROM iocs 
                        WHERE is_active = 1
                        ORDER BY ioc_type, added_date DESC
                    ''')
                
                results = cursor.fetchall()
                
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    if results:
                        fieldnames = results[0].keys()
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        
                        for row in results:
                            writer.writerow(dict(row))
                
                logger.info(f"Exported {len(results)} IOCs to {filename}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to export IOCs: {e}")
            return False
