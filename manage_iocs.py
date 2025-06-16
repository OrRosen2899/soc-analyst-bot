#!/usr/bin/env python3

import argparse
import logging
import os
import shutil
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import csv
from ioc_database import IOCDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class IOCManager:
    def __init__(self, db_path: str = "data/ioc_database.db"):
        """Initialize IOC manager"""
        self.db = IOCDatabase(db_path)
        self.db_path = db_path
        self.backup_dir = "backups"
        
        # Create backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def backup_database(self) -> str:
        """Create database backup"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = f"{self.backup_dir}/ioc_backup_{timestamp}.db"
        
        try:
            shutil.copy2(self.db_path, backup_file)
            logger.info(f"Database backed up to {backup_file}")
            return backup_file
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            raise
    
    def restore_database(self, backup_file: str) -> bool:
        """Restore database from backup"""
        try:
            if not os.path.exists(backup_file):
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            # Create backup of current database
            current_backup = self.backup_database()
            logger.info(f"Current database backed up to {current_backup}")
            
            # Restore from backup
            shutil.copy2(backup_file, self.db_path)
            logger.info(f"Database restored from {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    def cleanup_old_backups(self, days: int = 30) -> int:
        """Remove old backup files"""
        deleted_count = 0
        cutoff_date = datetime.now() - timedelta(days=days)
        
        try:
            for filename in os.listdir(self.backup_dir):
                if filename.startswith('ioc_backup_') and filename.endswith('.db'):
                    file_path = os.path.join(self.backup_dir, filename)
                    file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_mtime < cutoff_date:
                        os.remove(file_path)
                        deleted_count += 1
                        logger.info(f"Deleted old backup: {filename}")
            
            logger.info(f"Cleaned up {deleted_count} old backup files")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 0
    
    def search_iocs(self, pattern: str, ioc_type: str = None, limit: int = 50) -> List[Dict]:
        """Search IOCs with pattern"""
        try:
            if '*' in pattern or '%' in pattern:
                # Wildcard search
                search_pattern = pattern.replace('*', '%')
                results = self.db.search_iocs_wildcard(search_pattern, ioc_type)
            else:
                # Exact search
                result = self.db.search_ioc(pattern, ioc_type)
                results = [result] if result else []
            
            return results[:limit]
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return []
    
    def export_iocs(self, filename: str, ioc_type: str = None, format: str = 'csv') -> bool:
        """Export IOCs to file"""
        try:
            if format.lower() == 'csv':
                return self.db.export_iocs(filename, ioc_type)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
                
        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False
    
    def delete_ioc(self, ioc_value: str) -> bool:
        """Delete IOC from database"""
        try:
            return self.db.deactivate_ioc(ioc_value)
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return False
    
    def mark_false_positive(self, ioc_value: str) -> bool:
        """Mark IOC as false positive"""
        try:
            return self.db.mark_false_positive(ioc_value)
        except Exception as e:
            logger.error(f"Mark false positive failed: {e}")
            return False
    
    def get_top_hits(self, limit: int = 10) -> List[Dict]:
        """Get IOCs with most hits"""
        try:
            import sqlite3
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT i.*, COUNT(h.id) as hit_count
                    FROM iocs i
                    LEFT JOIN ioc_hits h ON i.id = h.ioc_id
                    WHERE i.is_active = 1
                    GROUP BY i.id
                    ORDER BY hit_count DESC
                    LIMIT ?
                ''', (limit,))
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Failed to get top hits: {e}")
            return []
    
    def get_recent_iocs(self, days: int = 7, limit: int = 50) -> List[Dict]:
        """Get recently added IOCs"""
        try:
            import sqlite3
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM iocs
                    WHERE is_active = 1 
                    AND added_date > datetime('now', '-{} days')
                    ORDER BY added_date DESC
                    LIMIT ?
                '''.format(days), (limit,))
                
                results = cursor.fetchall()
                return [dict(row) for row in results]
                
        except Exception as e:
            logger.error(f"Failed to get recent IOCs: {e}")
            return []
    
    def validate_database(self) -> Dict:
        """Validate database integrity"""
        issues = []
        stats = {'total_iocs': 0, 'valid_iocs': 0, 'invalid_iocs': 0, 'issues': []}
        
        try:
            import sqlite3
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get all IOCs
                cursor.execute('SELECT * FROM iocs WHERE is_active = 1')
                iocs = cursor.fetchall()
                
                stats['total_iocs'] = len(iocs)
                
                for ioc in iocs:
                    ioc_dict = dict(ioc)
                    is_valid = True
                    
                    # Check for empty IOC value
                    if not ioc_dict.get('ioc_value'):
                        issues.append(f"IOC ID {ioc_dict['id']}: Empty IOC value")
                        is_valid = False
                    
                    # Check IOC type
                    if not ioc_dict.get('ioc_type'):
                        issues.append(f"IOC ID {ioc_dict['id']}: Missing IOC type")
                        is_valid = False
                    
                    # Check confidence range
                    confidence = ioc_dict.get('confidence', 0)
                    if not isinstance(confidence, int) or not 0 <= confidence <= 100:
                        issues.append(f"IOC ID {ioc_dict['id']}: Invalid confidence value: {confidence}")
                        is_valid = False
                    
                    # Check severity
                    severity = ioc_dict.get('severity', '')
                    if severity not in ['low', 'medium', 'high', 'critical']:
                        issues.append(f"IOC ID {ioc_dict['id']}: Invalid severity: {severity}")
                        is_valid = False
                    
                    if is_valid:
                        stats['valid_iocs'] += 1
                    else:
                        stats['invalid_iocs'] += 1
                
                stats['issues'] = issues
                
        except Exception as e:
            logger.error(f"Database validation failed: {e}")
            stats['error'] = str(e)
        
        return stats
    
    def optimize_database(self) -> bool:
        """Optimize database performance"""
        try:
            import sqlite3
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Analyze tables
                cursor.execute('ANALYZE')
                
                # Vacuum database
                cursor.execute('VACUUM')
                
                conn.commit()
                
            logger.info("Database optimized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")
            return False
    
    def interactive_menu(self):
        """Interactive management menu"""
        while True:
            print("\n🗄️ IOC Database Management")
            print("=" * 30)
            print("1. 📊 Database Statistics")
            print("2. 🔍 Search IOCs")
            print("3. 📥 Export IOCs")
            print("4. 🗑️  Delete IOC")
            print("5. ❌ Mark False Positive")
            print("6. 💾 Backup Database")
            print("7. 🔄 Restore Database")
            print("8. 🧹 Cleanup Old Backups")
            print("9. 🔍 Top Hit IOCs")
            print("10. 📅 Recent IOCs")
            print("11. ✅ Validate Database")
            print("12. ⚡ Optimize Database")
            print("0. 🚪 Exit")
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '0':
                break
            elif choice == '1':
                self.show_stats()
            elif choice == '2':
                self.interactive_search()
            elif choice == '3':
                self.interactive_export()
            elif choice == '4':
                self.interactive_delete()
            elif choice == '5':
                self.interactive_mark_fp()
            elif choice == '6':
                backup_file = self.backup_database()
                print(f"✅ Database backed up to: {backup_file}")
            elif choice == '7':
                self.interactive_restore()
            elif choice == '8':
                days = int(input("Delete backups older than days (30): ") or "30")
                deleted = self.cleanup_old_backups(days)
                print(f"✅ Deleted {deleted} old backup files")
            elif choice == '9':
                self.show_top_hits()
            elif choice == '10':
                self.show_recent_iocs()
            elif choice == '11':
                self.validate_and_show()
            elif choice == '12':
                if self.optimize_database():
                    print("✅ Database optimized successfully")
                else:
                    print("❌ Database optimization failed")
            else:
                print("❌ Invalid option")
    
    def show_stats(self):
        """Show database statistics"""
        stats = self.db.get_database_stats()
        
        print(f"\n📊 IOC Database Statistics")
        print("=" * 30)
        print(f"Total active IOCs: {stats.get('total_active_iocs', 0):,}")
        print(f"Total hits: {stats.get('total_hits', 0):,}")
        print(f"Recent hits (24h): {stats.get('recent_hits_24h', 0):,}")
        print(f"Database size: {stats.get('database_size', 0) / 1024:.1f} KB")
        
        print(f"\nIOCs by type:")
        for ioc_type, count in stats.get('ioc_counts_by_type', {}).items():
            print(f"  {ioc_type.upper()}: {count:,}")
    
    def interactive_search(self):
        """Interactive IOC search"""
        pattern = input("Enter search pattern (* for wildcard): ").strip()
        ioc_type = input("Enter IOC type (optional): ").strip() or None
        
        results = self.search_iocs(pattern, ioc_type)
        
        if results:
            print(f"\n🔍 Found {len(results)} IOCs:")
            for ioc in results[:10]:  # Show first 10
                print(f"  {ioc['ioc_value']} ({ioc['ioc_type']}) - {ioc.get('threat_type', 'Unknown')}")
            
            if len(results) > 10:
                print(f"  ... and {len(results) - 10} more")
        else:
            print("❌ No IOCs found")
    
    def interactive_export(self):
        """Interactive IOC export"""
        filename = input("Enter output filename: ").strip()
        ioc_type = input("Enter IOC type to export (optional): ").strip() or None
        
        if self.export_iocs(filename, ioc_type):
            print(f"✅ IOCs exported to {filename}")
        else:
            print("❌ Export failed")
    
    def interactive_delete(self):
        """Interactive IOC deletion"""
        ioc_value = input("Enter IOC value to delete: ").strip()
        
        if self.delete_ioc(ioc_value):
            print(f"✅ IOC '{ioc_value}' deactivated")
        else:
            print("❌ Delete failed")
    
    def interactive_mark_fp(self):
        """Interactive false positive marking"""
        ioc_value = input("Enter IOC value to mark as false positive: ").strip()
        
        if self.mark_false_positive(ioc_value):
            print(f"✅ IOC '{ioc_value}' marked as false positive")
        else:
            print("❌ Mark false positive failed")
    
    def interactive_restore(self):
        """Interactive database restore"""
        print("\n💾 Available backups:")
        
        backups = []
        for filename in sorted(os.listdir(self.backup_dir)):
            if filename.startswith('ioc_backup_') and filename.endswith('.db'):
                file_path = os.path.join(self.backup_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                backups.append((filename, file_time))
                print(f"  {len(backups)}. {filename} ({file_time.strftime('%Y-%m-%d %H:%M:%S')})")
        
        if not backups:
            print("❌ No backups found")
            return
        
        try:
            choice = int(input("\nSelect backup to restore (0 to cancel): "))
            
            if choice == 0:
                return
            elif 1 <= choice <= len(backups):
                backup_file = os.path.join(self.backup_dir, backups[choice - 1][0])
                
                confirm = input(f"⚠️  Restore from {backups[choice - 1][0]}? (y/N): ")
                if confirm.lower() == 'y':
                    if self.restore_database(backup_file):
                        print("✅ Database restored successfully")
                    else:
                        print("❌ Restore failed")
                else:
                    print("❌ Restore cancelled")
            else:
                print("❌ Invalid selection")
                
        except ValueError:
            print("❌ Invalid input")
    
    def show_top_hits(self):
        """Show IOCs with most hits"""
        top_hits = self.get_top_hits()
        
        print(f"\n🔥 Top Hit IOCs:")
        print("=" * 50)
        
        for ioc in top_hits:
            print(f"🎯 {ioc['ioc_value']} ({ioc['ioc_type']})")
            print(f"   Hits: {ioc['hit_count']}")
            print(f"   Threat: {ioc.get('threat_type', 'Unknown')}")
            print(f"   Severity: {ioc.get('severity', 'Unknown')}")
            print()
    
    def show_recent_iocs(self):
        """Show recently added IOCs"""
        days = int(input("Show IOCs from last days (7): ") or "7")
        recent = self.get_recent_iocs(days)
        
        print(f"\n📅 Recent IOCs (last {days} days):")
        print("=" * 40)
        
        for ioc in recent:
            print(f"📌 {ioc['ioc_value']} ({ioc['ioc_type']})")
            print(f"   Added: {ioc['added_date']}")
            print(f"   Threat: {ioc.get('threat_type', 'Unknown')}")
            print()
    
    def validate_and_show(self):
        """Validate database and show results"""
        print("🔍 Validating database...")
        
        validation = self.validate_database()
        
        print(f"\n✅ Validation Results:")
        print(f"Total IOCs: {validation['total_iocs']}")
        print(f"Valid IOCs: {validation['valid_iocs']}")
        print(f"Invalid IOCs: {validation['invalid_iocs']}")
        
        if validation['issues']:
            print(f"\n⚠️  Issues found:")
            for issue in validation['issues'][:10]:  # Show first 10
                print(f"  - {issue}")
            
            if len(validation['issues']) > 10:
                print(f"  ... and {len(validation['issues']) - 10} more issues")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='IOC Database Management Tool')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--stats', '-s', action='store_true', help='Show database statistics')
    parser.add_argument('--backup', '-b', action='store_true', help='Create database backup')
    parser.add_argument('--restore', '-r', help='Restore from backup file')
    parser.add_argument('--export', '-e', help='Export IOCs to CSV file')
    parser.add_argument('--search', help='Search IOCs')
    parser.add_argument('--type', help='IOC type filter')
    parser.add_argument('--delete', help='Delete IOC')
    parser.add_argument('--mark-fp', help='Mark IOC as false positive')
    parser.add_argument('--validate', action='store_true', help='Validate database')
    parser.add_argument('--optimize', action='store_true', help='Optimize database')
    parser.add_argument('--cleanup', type=int, help='Cleanup backups older than N days')
    parser.add_argument('--db-path', default='data/ioc_database.db', help='Database path')
    
    args = parser.parse_args()
    
    manager = IOCManager(args.db_path)
    
    if args.interactive:
        manager.interactive_menu()
    elif args.stats:
        manager.show_stats()
    elif args.backup:
        backup_file = manager.backup_database()
        print(f"✅ Database backed up to: {backup_file}")
    elif args.restore:
        if manager.restore_database(args.restore):
            print(f"✅ Database restored from: {args.restore}")
        else:
            print("❌ Restore failed")
    elif args.export:
        if manager.export_iocs(args.export, args.type):
            print(f"✅ IOCs exported to: {args.export}")
        else:
            print("❌ Export failed")
    elif args.search:
        results = manager.search_iocs(args.search, args.type)
        if results:
            print(f"Found {len(results)} IOCs:")
            for ioc in results:
                print(f"  {ioc['ioc_value']} ({ioc['ioc_type']})")
        else:
            print("No IOCs found")
    elif args.delete:
        if manager.delete_ioc(args.delete):
            print(f"✅ IOC '{args.delete}' deleted")
        else:
            print("❌ Delete failed")
    elif args.mark_fp:
        if manager.mark_false_positive(args.mark_fp):
            print(f"✅ IOC '{args.mark_fp}' marked as false positive")
        else:
            print("❌ Mark false positive failed")
    elif args.validate:
        validation = manager.validate_database()
        print(f"Validation: {validation['valid_iocs']}/{validation['total_iocs']} IOCs valid")
        if validation['issues']:
            print(f"Issues: {len(validation['issues'])}")
    elif args.optimize:
        if manager.optimize_database():
            print("✅ Database optimized")
        else:
            print("❌ Optimization failed")
    elif args.cleanup is not None:
        deleted = manager.cleanup_old_backups(args.cleanup)
        print(f"✅ Deleted {deleted} old backup files")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
