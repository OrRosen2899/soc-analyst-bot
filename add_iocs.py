#!/usr/bin/env python3

import csv
import os
import sys
import argparse
import logging
from datetime import datetime
from typing import List, Dict
import pandas as pd
from ioc_database import IOCDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class IOCImporter:
    def __init__(self, db_path: str = "data/ioc_database.db"):
        """Initialize IOC importer"""
        self.db = IOCDatabase(db_path)
        
        # Supported IOC types
        self.supported_types = [
            'hash', 'md5', 'sha1', 'sha256',
            'ip', 'ipv4', 'ipv6',
            'domain', 'url', 'email',
            'filename', 'registry', 'mutex',
            'yara', 'certificate', 'imphash'
        ]
        
        # Default field mappings for CSV
        self.field_mappings = {
            'ioc_value': ['ioc', 'indicator', 'value', 'ioc_value', 'hash', 'ip', 'domain', 'url'],
            'ioc_type': ['type', 'ioc_type', 'indicator_type', 'category'],
            'threat_type': ['threat', 'threat_type', 'malware_type', 'threat_category'],
            'malware_family': ['malware', 'malware_family', 'family', 'malware_name', 'signature'],
            'source': ['source', 'feed', 'provider', 'origin', 'reporter'],
            'description': ['description', 'desc', 'comment', 'notes'],
            'confidence': ['confidence', 'score', 'reliability', 'vtpercent'],
            'severity': ['severity', 'priority', 'risk', 'level'],
            'first_seen': ['first_seen', 'first_date', 'discovered', 'first_seen_utc'],
            'last_seen': ['last_seen', 'last_date', 'updated'],
            'tags': ['tags', 'labels', 'classification'],
            'reference_url': ['reference', 'ref_url', 'url_ref', 'link']
        }
        
        # Special mappings for malware analysis CSV format
        self.malware_csv_mappings = {
            'sha256_hash': 'sha256_hash',
            'md5_hash': 'md5_hash',
            'sha1_hash': 'sha1_hash',
            'file_name': 'file_name',
            'signature': 'signature',
            'reporter': 'reporter',
            'first_seen_utc': 'first_seen_utc',
            'vtpercent': 'vtpercent',
            'file_type_guess': 'file_type_guess',
            'mime_type': 'mime_type',
            'clamav': 'clamav',
            'imphash': 'imphash'
        }
    
    def detect_csv_format(self, file_path: str) -> Dict:
        """Auto-detect CSV format and field mappings"""
        try:
            # Read first few rows to detect format
            df = pd.read_csv(file_path, nrows=5)
            columns = [col.lower().strip() for col in df.columns]
            
            logger.info(f"Detected CSV columns: {columns}")
            
            # Check if this is the special malware analysis format
            malware_indicators = ['sha256_hash', 'md5_hash', 'sha1_hash', 'signature', 'vtpercent']
            is_malware_format = sum(1 for indicator in malware_indicators if indicator in columns) >= 3
            
            if is_malware_format:
                logger.info("Detected malware analysis CSV format")
                return self.detect_malware_csv_format(file_path, columns)
            else:
                return self.detect_standard_csv_format(file_path, columns)
                
        except Exception as e:
            logger.error(f"Failed to detect CSV format: {e}")
            return {}
    
    def detect_malware_csv_format(self, file_path: str, columns: List[str]) -> Dict:
        """Detect malware analysis CSV format"""
        detected_mappings = {}
        
        # Map malware CSV specific fields
        for field, csv_field in self.malware_csv_mappings.items():
            if csv_field in columns:
                detected_mappings[field] = csv_field
        
        return {
            'format_type': 'malware_analysis',
            'columns': columns,
            'mappings': detected_mappings,
            'total_rows': len(pd.read_csv(file_path)),
            'multi_hash': True  # This format has multiple hash types per row
        }
    
    def detect_standard_csv_format(self, file_path: str, columns: List[str]) -> Dict:
        """Detect standard IOC CSV format"""
        detected_mappings = {}
        
        # Find field mappings
        for field, possible_names in self.field_mappings.items():
            for col in columns:
                if col in [name.lower() for name in possible_names]:
                    detected_mappings[field] = col
                    break
        
        return {
            'format_type': 'standard',
            'columns': columns,
            'mappings': detected_mappings,
            'total_rows': len(pd.read_csv(file_path)),
            'multi_hash': False
        }
    
    def import_malware_csv(self, file_path: str, mappings: Dict) -> Dict:
        """Import malware analysis CSV format with multiple hashes per row"""
        try:
            df = pd.read_csv(file_path)
            df.columns = [col.strip() for col in df.columns]
            
            all_iocs = []
            processed_rows = 0
            skipped_rows = 0
            
            logger.info(f"Processing {len(df)} rows from malware CSV")
            
            for index, row in df.iterrows():
                try:
                    # Convert row to dict
                    row_data = {}
                    for col in df.columns:
                        if pd.notna(row[col]):
                            row_data[col] = str(row[col]).strip()
                    
                    # Extract multiple IOCs from this row
                    row_iocs = self.extract_malware_iocs(row_data, mappings)
                    
                    if row_iocs:
                        all_iocs.extend(row_iocs)
                        processed_rows += 1
                    else:
                        skipped_rows += 1
                    
                except Exception as e:
                    logger.error(f"Error processing row {index + 2}: {e}")
                    skipped_rows += 1
                    continue
            
            # Import to database
            if all_iocs:
                added_count, failed_count = self.db.add_iocs_batch(all_iocs)
                
                return {
                    'success': True,
                    'total_rows': len(df),
                    'processed_rows': processed_rows,
                    'skipped_rows': skipped_rows,
                    'total_iocs': len(all_iocs),
                    'added': added_count,
                    'failed': failed_count
                }
            else:
                return {'success': False, 'error': 'No valid IOCs found in file'}
                
        except Exception as e:
            logger.error(f"Failed to import malware CSV: {e}")
            return {'success': False, 'error': str(e)}
    
    def extract_malware_iocs(self, row_data: Dict, mappings: Dict) -> List[Dict]:
        """Extract multiple IOCs from malware analysis row"""
        iocs = []
        
        # Convert VT percentage to confidence and severity
        vt_percent = row_data.get('vtpercent', '0')
        confidence = self.convert_vt_percent_to_confidence(vt_percent)
        severity = self.determine_severity_from_vt_percent(vt_percent)
        
        # Base IOC information
        base_info = {
            'threat_type': 'malware',
            'malware_family': row_data.get('signature', 'unknown'),
            'source': row_data.get('reporter', 'unknown'),
            'confidence': confidence,
            'severity': severity,
            'first_seen': row_data.get('first_seen_utc', ''),
            'description': self.create_malware_description(row_data)
        }
        
        # Extract SHA256
        if row_data.get('sha256_hash') and row_data['sha256_hash'] != 'None':
            sha256_ioc = base_info.copy()
            sha256_ioc.update({
                'ioc_value': row_data['sha256_hash'].lower(),
                'ioc_type': 'sha256'
            })
            iocs.append(sha256_ioc)
        
        # Extract MD5
        if row_data.get('md5_hash') and row_data['md5_hash'] != 'None':
            md5_ioc = base_info.copy()
            md5_ioc.update({
                'ioc_value': row_data['md5_hash'].lower(),
                'ioc_type': 'md5'
            })
            iocs.append(md5_ioc)
        
        # Extract SHA1
        if row_data.get('sha1_hash') and row_data['sha1_hash'] != 'None':
            sha1_ioc = base_info.copy()
            sha1_ioc.update({
                'ioc_value': row_data['sha1_hash'].lower(),
                'ioc_type': 'sha1'
            })
            iocs.append(sha1_ioc)
        
        # Extract filename
        if row_data.get('file_name') and row_data['file_name'] != 'None':
            filename_ioc = base_info.copy()
            filename_ioc.update({
                'ioc_value': row_data['file_name'],
                'ioc_type': 'filename'
            })
            iocs.append(filename_ioc)
        
        # Extract IMPHASH
        if row_data.get('imphash') and row_data['imphash'] != 'None':
            imphash_ioc = base_info.copy()
            imphash_ioc.update({
                'ioc_value': row_data['imphash'].lower(),
                'ioc_type': 'imphash'
            })
            iocs.append(imphash_ioc)
        
        return iocs
    
    def convert_vt_percent_to_confidence(self, vt_percent: str) -> int:
        """Convert VirusTotal percentage to confidence score"""
        try:
            if not vt_percent or vt_percent == 'None':
                return 50
            
            vt_percent = str(vt_percent).replace('%', '').strip()
            if vt_percent == '0':
                return 30
            
            percent = float(vt_percent)
            if percent >= 75:
                return 95
            elif percent >= 50:
                return 85
            elif percent >= 25:
                return 70
            else:
                return 50
        except:
            return 50
    
    def determine_severity_from_vt_percent(self, vt_percent: str) -> str:
        """Determine severity from VirusTotal percentage"""
        try:
            if not vt_percent or vt_percent == 'None':
                return 'medium'
            
            vt_percent = str(vt_percent).replace('%', '').strip()
            if vt_percent == '0':
                return 'low'
            
            percent = float(vt_percent)
            if percent >= 75:
                return 'critical'
            elif percent >= 50:
                return 'high'
            elif percent >= 25:
                return 'medium'
            else:
                return 'low'
        except:
            return 'medium'
    
    def create_malware_description(self, row_data: Dict) -> str:
        """Create description for malware IOC"""
        parts = []
        
        if row_data.get('signature'):
            parts.append(f"Signature: {row_data['signature']}")
        
        if row_data.get('file_type_guess'):
            parts.append(f"Type: {row_data['file_type_guess']}")
        
        if row_data.get('vtpercent'):
            parts.append(f"VT: {row_data['vtpercent']}%")
        
        if row_data.get('clamav') and row_data['clamav'] != 'None':
            parts.append(f"ClamAV: {row_data['clamav']}")
        
        return "; ".join(parts) if parts else "Malware sample"
    
    def import_from_csv(self, file_path: str, custom_mappings: Dict = None) -> Dict:
        """Import IOCs from CSV file with auto-detection"""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {'success': False, 'error': 'File not found'}
        
        try:
            # Detect format
            format_info = self.detect_csv_format(file_path)
            if not format_info:
                return {'success': False, 'error': 'Failed to detect CSV format'}
            
            # Use custom mappings if provided
            mappings = custom_mappings or format_info['mappings']
            
            # Handle different format types
            if format_info.get('format_type') == 'malware_analysis':
                logger.info("Using malware analysis import method")
                return self.import_malware_csv(file_path, mappings)
            else:
                logger.info("Using standard import method")
                return self.import_standard_csv(file_path, mappings)
                
        except Exception as e:
            logger.error(f"Failed to import CSV: {e}")
            return {'success': False, 'error': str(e)}
    
    def import_standard_csv(self, file_path: str, mappings: Dict) -> Dict:
        """Import standard IOC CSV format"""
        try:
            # Read CSV
            df = pd.read_csv(file_path)
            df.columns = [col.lower().strip() for col in df.columns]
            
            imported_iocs = []
            skipped_count = 0
            error_count = 0
            
            logger.info(f"Processing {len(df)} rows from {file_path}")
            
            for index, row in df.iterrows():
                try:
                    # Map fields
                    ioc_data = {}
                    
                    for field, csv_column in mappings.items():
                        if csv_column in df.columns:
                            value = row[csv_column]
                            if pd.notna(value):
                                ioc_data[field] = str(value).strip()
                    
                    # Skip if no IOC value
                    if not ioc_data.get('ioc_value'):
                        skipped_count += 1
                        continue
                    
                    # Validate IOC
                    is_valid, validation_msg = self.validate_ioc(ioc_data)
                    
                    if not is_valid:
                        logger.warning(f"Row {index + 2}: {validation_msg}")
                        error_count += 1
                        continue
                    
                    imported_iocs.append(ioc_data)
                    
                except Exception as e:
                    logger.error(f"Error processing row {index + 2}: {e}")
                    error_count += 1
                    continue
            
            # Import to database
            if imported_iocs:
                added_count, failed_count = self.db.add_iocs_batch(imported_iocs)
                
                result = {
                    'success': True,
                    'total_rows': len(df),
                    'processed': len(imported_iocs),
                    'added': added_count,
                    'failed': failed_count,
                    'skipped': skipped_count,
                    'errors': error_count
                }
                
                logger.info(f"Import completed: {added_count} added, {failed_count} failed, {skipped_count} skipped")
                return result
            else:
                return {'success': False, 'error': 'No valid IOCs found in file'}
                
        except Exception as e:
            logger.error(f"Failed to import CSV: {e}")
            return {'success': False, 'error': str(e)}
    
    def validate_ioc(self, ioc_data: Dict) -> tuple[bool, str]:
        """Validate IOC data"""
        
        # Required fields
        if not ioc_data.get('ioc_value'):
            return False, "Missing IOC value"
        
        # Normalize IOC type
        ioc_type = str(ioc_data.get('ioc_type', '')).lower()
        
        # Auto-detect type if not provided
        if not ioc_type:
            ioc_value = str(ioc_data['ioc_value']).strip()
            ioc_type = self.auto_detect_type(ioc_value)
            ioc_data['ioc_type'] = ioc_type
        
        # Validate IOC type
        if ioc_type not in self.supported_types:
            return False, f"Unsupported IOC type: {ioc_type}"
        
        # Validate confidence (0-100)
        try:
            confidence = int(ioc_data.get('confidence', 50))
            if not 0 <= confidence <= 100:
                ioc_data['confidence'] = 50
        except:
            ioc_data['confidence'] = 50
        
        # Validate severity
        valid_severities = ['low', 'medium', 'high', 'critical']
        severity = str(ioc_data.get('severity', 'medium')).lower()
        if severity not in valid_severities:
            ioc_data['severity'] = 'medium'
        
        return True, "Valid"
    
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
        
        # Filename pattern
        elif '.' in ioc_value and any(ioc_value.endswith(ext) for ext in ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js']):
            return 'filename'
        
        # Default to generic
        return 'hash'
    
    def interactive_import(self):
        """Interactive IOC import with user guidance"""
        print("\n🛡️ IOC Database Import Tool")
        print("=" * 40)
        
        # Get file path
        while True:
            file_path = input("\nEnter CSV file path: ").strip()
            if os.path.exists(file_path):
                break
            print("❌ File not found. Please try again.")
        
        # Detect format
        print("\n🔍 Analyzing CSV format...")
        format_info = self.detect_csv_format(file_path)
        
        if not format_info:
            print("❌ Failed to analyze CSV format")
            return
        
        print(f"📊 Found {format_info['total_rows']} rows")
        print(f"📋 Format detected: {format_info.get('format_type', 'standard')}")
        print(f"📄 Columns: {', '.join(format_info['columns'])}")
        
        # Show detected mappings
        if format_info.get('format_type') == 'malware_analysis':
            print("\n🎯 Malware analysis format detected!")
            print("   Will extract multiple IOCs per row (hashes + filenames)")
            
            mappings = format_info['mappings']
            for field, csv_col in mappings.items():
                print(f"  {field}: {csv_col}")
        else:
            print("\n🎯 Detected field mappings:")
            mappings = format_info['mappings']
            
            for field, csv_col in mappings.items():
                print(f"  {field}: {csv_col}")
        
        # Ask for confirmation
        confirm = input(f"\n📥 Import {format_info['total_rows']} rows? (y/N): ").lower().strip()
        
        if confirm != 'y':
            print("❌ Import cancelled")
            return
        
        # Import
        print("\n📥 Importing IOCs...")
        result = self.import_from_csv(file_path)
        
        # Show results
        if result['success']:
            print("\n✅ Import completed successfully!")
            print(f"📊 Results:")
            print(f"  Total rows: {result['total_rows']}")
            
            if 'total_iocs' in result:  # Malware format
                print(f"  Total IOCs extracted: {result['total_iocs']}")
                print(f"  Processed rows: {result['processed_rows']}")
                print(f"  Skipped rows: {result['skipped_rows']}")
            else:  # Standard format
                print(f"  Processed: {result['processed']}")
                print(f"  Skipped: {result['skipped']}")
                print(f"  Errors: {result['errors']}")
            
            print(f"  Added to database: {result['added']}")
            print(f"  Failed to add: {result['failed']}")
        else:
            print(f"\n❌ Import failed: {result['error']}")
    
    def show_database_stats(self):
        """Show current database statistics"""
        stats = self.db.get_database_stats()
        
        print("\n📊 IOC Database Statistics")
        print("=" * 30)
        print(f"Total active IOCs: {stats.get('total_active_iocs', 0)}")
        print(f"Total hits: {stats.get('total_hits', 0)}")
        print(f"Recent hits (24h): {stats.get('recent_hits_24h', 0)}")
        print(f"Database size: {stats.get('database_size', 0) / 1024:.1f} KB")
        
        print("\nIOCs by type:")
        for ioc_type, count in stats.get('ioc_counts_by_type', {}).items():
            print(f"  {ioc_type}: {count}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='IOC Database Import Tool')
    parser.add_argument('--file', '-f', help='CSV file to import')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--stats', '-s', action='store_true', help='Show database statistics')
    parser.add_argument('--db-path', default='data/ioc_database.db', help='Database path')
    
    args = parser.parse_args()
    
    importer = IOCImporter(args.db_path)
    
    if args.stats:
        importer.show_database_stats()
    elif args.interactive or not args.file:
        importer.interactive_import()
    elif args.file:
        result = importer.import_from_csv(args.file)
        if result['success']:
            if 'total_iocs' in result:
                print(f"✅ Successfully imported {result['added']} IOCs from {result['total_iocs']} extracted")
            else:
                print(f"✅ Successfully imported {result['added']} IOCs")
        else:
            print(f"❌ Import failed: {result['error']}")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
