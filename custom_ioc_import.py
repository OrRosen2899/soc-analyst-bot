#!/usr/bin/env python3

import csv
import os
import sys
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd
from ioc_database import IOCDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CustomMalwareIOCImporter:
    def __init__(self, db_path: str = "data/ioc_database.db"):
        """Initialize custom malware IOC importer for your specific CSV format"""
        self.db = IOCDatabase(db_path)
        
        # Your specific CSV format mapping
        self.csv_format = {
            'first_seen_utc': 'first_seen',
            'sha256_hash': 'sha256_hash',
            'md5_hash': 'md5_hash', 
            'sha1_hash': 'sha1_hash',
            'reporter': 'reporter',
            'file_name': 'file_name',
            'file_type_guess': 'file_type_guess',
            'mime_type': 'mime_type',
            'signature': 'signature',
            'clamav': 'clamav',
            'vtpercent': 'vtpercent',
            'imphash': 'imphash',
            'ssdeep': 'ssdeep',
            'tlsh': 'tlsh'
        }
        
    def convert_vt_percent_to_confidence(self, vt_percent: str) -> int:
        """Convert VirusTotal percentage to confidence score"""
        try:
            if not vt_percent or vt_percent == 'None' or vt_percent == '':
                return 50  # Default confidence
            
            # Remove % sign if present
            vt_percent = str(vt_percent).replace('%', '').strip()
            
            if vt_percent == '0' or vt_percent == '0.0':
                return 30  # Low confidence for clean files
            
            percent = float(vt_percent)
            
            # Convert VT percentage to confidence score
            if percent >= 75:
                return 95  # High confidence
            elif percent >= 50:
                return 85  # Good confidence
            elif percent >= 25:
                return 70  # Medium confidence
            elif percent >= 10:
                return 60  # Low-medium confidence
            else:
                return 40  # Low confidence
                
        except (ValueError, TypeError):
            return 50  # Default if conversion fails
    
    def determine_severity_from_vt_percent(self, vt_percent: str) -> str:
        """Determine severity based on VirusTotal percentage"""
        try:
            if not vt_percent or vt_percent == 'None' or vt_percent == '':
                return 'medium'
            
            vt_percent = str(vt_percent).replace('%', '').strip()
            
            if vt_percent == '0' or vt_percent == '0.0':
                return 'low'  # Clean files
            
            percent = float(vt_percent)
            
            if percent >= 75:
                return 'critical'
            elif percent >= 50:
                return 'high' 
            elif percent >= 25:
                return 'medium'
            else:
                return 'low'
                
        except (ValueError, TypeError):
            return 'medium'
    
    def create_description(self, row_data: Dict) -> str:
        """Create comprehensive description from row data"""
        desc_parts = []
        
        # Add signature info
        if row_data.get('signature'):
            desc_parts.append(f"Signature: {row_data['signature']}")
        
        # Add file type info
        if row_data.get('file_type_guess'):
            desc_parts.append(f"File Type: {row_data['file_type_guess']}")
        
        # Add ClamAV detection
        if row_data.get('clamav') and row_data['clamav'] != 'None':
            desc_parts.append(f"ClamAV: {row_data['clamav']}")
        
        # Add VT percentage
        if row_data.get('vtpercent'):
            desc_parts.append(f"VT Detection: {row_data['vtpercent']}%")
        
        # Add reporter
        if row_data.get('reporter'):
            desc_parts.append(f"Reporter: {row_data['reporter']}")
        
        return "; ".join(desc_parts) if desc_parts else "Malware sample from threat intelligence feed"
    
    def extract_iocs_from_row(self, row_data: Dict) -> List[Dict]:
        """Extract multiple IOCs from a single row (multiple hash types + filename)"""
        iocs = []
        
        # Base information
        base_info = {
            'threat_type': 'malware',
            'malware_family': row_data.get('signature', 'unknown'),
            'source': row_data.get('reporter', 'unknown'),
            'confidence': self.convert_vt_percent_to_confidence(row_data.get('vtpercent')),
            'severity': self.determine_severity_from_vt_percent(row_data.get('vtpercent')),
            'first_seen': row_data.get('first_seen_utc', ''),
            'description': self.create_description(row_data)
        }
        
        # Create tags from available metadata
        tags = ['malware']
        if row_data.get('file_type_guess'):
            tags.append(row_data['file_type_guess'].lower())
        if row_data.get('signature'):
            tags.append(row_data['signature'].lower().replace(' ', '_'))
        
        base_info['tags'] = ','.join(tags)
        
        # Extract SHA256 hash
        if row_data.get('sha256_hash') and row_data['sha256_hash'] != 'None':
            sha256_ioc = base_info.copy()
            sha256_ioc.update({
                'ioc_value': row_data['sha256_hash'].lower(),
                'ioc_type': 'sha256'
            })
            iocs.append(sha256_ioc)
        
        # Extract MD5 hash
        if row_data.get('md5_hash') and row_data['md5_hash'] != 'None':
            md5_ioc = base_info.copy()
            md5_ioc.update({
                'ioc_value': row_data['md5_hash'].lower(),
                'ioc_type': 'md5'
            })
            iocs.append(md5_ioc)
        
        # Extract SHA1 hash
        if row_data.get('sha1_hash') and row_data['sha1_hash'] != 'None':
            sha1_ioc = base_info.copy()
            sha1_ioc.update({
                'ioc_value': row_data['sha1_hash'].lower(),
                'ioc_type': 'sha1'
            })
            iocs.append(sha1_ioc)
        
        # Extract filename as IOC
        if row_data.get('file_name') and row_data['file_name'] != 'None':
            filename_ioc = base_info.copy()
            filename_ioc.update({
                'ioc_value': row_data['file_name'],
                'ioc_type': 'filename',
                'description': f"Malicious filename: {row_data['file_name']}. " + base_info['description']
            })
            iocs.append(filename_ioc)
        
        # Extract IMPHASH if available
        if row_data.get('imphash') and row_data['imphash'] != 'None':
            imphash_ioc = base_info.copy()
            imphash_ioc.update({
                'ioc_value': row_data['imphash'].lower(),
                'ioc_type': 'imphash',
                'description': f"Import hash from malware sample. " + base_info['description']
            })
            iocs.append(imphash_ioc)
        
        return iocs
    
    def import_malware_csv(self, file_path: str) -> Dict:
        """Import your specific malware CSV format"""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {'success': False, 'error': 'File not found'}
        
        try:
            # Read CSV
            df = pd.read_csv(file_path)
            
            # Clean column names (remove spaces, standardize)
            df.columns = [col.strip() for col in df.columns]
            
            logger.info(f"Processing {len(df)} rows from {file_path}")
            logger.info(f"Detected columns: {list(df.columns)}")
            
            all_iocs = []
            processed_rows = 0
            skipped_rows = 0
            
            for index, row in df.iterrows():
                try:
                    # Convert row to dict
                    row_data = {}
                    for col in df.columns:
                        if pd.notna(row[col]):
                            row_data[col] = str(row[col]).strip()
                    
                    # Extract IOCs from this row
                    row_iocs = self.extract_iocs_from_row(row_data)
                    
                    if row_iocs:
                        all_iocs.extend(row_iocs)
                        processed_rows += 1
                    else:
                        skipped_rows += 1
                        logger.warning(f"Row {index + 2}: No valid IOCs found")
                    
                except Exception as e:
                    logger.error(f"Error processing row {index + 2}: {e}")
                    skipped_rows += 1
                    continue
            
            # Import to database
            if all_iocs:
                added_count, failed_count = self.db.add_iocs_batch(all_iocs)
                
                result = {
                    'success': True,
                    'total_rows': len(df),
                    'processed_rows': processed_rows,
                    'skipped_rows': skipped_rows,
                    'total_iocs_extracted': len(all_iocs),
                    'added_to_db': added_count,
                    'failed_to_add': failed_count,
                    'ioc_breakdown': self.get_ioc_breakdown(all_iocs)
                }
                
                logger.info(f"Import completed: {added_count} IOCs added, {failed_count} failed")
                return result
            else:
                return {'success': False, 'error': 'No valid IOCs found in file'}
                
        except Exception as e:
            logger.error(f"Failed to import CSV: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_ioc_breakdown(self, iocs: List[Dict]) -> Dict:
        """Get breakdown of IOC types"""
        breakdown = {}
        for ioc in iocs:
            ioc_type = ioc.get('ioc_type', 'unknown')
            breakdown[ioc_type] = breakdown.get(ioc_type, 0) + 1
        return breakdown
    
    def validate_csv_format(self, file_path: str) -> Dict:
        """Validate if CSV matches expected format"""
        try:
            df = pd.read_csv(file_path, nrows=1)
            columns = [col.strip() for col in df.columns]
            
            # Check for required columns
            required_cols = ['sha256_hash', 'md5_hash', 'sha1_hash']
            missing_cols = [col for col in required_cols if col not in columns]
            
            # Check for recommended columns
            recommended_cols = ['first_seen_utc', 'signature', 'vtpercent', 'reporter']
            missing_recommended = [col for col in recommended_cols if col not in columns]
            
            validation = {
                'valid': len(missing_cols) == 0,
                'columns_found': columns,
                'missing_required': missing_cols,
                'missing_recommended': missing_recommended,
                'total_rows': len(pd.read_csv(file_path))
            }
            
            return validation
            
        except Exception as e:
            return {'valid': False, 'error': str(e)}
    
    def interactive_import(self):
        """Interactive import with validation"""
        print("\n🛡️ Custom Malware IOC Importer")
        print("=" * 40)
        print("Designed for CSV format with columns:")
        print("first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,")
        print("file_name, file_type_guess, mime_type, signature, clamav,")
        print("vtpercent, imphash, ssdeep, tlsh")
        print()
        
        # Get file path
        while True:
            file_path = input("Enter CSV file path: ").strip()
            if os.path.exists(file_path):
                break
            print("❌ File not found. Please try again.")
        
        # Validate format
        print("\n🔍 Validating CSV format...")
        validation = self.validate_csv_format(file_path)
        
        if not validation.get('valid', False):
            if 'error' in validation:
                print(f"❌ Validation error: {validation['error']}")
                return
            else:
                print("⚠️  CSV format issues detected:")
                if validation.get('missing_required'):
                    print(f"   Missing required columns: {', '.join(validation['missing_required'])}")
                if validation.get('missing_recommended'):
                    print(f"   Missing recommended columns: {', '.join(validation['missing_recommended'])}")
                
                proceed = input("\nProceed anyway? (y/N): ").lower().strip()
                if proceed != 'y':
                    print("❌ Import cancelled")
                    return
        
        print(f"✅ Found {validation.get('total_rows', 0)} rows")
        print(f"📋 Columns: {', '.join(validation.get('columns_found', []))}")
        
        # Confirm import
        confirm = input(f"\n📥 Import {validation.get('total_rows', 0)} rows? (y/N): ").lower().strip()
        
        if confirm != 'y':
            print("❌ Import cancelled")
            return
        
        # Import
        print("\n📥 Importing malware IOCs...")
        result = self.import_malware_csv(file_path)
        
        # Show results
        if result['success']:
            print("\n✅ Import completed successfully!")
            print(f"📊 Results:")
            print(f"   Total rows processed: {result['total_rows']}")
            print(f"   Rows with valid IOCs: {result['processed_rows']}")
            print(f"   Rows skipped: {result['skipped_rows']}")
            print(f"   Total IOCs extracted: {result['total_iocs_extracted']}")
            print(f"   IOCs added to database: {result['added_to_db']}")
            print(f"   Failed to add: {result['failed_to_add']}")
            
            print(f"\n📋 IOC Types:")
            for ioc_type, count in result['ioc_breakdown'].items():
                print(f"   {ioc_type.upper()}: {count}")
                
        else:
            print(f"\n❌ Import failed: {result['error']}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Custom Malware IOC Importer')
    parser.add_argument('--file', '-f', help='CSV file to import')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--validate', '-v', help='Validate CSV format without importing')
    parser.add_argument('--db-path', default='data/ioc_database.db', help='Database path')
    
    args = parser.parse_args()
    
    importer = CustomMalwareIOCImporter(args.db_path)
    
    if args.validate:
        validation = importer.validate_csv_format(args.validate)
        if validation.get('valid'):
            print(f"✅ CSV format is valid")
            print(f"   Rows: {validation['total_rows']}")
            print(f"   Columns: {len(validation['columns_found'])}")
        else:
            print(f"❌ CSV format issues:")
            if 'error' in validation:
                print(f"   Error: {validation['error']}")
            else:
                if validation.get('missing_required'):
                    print(f"   Missing required: {', '.join(validation['missing_required'])}")
                    
    elif args.interactive or not args.file:
        importer.interactive_import()
        
    elif args.file:
        result = importer.import_malware_csv(args.file)
        if result['success']:
            print(f"✅ Successfully imported {result['added_to_db']} IOCs from {result['total_iocs_extracted']} extracted")
            print("IOC breakdown:")
            for ioc_type, count in result['ioc_breakdown'].items():
                print(f"  {ioc_type}: {count}")
        else:
            print(f"❌ Import failed: {result['error']}")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
