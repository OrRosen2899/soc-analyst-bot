#!/usr/bin/env python3
"""
IOC Import Utility
Usage: python import_iocs.py <file_path> [source_name]
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from soc_agent import SOCAgent

def main():
    if len(sys.argv) < 2:
        print("Usage: python import_iocs.py <file_path> [source_name]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    source_name = sys.argv[2] if len(sys.argv) > 2 else "manual_import"
    
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(1)
    
    agent = SOCAgent()
    count = agent.load_iocs_from_file(file_path, source_name)
    print(f"✅ Imported {count} IOCs from {file_path}")

if __name__ == "__main__":
    main()
