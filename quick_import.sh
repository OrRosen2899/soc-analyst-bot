#!/bin/bash

# Quick Import Script for Custom Malware CSV Format
# Usage: ./quick_import.sh your_malware_file.csv

echo "🛡️ Quick IOC Import for Malware CSV"
echo "=================================="

# Check if file argument provided
if [ $# -eq 0 ]; then
    echo "❌ Usage: $0 <csv_file>"
    echo ""
    echo "Expected CSV format with headers:"
    echo "first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,"
    echo "file_name, file_type_guess, mime_type, signature, clamav,"
    echo "vtpercent, imphash, ssdeep, tlsh"
    echo ""
    echo "Examples:"
    echo "  $0 malware_samples.csv"
    echo "  $0 ioc_imports/new_threats.csv"
    exit 1
fi

CSV_FILE="$1"

# Check if file exists
if [ ! -f "$CSV_FILE" ]; then
    echo "❌ File not found: $CSV_FILE"
    exit 1
fi

# Get file info
FILE_SIZE=$(du -h "$CSV_FILE" | cut -f1)
LINE_COUNT=$(wc -l < "$CSV_FILE")
echo "📄 File: $CSV_FILE"
echo "📊 Size: $FILE_SIZE"
echo "📝 Lines: $LINE_COUNT"

# Validate CSV format quickly
echo ""
echo "🔍 Validating CSV format..."

# Check if file has the expected headers
HEADER_LINE=$(head -n 1 "$CSV_FILE")

# Check for key columns
if [[ $HEADER_LINE == *"sha256_hash"* ]] && [[ $HEADER_LINE == *"md5_hash"* ]] && [[ $HEADER_LINE == *"sha1_hash"* ]]; then
    echo "✅ CSV format looks correct"
else
    echo "⚠️  Warning: Expected headers not found"
    echo "Found headers: $HEADER_LINE"
    echo ""
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Import cancelled"
        exit 1
    fi
fi

# Estimate IOCs that will be extracted
ESTIMATED_ROWS=$((LINE_COUNT - 1))  # Minus header
ESTIMATED_IOCS=$((ESTIMATED_ROWS * 4))  # Assuming avg 4 IOCs per row (3 hashes + filename)

echo ""
echo "📊 Estimated extraction:"
echo "   Rows to process: $ESTIMATED_ROWS"
echo "   IOCs to extract: ~$ESTIMATED_IOCS"
echo ""

# Confirm import
read -p "🚀 Start import? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Import cancelled"
    exit 1
fi

# Run the import
echo ""
echo "📥 Importing IOCs..."
echo "⏳ This may take a while for large files..."
echo ""

START_TIME=$(date +%s)

# Use the custom importer
python3 custom_ioc_import.py --file "$CSV_FILE"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "⏱️  Import completed in ${DURATION} seconds"

# Show database stats
echo ""
echo "📊 Updated database statistics:"
python3 add_iocs.py --stats

echo ""
echo "✅ Quick import finished!"
echo ""
echo "🔧 Management commands:"
echo "   View recent IOCs: python3 manage_iocs.py --interactive"
echo "   Search IOCs: python3 manage_iocs.py --search 'pattern'"
echo "   Database stats: python3 add_iocs.py --stats"
echo "   Test detection: Send a hash to your Telegram bot"
