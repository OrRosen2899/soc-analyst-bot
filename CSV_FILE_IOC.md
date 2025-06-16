# 🗄️ Your Custom CSV Format Integration Guide

## 📋 Your CSV Headers Detected

```
first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, 
file_name, file_type_guess, mime_type, signature, clamav, 
vtpercent, imphash, ssdeep, tlsh
```

Perfect! Your CSV format is **fully supported** with specialized import tools.

## 🚀 Quick Start - Import Your IOCs

### Method 1: Super Quick Import
```bash
# Make the quick import script executable
chmod +x quick_import.sh

# Import your CSV file
./quick_import.sh your_malware_file.csv
```

### Method 2: Custom Importer (Most Features)
```bash
# Interactive import with validation
python3 custom_ioc_import.py --interactive

# Direct import
python3 custom_ioc_import.py --file your_malware_file.csv

# Validate format first
python3 custom_ioc_import.py --validate your_malware_file.csv
```

### Method 3: Standard Importer (Auto-Detects Your Format)
```bash
# Auto-detects your format and imports accordingly
python3 add_iocs.py --interactive

# Direct import with auto-detection
python3 add_iocs.py --file your_malware_file.csv
```

## 🎯 What Gets Extracted from Your CSV

From **each row** in your CSV, the system extracts **multiple IOCs**:

### ✅ Hash IOCs (3 per row)
- **SHA256** → `sha256_hash` column
- **MD5** → `md5_hash` column  
- **SHA1** → `sha1_hash` column

### ✅ Filename IOCs
- **Filename** → `file_name` column (e.g., `malware.exe`)

### ✅ Import Hash IOCs
- **IMPHASH** → `imphash` column (if available)

### 📊 Rich Metadata Automatically Added
- **Threat Type**: `malware` (auto-set)
- **Malware Family**: From `signature` column
- **Source**: From `reporter` column
- **Confidence**: Calculated from `vtpercent` column
- **Severity**: Determined from `vtpercent` column
- **First Seen**: From `first_seen_utc` column
- **Description**: Auto-generated from multiple fields

## 🔢 Smart VT Percentage Conversion

Your `vtpercent` column is automatically converted to:

| VT Percentage | Confidence Score | Severity Level |
|---------------|------------------|----------------|
| 75%+ | 95% | Critical |
| 50-74% | 85% | High |
| 25-49% | 70% | Medium |
| 10-24% | 60% | Low-Medium |
| 0-9% | 40% | Low |
| 0% (Clean) | 30% | Low |

## 📝 Example: What Your CSV Looks Like

Use the provided `malware_sample.csv` as a template:

```csv
first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh
2024-01-15 10:30:00,e3b0c442...,d41d8cd9...,da39a3ee...,sandbox_analysis,malware.exe,executable,application/x-executable,Trojan.Generic,Win.Trojan.Generic-123,85,f1a2b3c4...,768:1A2B...,T12345ABC
```

## 🎯 Import Results Example

From **1 row** in your CSV, you get **4-5 IOCs**:

```
✅ Import completed successfully!
📊 Results:
   Total rows processed: 1
   Total IOCs extracted: 4
   IOCs added to database: 4
   
📋 IOC Types:
   SHA256: 1
   MD5: 1  
   SHA1: 1
   FILENAME: 1
```

## 🛡️ How Detection Works

When someone sends a suspicious file or hash to your bot:

1. **Instant Database Check** - All 3 hashes + filename checked
2. **IOC Match Alert** - If found in your database:
   ```
   🚨 IOC DATABASE MATCH!
   Threat Type: malware
   Malware Family: Trojan.Generic
   Severity: Critical
   Source: sandbox_analysis
   Confidence: 85%
   Description: Signature: Trojan.Generic; Type: executable; VT: 85%
   ```
3. **AI Analysis** - Enhanced with IOC context
4. **VirusTotal** - Additional verification (if configured)

## 🔧 Management Commands

### View Your Imported IOCs
```bash
# Database statistics
python3 add_iocs.py --stats

# Search for specific IOC
python3 manage_iocs.py --search "malware.exe"

# Interactive management
python3 manage_iocs.py --interactive
```

### Export Your IOCs
```bash
# Export all hashes
python3 manage_iocs.py --export my_hashes.csv --type sha256

# Export all malware IOCs
python3 manage_iocs.py --export malware_iocs.csv
```

## 📁 File Organization

```bash
# Put your CSV files here for easy access
mkdir -p ioc_imports
cp your_malware_file.csv ioc_imports/

# Import from the directory
python3 custom_ioc_import.py --file ioc_imports/your_malware_file.csv
```

## 🔄 Automated Imports

### Daily Auto-Import (Optional)
Create a script to automatically import new CSV files:

```bash
# Create auto-import script
cat > auto_import_daily.sh << 'EOF'
#!/bin/bash
cd ~/soc-analyst-bot

# Import all new CSV files
for file in ioc_imports/new_*.csv; do
    if [ -f "$file" ]; then
        echo "Importing $file..."
        python3 custom_ioc_import.py --file "$file"
        
        # Move to processed folder
        mkdir -p ioc_imports/processed
        mv "$file" ioc_imports/processed/
    fi
done
EOF

chmod +x auto_import_daily.sh

# Add to cron (daily at 1 AM)
(crontab -l 2>/dev/null; echo "0 1 * * * cd ~/soc-analyst-bot && ./auto_import_daily.sh") | crontab -
```

## ⚠️ Important Notes

### ✅ What Works Great
- **Multiple hash types** per row
- **Large CSV files** (thousands of rows)
- **Missing columns** (script handles gracefully)
- **Empty values** (skips None/empty entries)
- **Auto-detection** of your format

### 🔧 CSV Requirements
- **UTF-8 encoding** (recommended)
- **Comma-separated** values
- **Headers in first row** (exactly as you specified)
- **No extra quotes** around values (unless necessary)

### 📊 Performance Tips
- Files with **10,000+ rows**: Use `custom_ioc_import.py` (optimized)
- Files with **< 1,000 rows**: Any method works fine
- **Very large files**: Import during off-peak hours

## 🧪 Testing Your Import

### 1. Test with Sample File
```bash
# Use the provided sample
python3 custom_ioc_import.py --file malware_sample.csv
```

### 2. Validate Your CSV Format
```bash
# Check if your CSV is compatible
python3 custom_ioc_import.py --validate your_file.csv
```

### 3. Test Detection
```bash
# Import sample, then test detection in Telegram bot
# Send this MD5 hash: d41d8cd98f00b204e9800998ecf8427e
# Should trigger IOC match alert!
```

## 🎉 Success Indicators

After importing your CSV file, you should see:

✅ **Database Growth**
```bash
python3 add_iocs.py --stats
# Should show increased IOC counts
```

✅ **Successful Detection**
- Send a hash from your CSV to the Telegram bot
- Should get "🚨 IOC DATABASE MATCH!" alert

✅ **Rich Context**
- AI analysis includes your IOC metadata
- Severity and confidence from your VT percentages
- Malware family from signature column

## 🔄 Regular Workflow

1. **Get new CSV** from your malware analysis system
2. **Copy to imports folder**: `cp new_threats.csv ioc_imports/`
3. **Quick import**: `./quick_import.sh ioc_imports/new_threats.csv`
4. **Verify import**: `python3 add_iocs.py --stats`
5. **Test detection**: Send a hash to your bot

---

**🎯 Your CSV format is now fully integrated! The system will extract 4-5 IOCs per row and provide rich threat intelligence for your SOC analysis.**

**🚀 Ready to protect your family with enterprise-grade threat detection!**
