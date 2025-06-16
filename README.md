# 🛡️ AI SOC Analyst Bot with Advanced IOC Database

A comprehensive Security Operations Center (SOC) analyst powered by AI, designed for Raspberry Pi with enterprise-grade threat intelligence capabilities. Perfect for families and professionals who need real-time threat detection and analysis.

## 🚀 Key Features

### 🔍 **Multi-Vector Analysis**
- **🔐 Hash Analysis** - MD5, SHA1, SHA256 with instant IOC database lookup
- **🌐 IP Analysis** - Reputation checking with geographic intelligence  
- **🔗 URL Analysis** - Phishing and malware domain detection
- **📄 File Analysis** - Upload any file for comprehensive security analysis
- **📧 Email Analysis** - Forward suspicious emails for threat assessment

### 🗄️ **Advanced IOC Database System**
- **📥 Custom CSV Import** - Specialized support for malware analysis CSV files
- **🌐 Automated Threat Feeds** - Download from multiple public intelligence sources
- **⚡ Instant Detection** - Every analysis checks against your threat database
- **📊 Rich Analytics** - Hit tracking, statistics, and trend analysis
- **💾 Enterprise Management** - Backup, restore, search, export capabilities

### 🤖 **AI-Powered Intelligence**
- **🧠 Local AI Analysis** - Ollama integration for privacy-first analysis
- **🎯 Context-Aware** - AI enhanced with IOC database matches
- **📈 Continuous Learning** - Improves accuracy over time
- **🔒 Privacy-First** - All analysis done locally on your device

### 👨‍👩‍👧‍👦 **Family-Friendly Design**
- **📱 Telegram Interface** - Intuitive buttons and clear results
- **🔍 Auto-Detection** - Just send suspicious content directly
- **🛡️ Real-Time Protection** - Automatic threat blocking
- **📚 Educational** - Learn about cybersecurity threats

## 📋 System Requirements

### **Minimum**
- Raspberry Pi 4 (2GB RAM)
- 16GB SD card (Class 10)
- Internet connection for setup

### **Recommended**
- Raspberry Pi 4 (4GB+ RAM)
- 32GB+ SD card (high-speed)
- Ethernet connection
- Cooling solution

## ⚡ Quick Installation

### 1. **Download Project**
```bash
git clone <your-repo-url>
cd ai-soc-analyst-bot
```

### 2. **One-Click Setup**
```bash
chmod +x install.sh
./install.sh
```

### 3. **Configure Bot**
```bash
# Get Telegram bot token from @BotFather
nano .env
# Add: TELEGRAM_BOT_TOKEN=your_token_here
```

### 4. **Setup Automation**
```bash
chmod +x setup_cron.sh
./setup_cron.sh
```

### 5. **Start Protecting!**
```bash
docker-compose restart
# Send /start to your bot on Telegram
```

## 🗄️ IOC Database - The Game Changer

### **Custom CSV Format Support**
Perfect for malware analysis systems with this exact format:
```
first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter, 
file_name, file_type_guess, mime_type, signature, clamav, 
vtpercent, imphash, ssdeep, tlsh
```

### **Smart IOC Extraction**
From **each CSV row**, extract **4-5 IOCs**:
- ✅ **SHA256, MD5, SHA1** hashes
- ✅ **Filenames** and **Import hashes**
- ✅ **Auto-calculated confidence** from VT percentages
- ✅ **Rich metadata** and threat classification

### **Multiple Import Methods**

#### **Super Quick Import**
```bash
./quick_import.sh your_malware_file.csv
```

#### **Custom Format Importer**
```bash
# Interactive import with validation
python3 custom_ioc_import.py --interactive

# Direct import
python3 custom_ioc_import.py --file your_malware_data.csv
```

#### **Auto-Detection Import**
```bash
# Automatically detects your CSV format
python3 add_iocs.py --interactive
```

### **Automated Threat Intelligence**
- **Daily Updates** - Download latest IOCs from public feeds
- **Multiple Sources** - Abuse.ch, Blocklist.de, PhishTank, and more
- **Smart Processing** - Automatic deduplication and validation
- **Zero Maintenance** - Runs automatically in background

## 🎯 How It Works

### **Real-Time Protection Flow**
1. **Family member** sends suspicious link/file to bot
2. **Instant IOC check** against your threat database
3. **AI analysis** enhanced with IOC context if match found
4. **VirusTotal lookup** (if configured)
5. **Comprehensive report** with actionable recommendations

### **IOC Match Example**
```
🚨 IOC DATABASE MATCH!
Threat Type: malware
Malware Family: Trojan.Generic
Severity: Critical
Source: sandbox_analysis  
Confidence: 85%
Description: Signature: Trojan.Generic; Type: executable; VT: 85%

🤖 AI Analysis:
This hash matches a known malicious file in our threat database.
IMMEDIATE ACTION REQUIRED:
1. Do not execute this file
2. Run full system scan
3. Check for other indicators of compromise
```

## 📊 Management & Analytics

### **Database Management**
```bash
# Interactive management menu
python3 manage_iocs.py --interactive

# Quick statistics
python3 add_iocs.py --stats

# Search IOCs
python3 manage_iocs.py --search "evil.com"

# Export threat intelligence
python3 manage_iocs.py --export my_threats.csv
```

### **Feed Management**
```bash
# Update all threat feeds
python3 ioc_feeds.py --update

# List available feeds
python3 ioc_feeds.py --list

# Enable/disable specific feeds
python3 ioc_feeds.py --enable abuse_ch_malware
```

### **System Monitoring**
```bash
# Check bot status
docker-compose ps

# View real-time logs
docker-compose logs -f soc-bot

# Database statistics
python3 add_iocs.py --stats
```

## 🔧 Advanced Configuration

### **Environment Variables (.env)**
```bash
# Required: Telegram Bot Token
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ

# AI Configuration
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama2

# Optional: Enhanced Analysis
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

### **Supported IOC Types**
- **Hashes**: MD5, SHA1, SHA256, IMPHASH
- **Network**: IPv4, IPv6, Domains, URLs
- **Files**: Filenames, Registry keys, Mutexes
- **Email**: Email addresses
- **Advanced**: YARA rules, Certificates

### **Automated Operations**
- **Daily (2:00 AM)**: Download threat feeds, import IOCs, create backups
- **Weekly (Sunday 3:00 AM)**: Database maintenance, cleanup, optimization
- **Continuous**: Real-time threat detection and family protection

## 🔒 Security & Privacy

### **Privacy-First Design**
- **Local Processing** - All AI analysis runs on your device
- **No Data Sharing** - IOCs and analysis stay on your Raspberry Pi
- **Encrypted Backups** - Optional backup encryption
- **Access Control** - Only your family has access

### **Enterprise Security Features**
- **Audit Trail** - Track all IOC hits and system access
- **False Positive Management** - Learn and improve over time
- **Database Integrity** - Automatic validation and repair
- **Secure Updates** - Verified threat intelligence sources

## 📱 Telegram Bot Interface

### **Smart Buttons**
- 🔍 **Analyze Hash** - Submit file hashes for analysis
- 🌐 **Analyze IP** - Check IP address reputation
- 🔗 **Analyze URL** - Verify link safety before clicking
- 📄 **Analyze File** - Upload suspicious files
- 📧 **Analyze Email** - Forward phishing attempts
- 🗄️ **IOC Database** - Manage threat intelligence
- 📊 **Status** - System health and statistics

### **Auto-Detection**
Just send any suspicious content directly:
- **Hashes**: `5d41402abc4b2a76b9719d911017c592`
- **IPs**: `192.168.1.100`
- **URLs**: `https://suspicious-site.com`
- **Files**: Upload any file type

## 🏠 Family Protection Scenarios

### **Safe Browsing**
"*Dad, is this link safe?*" → Send to bot → Instant safety report

### **Email Security** 
"*Mom got a suspicious email*" → Forward to bot → Phishing analysis

### **File Safety**
"*Downloaded this file, is it safe?*" → Upload to bot → Malware scan

### **Learning Opportunity**
Each analysis includes educational content about cybersecurity threats

## 📁 Complete Project Structure

```
ai-soc-analyst-bot/
├── 🔧 Core Application
│   ├── main.py                    # Main bot with IOC integration
│   ├── ioc_database.py           # IOC database management
│   ├── add_iocs.py               # Enhanced IOC import with auto-detection
│   ├── custom_ioc_import.py      # Specialized importer for your CSV format
│   ├── ioc_feeds.py              # Automated threat feed downloader
│   ├── manage_iocs.py            # Database management tools
│   └── requirements.txt          # Python dependencies
│
├── 🐳 Deployment
│   ├── Dockerfile                # Container with IOC database support
│   ├── docker-compose.yml        # Service orchestration
│   ├── install.sh                # Enhanced installation script
│   └── soc-bot.service          # Systemd service
│
├── ⚙️ Configuration & Templates
│   ├── .env.example             # Environment configuration template
│   ├── ioc_template.csv         # Standard IOC CSV format
│   ├── malware_sample.csv       # Your custom CSV format example
│   └── .gitignore               # Git ignore rules
│
├── 🔄 Automation Scripts
│   ├── setup_cron.sh            # Setup automated operations
│   ├── quick_import.sh           # One-command CSV import
│   ├── update_ioc_feeds.sh      # Daily feed updates (auto-created)
│   └── weekly_maintenance.sh    # Weekly maintenance (auto-created)
│
├── 📖 Documentation
│   ├── README.md                # This comprehensive guide
│   ├── IOC_IMPORT_GUIDE.md      # Detailed IOC import instructions
│   ├── YOUR_CSV_FORMAT_GUIDE.md # Guide for your specific CSV format
│   └── COMPLETE_PROJECT_STRUCTURE.md # Full project overview
│
└── 📂 Runtime Directories (created automatically)
    ├── data/                    # IOC database storage
    ├── logs/                   # Application and feed logs
    ├── ioc_imports/           # Your CSV files go here
    ├── backups/               # Automated database backups
    └── ioc_feeds/             # Downloaded threat feed cache
```

## 🎯 Success Metrics

### **Deployment Success**
- ✅ Bot responds to `/start` command
- ✅ IOC database initialized with sample data
- ✅ Automated feeds downloading daily
- ✅ Family members can use successfully

### **Protection Success** 
- 🎯 **Threats Detected** - IOC matches trigger alerts
- 📈 **Database Growth** - Continuous threat intelligence updates
- 👨‍👩‍👧‍👦 **Family Usage** - Regular safety checks by family members
- 📊 **Analytics** - Hit statistics and trend analysis

## 🔄 Regular Workflow

### **For Administrators**
1. **Weekly**: Check `python3 add_iocs.py --stats`
2. **Monthly**: Review hit analytics and false positives
3. **As Needed**: Import new threat intelligence CSV files
4. **Ongoing**: Monitor family usage and provide guidance

### **For Family Members**
1. **Before Clicking Links**: Send to bot for safety check
2. **Suspicious Emails**: Forward to bot for analysis
3. **Downloaded Files**: Upload to bot before opening
4. **Learning**: Read bot explanations about threats

## 🐛 Troubleshooting

### **Common Issues**

#### **Bot Not Responding**
```bash
docker-compose ps              # Check if services are running
docker-compose logs soc-bot    # Check bot logs
docker-compose restart         # Restart services
```

#### **IOC Database Issues**
```bash
python3 add_iocs.py --stats           # Check database status
python3 manage_iocs.py --validate     # Validate database integrity
python3 manage_iocs.py --optimize     # Optimize performance
```

#### **Import Problems**
```bash
python3 custom_ioc_import.py --validate your_file.csv  # Check CSV format
python3 add_iocs.py --interactive                      # Interactive import
./quick_import.sh your_file.csv                        # Quick import
```

### **Performance Optimization**
```bash
# For large IOC databases
python3 manage_iocs.py --optimize

# For memory issues
docker-compose restart ollama

# For storage issues
python3 manage_iocs.py --cleanup 30  # Remove old backups
```

## 🔮 Advanced Features

### **Custom Threat Feeds**
Add your own threat intelligence sources to `ioc_feeds_config.json`

### **API Integration**
Extend with additional threat intelligence APIs

### **Machine Learning**
AI model learns from your specific threat landscape

### **Multi-Tenant**
Support multiple families/organizations

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b amazing-feature`
3. Make your changes
4. Test on Raspberry Pi
5. Submit pull request

## 📄 License

This project is open source and available under the MIT License.

## ⚠️ Disclaimer

This tool is designed for educational and defensive security purposes. Users are responsible for complying with applicable laws and regulations. The system provides security analysis but should not be the only security measure implemented.

## 🆘 Support

- **📖 Documentation**: Check the comprehensive guides included
- **🐛 Issues**: Create GitHub issues for bugs or feature requests
- **💬 Discussions**: Use GitHub discussions for questions
- **📧 Contact**: Reach out to the maintainer for enterprise support

---

## 🎉 Ready to Deploy?

**Your AI SOC Analyst Bot is the most advanced family cybersecurity solution available.**

### **What You Get:**
- 🛡️ **Enterprise-grade threat detection** for your entire family
- 🗄️ **Custom threat intelligence** from your malware analysis
- 🤖 **AI-powered analysis** with local privacy
- 📱 **Family-friendly interface** that anyone can use
- 🔄 **Automated operations** requiring zero maintenance
- 📊 **Professional analytics** and reporting capabilities

### **Installation Time:** 15 minutes
### **Family Protection:** Immediate
### **Maintenance Required:** None (fully automated)

**🚀 Start protecting your family today with enterprise-grade cybersecurity!**

```bash
git clone <your-repo-url>
cd ai-soc-analyst-bot
./install.sh
# Add your Telegram bot token to .env
# Start protecting your family! 🛡️
```

---

**🛡️ Stay Safe, Stay Secure, Stay Protected!**
