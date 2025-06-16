# 🛡️ SOC AI Agent

A comprehensive Security Operations Center AI agent for Telegram that combines threat intelligence APIs with local AI analysis. Perfect for family cybersecurity monitoring on Raspberry Pi.

## ✨ Features

- 🤖 **AI-Powered Analysis** using Ollama (runs locally)
- 🦠 **VirusTotal Integration** for malware detection
- 🚫 **AbuseIPDB Integration** for IP reputation
- 📋 **Local IOC Database** with SQLite
- 💬 **Telegram Bot Interface** with rich UI
- 🔍 **Multi-Indicator Support**: URLs, IPs, domains, hashes
- 📊 **Analysis History** and statistics
- 🔒 **Family-Safe** with user authorization
- 🍓 **Raspberry Pi Optimized**

## 🎯 Supported Indicators

| Type | Examples | Sources |
|------|----------|---------|
| **URLs** | `https://example.com/malware.exe` | VirusTotal, AI Analysis |
| **IP Addresses** | `192.168.1.1`, `2001:db8::1` | VirusTotal, AbuseIPDB, Local IOCs |
| **Domains** | `malware.com`, `phishing.net` | VirusTotal, Local IOCs |
| **File Hashes** | MD5, SHA1, SHA256 | VirusTotal, Local IOCs |

## 🚀 Quick Installation

### Prerequisites
- Raspberry Pi 4 with 8GB RAM (or any Linux system)
- Python 3.8+
- Internet connection

### One-Command Install
```bash
git clone https://github.com/yourusername/soc-ai-agent.git
cd soc-ai-agent
python3 setup.py
```

### Manual Installation

1. **Clone Repository**
```bash
git clone https://github.com/yourusername/soc-ai-agent.git
cd soc-ai-agent
```

2. **Install System Dependencies**
```bash
sudo apt update
sudo apt install -y python3-pip python3-venv git curl sqlite3
```

3. **Install Ollama**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama2
```

4. **Setup Python Environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

5. **Configure Environment**
```bash
cp .env.example .env
# Edit .env with your API keys
```

## ⚙️ Configuration

### API Keys Required

1. **Telegram Bot Token**
   - Message [@BotFather](https://t.me/botfather) on Telegram
   - Create new bot: `/newbot`
   - Copy the token to `.env`

2. **VirusTotal API Key**
   - Register at [virustotal.com](https://virustotal.com)
   - Go to API Key section
   - Copy key to `.env`

3. **AbuseIPDB API Key** (Optional)
   - Register at [abuseipdb.com](https://abuseipdb.com)
   - Generate API key
   - Copy key to `.env`

### Environment Configuration (.env)
```bash
# Required
TELEGRAM_BOT_TOKEN=your_bot_token_here
VIRUSTOTAL_API_KEY=your_vt_key_here

# Optional but recommended
ABUSEDB_API_KEY=your_abusedb_key_here
ALLOWED_USER_IDS=123456789,987654321

# System Configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama2
DATABASE_PATH=soc_agent.db
```

### Get Your Telegram User ID
1. Message [@userinfobot](https://t.me/userinfobot) on Telegram
2. Add your ID to `ALLOWED_USER_IDS` in `.env`

## 🏃‍♂️ Running the Agent

### Test Run
```bash
source venv/bin/activate
python soc_agent.py
```

### Install as System Service
```bash
sudo cp soc-agent.service /etc/systemd/system/
sudo systemctl enable soc-agent
sudo systemctl start soc-agent
sudo systemctl status soc-agent
```

### Check Logs
```bash
sudo journalctl -u soc-agent -f
```

## 📋 IOC Management

### IOC File Formats

**Malware Analysis Feed Format** (your specific format):
```csv
first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,clamav,vtpercent,imphash,ssdeep,tlsh
2025-01-15T10:30:00Z,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,d41d8cd98f00b204e9800998ecf8427e,da39a3ee5e6b4b0d3255bfef95601890afd80709,MalwareAnalysis,trojan.exe,PE32 executable,application/x-executable,Trojan.Win32.Generic,Win.Trojan.Agent-123456,75%,1234567890abcdef,48:hash1234:hash5678,T1234567890ABCDEF
```

**Standard IOC Format**:
```csv
indicator,type,description,threat_type,source,confidence
malware.com,domain,Known malware distribution,malware,threat_intel,95
192.168.1.100,ip,Compromised internal host,botnet,internal,80
d41d8cd98f00b204e9800998ecf8427e,md5,Empty file hash,safe,system,100
```

**Plain Text Format**:
```
malware.com
192.168.1.100
d41d8cd98f00b204e9800998ecf8427e
# Comments start with #
suspicious-domain.net
```

### Import IOCs
```bash
# Import malware analysis feed (auto-detects format)
python import_iocs.py malware_feed.csv "threat_intel"

# Import standard IOC format
python import_iocs.py indicators.csv "external_feed"

# Import from text file
python import_iocs.py indicators.txt "manual_analysis"
```

**Smart Import Features:**
- 🔍 **Auto-detection** of CSV format (malware feed vs standard)
- 📊 **Multiple hashes** extracted from single row (MD5, SHA1, SHA256)
- 📁 **Rich metadata** preserved from malware analysis feeds
- 🎯 **Confidence scoring** based on VT detection percentages
- 🔄 **Duplicate handling** with automatic updates

### IOC Database Schema
| Field | Type | Description |
|-------|------|-------------|
| `indicator` | TEXT | The actual indicator (IP, domain, hash, etc.) |
| `type` | TEXT | Indicator type (ip, domain, md5, sha1, sha256, url) |
| `description` | TEXT | Human-readable description |
| `threat_type` | TEXT | Type of threat (malware, phishing, botnet, safe, etc.) |
| `source` | TEXT | Source of the indicator |
| `confidence` | INTEGER | Confidence level (0-100) |
| `metadata` | TEXT | JSON metadata (file info, VT percentages, etc.) |

**Malware Feed Metadata** includes:
- `first_seen_utc` - When the sample was first observed
- `file_name` - Original filename
- `file_type_guess` - Detected file type
- `signature` - Antivirus signature name
- `vtpercent` - VirusTotal detection percentage
- `reporter` - Source of the analysis

## 💬 Using the Bot

### Start the Bot
1. Find your bot on Telegram (search by username)
2. Send `/start`
3. Use the interactive menu or send indicators directly

### Send Indicators
Just type or paste any supported indicator:
```
https://malicious-site.com
192.168.1.100
malware.exe.md5hash
suspicious-domain.net
```

### Bot Commands
- `/start` - Show main menu and help
- Send any indicator - Immediate analysis
- Use inline buttons for navigation

### Bot Interface
```
🛡️ SOC AI Agent

🔍 Analyze Indicator  📊 Analysis History
📋 IOC Stats         ℹ️ Help
```

## 📊 Analysis Output

The bot provides comprehensive analysis including:

```
🔍 Analysis Report
Indicator: d41d8cd98f00b204e9800998ecf8427e
Type: MD5
Timestamp: 2025-06-16 15:30:45

🦠 VirusTotal Analysis:
🚨 Detection: 15/89 engines flagged as malicious
📊 Reputation Score: -50

📋 Local IOC Database:
⚠️ Match found: malware (Confidence: 95%)
   Source: threat_intel
   📄 File: trojan.exe
   📁 Type: PE32 executable
   🔍 Signature: Trojan.Win32.Generic
   🦠 VT Detection: 75%
   📅 First Seen: 2025-01-15T10:30:00Z

🤖 AI Security Analysis:
Risk Assessment: HIGH
This file hash has been flagged by multiple security vendors...
Recommended Actions: Block file execution, quarantine system...
```

## 🔧 Troubleshooting

### Common Issues

**Bot not responding:**
```bash
# Check if service is running
sudo systemctl status soc-agent

# Check logs
sudo journalctl -u soc-agent -f
```

**Ollama not working:**
```bash
# Check Ollama status
sudo systemctl status ollama

# Test Ollama directly
curl http://localhost:11434/api/version
```

**API rate limits:**
- VirusTotal: 4 requests/minute (free tier)
- AbuseIPDB: 1000 requests/day (free tier)

**Memory issues on Raspberry Pi:**
- Use smaller Ollama models: `ollama pull llama2:7b-chat`
- Limit concurrent requests in code
- Monitor with `htop`

### Performance Optimization

**For Raspberry Pi 4:**
```bash
# GPU memory split (if using desktop)
echo "gpu_mem=16" | sudo tee -a /boot/config.txt

# Increase swap
sudo dphys-swapfile swapoff
sudo sed -i 's/CONF_SWAPSIZE=100/CONF_SWAPSIZE=2048/' /etc/dphys-swapfile
sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

## 🔒 Security Considerations

### Best Practices
- ✅ Use `ALLOWED_USER_IDS` to restrict access
- ✅ Keep API keys secure in `.env`
- ✅ Run bot as non-root user
- ✅ Regular database backups
- ✅ Monitor logs for suspicious activity

### Network Security
```bash
# Optional: Restrict network access
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow from 192.168.1.0/24 to any port 11434  # Ollama local only
```

## 📁 File Structure

```
soc-ai-agent/
├── soc_agent.py          # Main bot application
├── setup.py              # Installation script
├── import_iocs.py        # IOC import utility
├── .env                  # Configuration (create from .env.example)
├── .env.example          # Environment template
├── soc-agent.service     # Systemd service file
├── soc_agent.db          # SQLite database (created automatically)
├── README.md             # This file
├── requirements.txt      # Python dependencies
└── samples/
    ├── sample_iocs.csv   # Example IOC file
    └── indicators.txt    # Example text file
```

## 🔄 Updates and Maintenance

### Update the Bot
```bash
cd soc-ai-agent
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart soc-agent
```

### Database Backup
```bash
# Backup
sqlite3 soc_agent.db ".backup backup_$(date +%Y%m%d).db"

# Restore
sqlite3 soc_agent.db ".restore backup_20250616.db"
```

### Log Rotation
```bash
# Add to /etc/logrotate.d/soc-agent
/var/log/soc-agent.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 644 pi pi
    postrotate
        systemctl reload soc-agent
    endscript
}
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: Open a GitHub issue
- **Discussions**: Use GitHub Discussions
- **Security**: Email security issues privately

## 🙏 Acknowledgments

- **Ollama** - Local AI inference
- **VirusTotal** - Malware detection API
- **AbuseIPDB** - IP reputation database
- **python-telegram-bot** - Telegram Bot framework

---

**Made with ❤️ for family cybersecurity**
