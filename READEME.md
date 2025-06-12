# 🛡️ Private SOC Analyst Bot

Your personal Security Operations Center analyst powered by AI, running locally on Raspberry Pi 4. Perfect for families who want to stay safe online!

## ✨ Features

- 🤖 **Local AI Analysis** - Uses Ollama with Llama 3.2 (no data leaves your network)
- 📁 **File Scanning** - YARA rules + AI analysis for malware detection
- 🌐 **URL Checking** - Reputation analysis for suspicious links
- 🔍 **IP Investigation** - Check IPs against threat intelligence databases
- 🔐 **Hash Lookup** - Verify file hashes against known malware
- 📧 **Email Analysis** - Detect phishing and suspicious emails
- 👨‍👩‍👧‍👦 **Family Friendly** - Simple explanations for non-technical users
- 🔒 **Privacy First** - Everything runs locally on your Raspberry Pi
- 📱 **Telegram Interface** - Easy to use from any device

## 🚀 One-Click Installation

**For Raspberry Pi 4 (Recommended):**

```bash
# Download and run the installer
curl -fsSL https://raw.githubusercontent.com/OrRosen2899/soc-analyst-bot/main/install.sh | bash

# Or manual installation:
wget https://raw.githubusercontent.com/OrRosen2899/soc-analyst-bot/main/install.sh
chmod +x install.sh
./install.sh
