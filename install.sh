#!/bin/bash

# SOC Analyst Bot Installation Script for Raspberry Pi 4
# This script will install and configure everything needed

set -e

echo "🛡️  SOC Analyst Bot Installation Starting..."
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running on Raspberry Pi
if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
    print_warning "This script is optimized for Raspberry Pi, but will continue anyway..."
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Create installation directory
INSTALL_DIR="$HOME/soc-analyst-bot"
print_status "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Update system packages
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install system dependencies
print_status "Installing system dependencies..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libmagic1 \
    libmagic-dev \
    libyara-dev \
    yara \
    curl \
    wget \
    git \
    systemd

# Install Ollama
print_status "Installing Ollama..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.ai/install.sh | sh
    print_success "Ollama installed successfully"
else
    print_success "Ollama already installed"
fi

# Start Ollama service
print_status "Starting Ollama service..."
sudo systemctl enable ollama
sudo systemctl start ollama

# Wait for Ollama to be ready
print_status "Waiting for Ollama to be ready..."
sleep 5

# Pull the AI model (using a smaller model suitable for RPi4)
print_status "Pulling AI model (this may take several minutes)..."
ollama pull llama3.2:1b
print_success "AI model downloaded successfully"

# Create Python virtual environment
print_status "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Download the main bot script from GitHub
print_status "Downloading bot application..."
curl -fsSL https://raw.githubusercontent.com/OrRosen2899/soc-analyst-bot/main/soc_analyst_bot.py -o soc_analyst_bot.py

# Download requirements.txt
curl -fsSL https://raw.githubusercontent.com/OrRosen2899/soc-analyst-bot/main/requirements.txt -o requirements.txt

# Download environment template
curl -fsSL https://raw.githubusercontent.com/OrRosen2899/soc-analyst-bot/main/.env.template -o .env.template
cp .env.template .env

# Install Python dependencies
print_status "Installing Python dependencies..."
pip install -r requirements.txt
print_success "Python dependencies installed"

# Make the script executable
chmod +x soc_analyst_bot.py

# Create systemd service file
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/soc-analyst-bot.service > /dev/null << EOF
[Unit]
Description=SOC Analyst Bot
After=network.target ollama.service
Requires=ollama.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/soc_analyst_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Create startup script
print_status "Creating startup script..."
cat > start_bot.sh << EOF
#!/bin/bash
cd "$INSTALL_DIR"
source venv/bin/activate
python soc_analyst_bot.py
EOF
chmod +x start_bot.sh

# Create update script
print_status "Creating update script..."
cat > update_bot.sh << EOF
#!/bin/bash
cd "$INSTALL_DIR"
source venv/bin/activate
pip install --upgrade -r requirements.txt
ollama pull llama3.2:1b
sudo systemctl restart soc-analyst-bot
echo "Bot updated successfully!"
EOF
chmod +x update_bot.sh

# Create uninstall script
print_status "Creating uninstall script..."
cat > uninstall.sh << EOF
#!/bin/bash
echo "Uninstalling SOC Analyst Bot..."
sudo systemctl stop soc-analyst-bot
sudo systemctl disable soc-analyst-bot
sudo rm /etc/systemd/system/soc-analyst-bot.service
sudo systemctl daemon-reload
cd ..
rm -rf "$INSTALL_DIR"
echo "Uninstall complete!"
EOF
chmod +x uninstall.sh

# Create README
print_status "Creating documentation..."
cat > README.md << EOF
# 🛡️ SOC Analyst Bot

Your personal Security Operations Center analyst running on Raspberry Pi!

## 🚀 Quick Start

1. **Get a Telegram Bot Token:**
   - Message @BotFather on Telegram
   - Create a new bot with /newbot
   - Copy the token

2. **Configure the bot:**
   \`\`\`bash
   nano .env
   \`\`\`
   - Add your Telegram bot token
   - Optionally add your Telegram user ID for authorization
   - Add API keys for enhanced features (optional)

3. **Start the bot:**
   \`\`\`bash
   ./start_bot.sh
   \`\`\`

4. **Or run as a service:**
   \`\`\`bash
   sudo systemctl enable soc-analyst-bot
   sudo systemctl start soc-analyst-bot
   \`\`\`

## 📱 How to Use

Send your bot any of these:
- 📁 **Files** - Upload any file for malware analysis
- 🌐 **URLs** - Send a URL to check its reputation
- 🔍 **IP Addresses** - Check if an IP is malicious
- 🔐 **File Hashes** - MD5, SHA1, or SHA256 hashes
- 📧 **Email Content** - Paste suspicious emails

## 🔧 Commands

- \`/start\` - Welcome message and instructions
- \`/help\` - Detailed help information
- \`/status\` - Check system status

## 🛠️ Maintenance

- **Update:** \`./update_bot.sh\`
- **View logs:** \`sudo journalctl -u soc-analyst-bot -f\`
- **Restart:** \`sudo systemctl restart soc-analyst-bot\`
- **Uninstall:** \`./uninstall.sh\`

## 🔑 API Keys (Optional but Recommended)

For enhanced threat intelligence, get free API keys:

1. **VirusTotal:** https://www.virustotal.com/gui/join-us
2. **AbuseIPDB:** https://www.abuseipdb.com/register

Add them to your \`.env\` file for better analysis results.

## 🎯 Features

- ✅ Local AI analysis (no data leaves your Pi)
- ✅ File malware scanning with YARA rules
- ✅ URL reputation checking
- ✅ IP threat intelligence
- ✅ Hash lookup against threat databases
- ✅ Email analysis for phishing
- ✅ Family-friendly security advice
- ✅ Multi-user support with authorization

## 🔒 Security

- All analysis happens locally on your Raspberry Pi
- No sensitive data is sent to external services (except optional API calls)
- User authorization prevents unauthorized access
- Automatic file cleanup after analysis

## 📈 Performance

Optimized for Raspberry Pi 4:
- Uses lightweight Llama 3.2 1B model
- Efficient resource usage
- Automatic cleanup and monitoring

## 🆘 Troubleshooting

**Bot not responding?**
\`\`\`bash
sudo systemctl status soc-analyst-bot
sudo journalctl -u soc-analyst-bot -f
\`\`\`

**Ollama issues?**
\`\`\`bash
sudo systemctl status ollama
ollama list
\`\`\`

**Need help?** Check the logs and verify your .env configuration.
EOF

print_success "Installation completed successfully!"
echo
echo "=========================================="
echo "🎉 SOC Analyst Bot Installation Complete!"
echo "=========================================="
echo
echo "📋 Next Steps:"
echo "1. Edit the configuration file:"
echo "   nano $INSTALL_DIR/.env"
echo
echo "2. Add your Telegram bot token (get it from @BotFather)"
echo
echo "3. Start the bot:"
echo "   cd $INSTALL_DIR && ./start_bot.sh"
echo
echo "4. Or run as a service:"
echo "   sudo systemctl enable soc-analyst-bot"
echo "   sudo systemctl start soc-analyst-bot"
echo
echo "📚 Documentation: $INSTALL_DIR/README.md"
echo "🔧 Configuration: $INSTALL_DIR/.env"
echo "📊 View logs: sudo journalctl -u soc-analyst-bot -f"
echo
print_success "Your personal SOC analyst is ready to protect your family!"
