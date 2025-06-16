#!/bin/bash

echo "🛡️ Installing AI SOC Analyst Bot with IOC Database..."

# Check if running on Raspberry Pi
if [[ $(uname -m) == "aarch64" || $(uname -m) == "armv7l" ]]; then
    echo "✅ Raspberry Pi detected"
else
    echo "⚠️ Not running on Raspberry Pi, but continuing..."
fi

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install system dependencies
echo "🔧 Installing system dependencies..."
sudo apt install -y python3 python3-pip sqlite3 curl wget

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
fi

# Install Docker Compose if not present
if ! command -v docker-compose &> /dev/null; then
    echo "🔧 Installing Docker Compose..."
    sudo apt install -y docker-compose
fi

# Create project directory
echo "📁 Setting up project..."
mkdir -p ~/soc-analyst-bot
cd ~/soc-analyst-bot

# Create necessary directories
mkdir -p data logs ioc_imports backups

# Copy configuration files (assuming they're in current directory)
echo "📋 Setting up configuration..."

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "⚙️ Creating environment configuration..."
    cat > .env << EOL
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=

# Ollama Configuration  
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama2

# VirusTotal API (Optional)
VIRUSTOTAL_API_KEY=

# IOC Database Configuration
IOC_DATABASE_PATH=data/ioc_database.db
IOC_AUTO_BACKUP=true
IOC_BACKUP_RETENTION_DAYS=30
EOL
    echo "📝 Please edit .env file with your Telegram bot token"
    echo "   Get token from @BotFather on Telegram"
fi

# Install Python dependencies if running outside Docker
echo "🐍 Installing Python dependencies..."
pip3 install --user python-telegram-bot python-dotenv requests python-magic pandas

# Initialize IOC database
echo "🗄️ Initializing IOC database..."
if [ -f "ioc_database.py" ]; then
    python3 -c "
from ioc_database import IOCDatabase
db = IOCDatabase()
print('✅ IOC database initialized successfully')
"
else
    echo "⚠️ IOC database module not found, will be initialized when bot starts"
fi

# Create sample IOC file if it doesn't exist
if [ ! -f "ioc_imports/sample_iocs.csv" ]; then
    echo "📄 Creating sample IOC file..."
    cat > ioc_imports/sample_iocs.csv << EOL
ioc_value,ioc_type,threat_type,malware_family,source,description,confidence,severity
5d41402abc4b2a76b9719d911017c592,md5,test,sample,install_script,Sample test hash for demonstration,50,low
192.168.999.999,ip,test,sample,install_script,Invalid IP for testing,30,low
test-domain.example,domain,test,sample,install_script,Test domain for demonstration,40,low
EOL
fi

# Start services
echo "🚀 Starting services..."
docker-compose up -d

# Wait for Ollama to start
echo "⏳ Waiting for Ollama to start..."
sleep 30

# Pull the AI model
echo "🧠 Downloading AI model (this may take a while)..."
docker exec soc-ollama ollama pull llama2

# Test IOC database functionality
echo "🧪 Testing IOC database..."
if [ -f "add_iocs.py" ]; then
    python3 add_iocs.py --file ioc_imports/sample_iocs.csv
    echo "✅ Sample IOCs imported for testing"
fi

# Create backup script
echo "💾 Setting up backup system..."
cat > backup_iocs.sh << 'EOL'
#!/bin/bash
# IOC Database Backup Script

BACKUP_DIR="backups"
DB_FILE="data/ioc_database.db"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/ioc_backup_$DATE.db"

mkdir -p $BACKUP_DIR

if [ -f "$DB_FILE" ]; then
    cp "$DB_FILE" "$BACKUP_FILE"
    echo "✅ IOC database backed up to $BACKUP_FILE"
    
    # Keep only last 7 days of backups
    find $BACKUP_DIR -name "ioc_backup_*.db" -mtime +7 -delete
else
    echo "❌ Database file not found: $DB_FILE"
fi
EOL

chmod +x backup_iocs.sh

# Create maintenance script
echo "🔧 Setting up maintenance script..."
cat > maintain_iocs.sh << 'EOL'
#!/bin/bash
# IOC Database Maintenance Script

echo "🔧 IOC Database Maintenance"
echo "=========================="

# Backup database
echo "💾 Creating backup..."
./backup_iocs.sh

# Show statistics
echo "📊 Current statistics:"
python3 add_iocs.py --stats

# Clean old hits (optional)
echo "🧹 Cleaning old hit records (older than 30 days)..."
python3 -c "
from ioc_database import IOCDatabase
try:
    db = IOCDatabase()
    deleted = db.cleanup_old_hits(30)
    print(f'✅ Cleaned {deleted} old hit records')
except Exception as e:
    print(f'❌ Cleanup failed: {e}')
"

echo "✅ Maintenance completed"
EOL

chmod +x maintain_iocs.sh

# Set up systemd service for auto-start (optional)
echo "⚙️ Setting up auto-start service..."
cat > soc-bot-setup.service << EOL
[Unit]
Description=AI SOC Analyst Bot with IOC Database
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=true
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0
User=$(whoami)

[Install]
WantedBy=multi-user.target
EOL

# Offer to install systemd service
read -p "🔄 Install auto-start service? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    sudo cp soc-bot-setup.service /etc/systemd/system/soc-bot.service
    sudo systemctl daemon-reload
    sudo systemctl enable soc-bot
    echo "✅ Auto-start service installed"
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "🛡️ Your SOC Analyst Bot with IOC Database is ready!"
echo ""
echo "📋 Next Steps:"
echo "1. Edit .env file with your Telegram bot token:"
echo "   nano .env"
echo ""
echo "2. Restart services after adding token:"
echo "   docker-compose restart"
echo ""
echo "3. Import your IOCs:"
echo "   python3 add_iocs.py --interactive"
echo ""
echo "4. Test the bot on Telegram!"
echo ""
echo "🔧 Management Commands:"
echo "📊 Check status: docker-compose ps"
echo "📝 View logs: docker-compose logs -f soc-bot"
echo "🗄️ IOC stats: python3 add_iocs.py --stats"
echo "💾 Backup IOCs: ./backup_iocs.sh"
echo "🔧 Maintenance: ./maintain_iocs.sh"
echo ""
echo "📖 For IOC import help, see: IOC_IMPORT_GUIDE.md"
