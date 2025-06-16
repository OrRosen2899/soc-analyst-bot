#!/bin/bash

echo "🕐 Setting up automated IOC feed updates..."

# Get current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create cron job scripts
echo "📝 Creating cron job scripts..."

# Daily IOC feed update script
cat > update_ioc_feeds.sh << 'EOL'
#!/bin/bash

# IOC Feed Update Script
# Runs daily to update threat intelligence feeds

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="logs/ioc_feeds_$(date +%Y%m%d).log"
mkdir -p logs

echo "$(date): Starting IOC feed update" >> "$LOG_FILE"

# Update feeds
python3 ioc_feeds.py --update >> "$LOG_FILE" 2>&1

# Backup database after updates
if [ $? -eq 0 ]; then
    echo "$(date): Feed update successful, creating backup" >> "$LOG_FILE"
    python3 manage_iocs.py --backup >> "$LOG_FILE" 2>&1
else
    echo "$(date): Feed update failed" >> "$LOG_FILE"
fi

# Cleanup old logs (keep 7 days)
find logs/ -name "ioc_feeds_*.log" -mtime +7 -delete

echo "$(date): IOC feed update completed" >> "$LOG_FILE"
EOL

chmod +x update_ioc_feeds.sh

# Weekly maintenance script
cat > weekly_maintenance.sh << 'EOL'
#!/bin/bash

# Weekly IOC Database Maintenance Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

LOG_FILE="logs/maintenance_$(date +%Y%m%d).log"
mkdir -p logs

echo "$(date): Starting weekly maintenance" >> "$LOG_FILE"

# Backup database
echo "$(date): Creating weekly backup" >> "$LOG_FILE"
python3 manage_iocs.py --backup >> "$LOG_FILE" 2>&1

# Cleanup old IOC hits (30 days)
echo "$(date): Cleaning old IOC hits" >> "$LOG_FILE"
python3 -c "
from ioc_database import IOCDatabase
try:
    db = IOCDatabase()
    deleted = db.cleanup_old_hits(30)
    print(f'Cleaned {deleted} old hit records')
except Exception as e:
    print(f'Cleanup failed: {e}')
" >> "$LOG_FILE" 2>&1

# Cleanup old backups (30 days)
echo "$(date): Cleaning old backups" >> "$LOG_FILE"
python3 manage_iocs.py --cleanup 30 >> "$LOG_FILE" 2>&1

# Optimize database
echo "$(date): Optimizing database" >> "$LOG_FILE"
python3 manage_iocs.py --optimize >> "$LOG_FILE" 2>&1

# Validate database
echo "$(date): Validating database" >> "$LOG_FILE"
python3 manage_iocs.py --validate >> "$LOG_FILE" 2>&1

# Cleanup old logs (keep 30 days)
find logs/ -name "*.log" -mtime +30 -delete

echo "$(date): Weekly maintenance completed" >> "$LOG_FILE"
EOL

chmod +x weekly_maintenance.sh

# Check if cron is available
if ! command -v crontab &> /dev/null; then
    echo "⚠️ Cron not available, installing..."
    sudo apt update
    sudo apt install -y cron
    sudo systemctl enable cron
    sudo systemctl start cron
fi

# Create cron job entries
CRON_TEMP=$(mktemp)

# Get existing crontab
crontab -l 2>/dev/null > "$CRON_TEMP" || true

# Remove existing SOC bot entries
sed -i '/# SOC Analyst Bot/d' "$CRON_TEMP"
sed -i '/update_ioc_feeds\.sh/d' "$CRON_TEMP"
sed -i '/weekly_maintenance\.sh/d' "$CRON_TEMP"

# Add new entries
cat >> "$CRON_TEMP" << EOF

# SOC Analyst Bot - IOC Feed Updates
# Update IOC feeds daily at 2 AM
0 2 * * * cd $SCRIPT_DIR && ./update_ioc_feeds.sh

# SOC Analyst Bot - Weekly Maintenance
# Run maintenance every Sunday at 3 AM
0 3 * * 0 cd $SCRIPT_DIR && ./weekly_maintenance.sh
EOF

# Install new crontab
crontab "$CRON_TEMP"
rm "$CRON_TEMP"

echo "✅ Cron jobs installed successfully!"

# Show current cron jobs
echo ""
echo "📋 Current cron jobs:"
crontab -l | grep -A 5 -B 1 "SOC Analyst Bot"

echo ""
echo "🕐 Automated Schedule:"
echo "• IOC feeds update: Daily at 2:00 AM"
echo "• Database maintenance: Weekly on Sunday at 3:00 AM"
echo ""
echo "📝 Log files will be stored in: logs/"
echo ""

# Create IOC feeds configuration if it doesn't exist
if [ ! -f "ioc_feeds_config.json" ]; then
    echo "⚙️ Creating IOC feeds configuration..."
    python3 -c "
from ioc_feeds import IOCFeedManager
manager = IOCFeedManager()
print('IOC feeds configuration created')
"
fi

# Test the setup
echo "🧪 Testing IOC feed system..."
python3 ioc_feeds.py --list

echo ""
echo "✅ Automated IOC feed setup completed!"
echo ""
echo "🔧 Management commands:"
echo "• Manual feed update: python3 ioc_feeds.py --update"
echo "• List feeds: python3 ioc_feeds.py --list"
echo "• Enable feed: python3 ioc_feeds.py --enable <feed_name>"
echo "• Disable feed: python3 ioc_feeds.py --disable <feed_name>"
echo ""
echo "📊 To check if feeds are working:"
echo "• View logs: tail -f logs/ioc_feeds_$(date +%Y%m%d).log"
echo "• Check database: python3 manage_iocs.py --stats"
