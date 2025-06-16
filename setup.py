#!/usr/bin/env python3
"""
SOC AI Agent Installation Script
Automated setup for Raspberry Pi 4
"""

import os
import sys
import subprocess
import json
import sqlite3
from pathlib import Path

def run_command(cmd, check=True):
    """Run shell command"""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    return result

def install_system_dependencies():
    """Install system packages"""
    print("📦 Installing system dependencies...")
    
    commands = [
        "sudo apt update",
        "sudo apt install -y python3-pip python3-venv git curl",
        "sudo apt install -y sqlite3 libsqlite3-dev",
        "sudo apt install -y build-essential libssl-dev libffi-dev python3-dev"
    ]
    
    for cmd in commands:
        run_command(cmd)

def install_ollama():
    """Install Ollama"""
    print("🤖 Installing Ollama...")
    
    # Check if ollama is already installed
    result = run_command("which ollama", check=False)
    if result.returncode == 0:
        print("✅ Ollama already installed")
        return
    
    # Install Ollama
    run_command("curl -fsSL https://ollama.com/install.sh | sh")
    
    # Start Ollama service
    run_command("sudo systemctl enable ollama")
    run_command("sudo systemctl start ollama")
    
    print("⏳ Waiting for Ollama to start...")
    import time
    time.sleep(10)
    
    # Pull default model
    print("📥 Downloading AI model (this may take a while)...")
    run_command("ollama pull llama2")

def create_virtual_environment():
    """Create Python virtual environment"""
    print("🐍 Creating Python virtual environment...")
    
    if not os.path.exists("venv"):
        run_command("python3 -m venv venv")
    
    # Activate venv and upgrade pip
    run_command("./venv/bin/pip install --upgrade pip")

def install_python_dependencies():
    """Install Python packages"""
    print("📚 Installing Python dependencies...")
    
    requirements = [
        "python-telegram-bot>=20.0",
        "requests>=2.28.0",
        "aiofiles>=22.1.0",
        "python-dotenv>=1.0.0",
        "cryptography>=3.4.8",
        "urllib3>=1.26.0"
    ]
    
    for req in requirements:
        run_command(f"./venv/bin/pip install {req}")

def setup_configuration():
    """Setup configuration files"""
    print("⚙️ Setting up configuration...")
    
    if not os.path.exists(".env"):
        print("Creating .env file...")
        env_content = """# SOC AI Agent Configuration
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEDB_API_KEY=your_abuseipdb_api_key_here
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama2
DATABASE_PATH=soc_agent.db
ALLOWED_USER_IDS=
LOG_LEVEL=INFO
"""
        with open(".env", "w") as f:
            f.write(env_content)
        
        print("⚠️  Please edit .env file with your API keys and configuration")

def create_service_file():
    """Create systemd service file"""
    print("🔧 Creating systemd service...")
    
    current_dir = os.getcwd()
    service_content = f"""[Unit]
Description=SOC AI Agent Telegram Bot
After=network.target ollama.service
Requires=ollama.service

[Service]
Type=simple
User=pi
WorkingDirectory={current_dir}
Environment=PATH={current_dir}/venv/bin
ExecStart={current_dir}/venv/bin/python {current_dir}/soc_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    service_path = "/etc/systemd/system/soc-agent.service"
    with open("soc-agent.service", "w") as f:
        f.write(service_content)
    
    print(f"Service file created. To install:")
    print(f"sudo cp soc-agent.service {service_path}")
    print("sudo systemctl enable soc-agent")
    print("sudo systemctl start soc-agent")

def setup_sample_iocs():
    """Create sample IOC database"""
    print("📋 Setting up sample IOC database...")
    
    sample_iocs = [
        {
            "indicator": "127.0.0.1",
            "type": "ip",
            "description": "Localhost - Safe IP",
            "threat_type": "safe",
            "source": "system",
            "confidence": 100
        },
        {
            "indicator": "malware.com",
            "type": "domain",
            "description": "Known malware distribution domain",
            "threat_type": "malware",
            "source": "threat_intel",
            "confidence": 95
        },
        {
            "indicator": "d41d8cd98f00b204e9800998ecf8427e",
            "type": "md5",
            "description": "Empty file hash",
            "threat_type": "safe",
            "source": "system",
            "confidence": 100
        }
    ]
    
    # Initialize database
    conn = sqlite3.connect("soc_agent.db")
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            threat_type TEXT,
            source TEXT,
            confidence INTEGER DEFAULT 50,
            metadata TEXT DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            indicator TEXT NOT NULL,
            analysis_type TEXT NOT NULL,
            results TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add metadata column if it doesn't exist (for upgrades)
    try:
        cursor.execute('ALTER TABLE iocs ADD COLUMN metadata TEXT DEFAULT "{}"')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    for ioc in sample_iocs:
        cursor.execute('''
            INSERT OR REPLACE INTO iocs 
            (indicator, type, description, threat_type, source, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ioc['indicator'], ioc['type'], ioc['description'], 
              ioc['threat_type'], ioc['source'], ioc['confidence']))
    
    conn.commit()
    conn.close()
    
    print("✅ Sample IOCs loaded")

def create_ioc_import_script():
    """Create IOC import utility"""
    print("📥 Creating IOC import utility...")
    
    import_script = '''#!/usr/bin/env python3
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
'''
    
    with open("import_iocs.py", "w") as f:
        f.write(import_script)
    
    os.chmod("import_iocs.py", 0o755)

def check_requirements():
    """Check system requirements"""
    print("🔍 Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        sys.exit(1)
    
    # Check available memory
    try:
        with open('/proc/meminfo', 'r') as f:
            meminfo = f.read()
        mem_total_kb = int([line for line in meminfo.split('\n') if 'MemTotal' in line][0].split()[1])
        mem_total_gb = mem_total_kb / 1024 / 1024
        
        if mem_total_gb < 4:
            print("⚠️  Warning: Less than 4GB RAM detected. Performance may be limited.")
        else:
            print(f"✅ Memory check passed: {mem_total_gb:.1f}GB")
    except:
        print("⚠️  Could not check memory")
    
    # Check architecture
    import platform
    arch = platform.machine()
    if arch not in ['aarch64', 'armv7l', 'x86_64']:
        print(f"⚠️  Untested architecture: {arch}")
    else:
        print(f"✅ Architecture: {arch}")

def main():
    """Main installation function"""
    print("🛡️  SOC AI Agent Installation")
    print("=============================")
    
    try:
        check_requirements()
        install_system_dependencies()
        create_virtual_environment()
        install_python_dependencies()
        install_ollama()
        setup_configuration()
        setup_sample_iocs()
        create_ioc_import_script()
        create_service_file()
        
        print("\n✅ Installation completed successfully!")
        print("\n📝 Next steps:")
        print("1. Edit .env file with your API keys:")
        print("   - Get Telegram bot token from @BotFather")
        print("   - Get VirusTotal API key from virustotal.com")
        print("   - Get AbuseIPDB API key from abuseipdb.com")
        print("   - Add your Telegram user ID to ALLOWED_USER_IDS")
        
        print("\n2. Test the installation:")
        print("   ./venv/bin/python soc_agent.py")
        
        print("\n3. Install as service (optional):")
        print("   sudo cp soc-agent.service /etc/systemd/system/")
        print("   sudo systemctl enable soc-agent")
        print("   sudo systemctl start soc-agent")
        
        print("\n4. Import IOCs:")
        print("   python import_iocs.py your_ioc_file.csv")
        
        print("\n🎉 Your SOC AI Agent is ready!")
        
    except KeyboardInterrupt:
        print("\n❌ Installation cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Installation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
