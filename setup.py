#!/usr/bin/env python3
"""
SOC AI Agent Setup Script
Automated installation and configuration for Raspberry Pi
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

class SOCAgentSetup:
    def __init__(self):
        self.python_version = sys.version_info
        self.is_raspberry_pi = self.detect_raspberry_pi()
        self.base_dir = Path.cwd()
        
    def detect_raspberry_pi(self):
        """Detect if running on Raspberry Pi"""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                if 'Raspberry Pi' in f.read():
                    return True
        except:
            pass
        return False
    
    def check_requirements(self):
        """Check system requirements"""
        print("🔍 Checking system requirements...")
        
        # Check Python version
        if self.python_version < (3, 8):
            print("❌ Python 3.8+ required. Current version:", sys.version)
            return False
        else:
            print("✅ Python version:", sys.version.split()[0])
        
        # Check if running on Raspberry Pi
        if self.is_raspberry_pi:
            print("✅ Raspberry Pi detected")
        else:
            print("⚠️  Not running on Raspberry Pi - some optimizations may not apply")
        
        # Check available memory
        try:
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                for line in meminfo.split('\n'):
                    if 'MemTotal' in line:
                        mem_kb = int(line.split()[1])
                        mem_gb = mem_kb / 1024 / 1024
                        print(f"✅ Available RAM: {mem_gb:.1f}GB")
                        if mem_gb < 4:
                            print("⚠️  Low memory detected. Consider enabling swap.")
                        break
        except:
            print("⚠️  Could not check memory")
        
        return True
    
    def install_system_dependencies(self):
        """Install system-level dependencies"""
        print("\n📦 Installing system dependencies...")
        
        if self.is_raspberry_pi:
            # Update package list
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            
            # Install required packages
            packages = [
                'python3-pip',
                'python3-venv',
                'libmagic1',
                'sqlite3',
                'build-essential',
                'python3-dev',
                'libffi-dev',
                'libssl-dev',
                'git'
            ]
            
            for package in packages:
                print(f"Installing {package}...")
                try:
                    subprocess.run(['sudo', 'apt', 'install', '-y', package], 
                                 check=True, capture_output=True)
                    print(f"✅ {package} installed")
                except subprocess.CalledProcessError:
                    print(f"❌ Failed to install {package}")
        else:
            print("ℹ️  Please ensure the following are installed:")
            print("  - python3-pip")
            print("  - libmagic")
            print("  - sqlite3")
    
    def create_virtual_environment(self):
        """Create Python virtual environment"""
        print("\n🐍 Creating virtual environment...")
        
        venv_path = self.base_dir / 'soc_venv'
        
        if venv_path.exists():
            print("ℹ️  Virtual environment already exists")
            return str(venv_path)
        
        try:
            subprocess.run([sys.executable, '-m', 'venv', str(venv_path)], check=True)
            print("✅ Virtual environment created")
            return str(venv_path)
        except subprocess.CalledProcessError:
            print("❌ Failed to create virtual environment")
            return None
    
    def install_python_dependencies(self, venv_path):
        """Install Python dependencies"""
        print("\n📚 Installing Python dependencies...")
        
        if self.is_raspberry_pi:
            pip_path = os.path.join(venv_path, 'bin', 'pip')
        else:
            pip_path = os.path.join(venv_path, 'Scripts', 'pip')
        
        # Create requirements.txt
        requirements = [
            "python-telegram-bot==20.7",
            "python-dotenv==1.0.0",
            "requests==2.31.0",
            "transformers==4.35.2",
            "torch==2.1.1+cpu",
            "tokenizers==0.15.0",
            "python-magic==0.4.27",
            "sqlite3",  # Built-in, but just for reference
            "numpy==1.24.3",
            "asyncio",  # Built-in
            "pathlib",  # Built-in
            "hashlib",  # Built-in
            "base64",   # Built-in
            "urllib3==2.0.7"
        ]
        
        # Write requirements.txt
        with open('requirements.txt', 'w') as f:
            for req in requirements:
                if not req.endswith('Built-in'):
                    f.write(req + '\n')
        
        # Install requirements
        try:
            # Upgrade pip first
            subprocess.run([pip_path, 'install', '--upgrade', 'pip'], check=True)
            
            # Install PyTorch CPU version for Raspberry Pi
            if self.is_raspberry_pi:
                subprocess.run([
                    pip_path, 'install', 'torch==2.1.1+cpu', 
                    '-f', 'https://download.pytorch.org/whl/torch_stable.html'
                ], check=True)
            
            # Install other requirements
            subprocess.run([pip_path, 'install', '-r', 'requirements.txt'], check=True)
            print("✅ Python dependencies installed")
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install dependencies: {e}")
            return False
        
        return True
    
    def create_directory_structure(self):
        """Create necessary directories"""
        print("\n📁 Creating directory structure...")
        
        directories = [
            'temp',
            'logs',
            'data',
            'models'
        ]
        
        for directory in directories:
            dir_path = self.base_dir / directory
            dir_path.mkdir(exist_ok=True)
            print(f"✅ Created {directory}/ directory")
    
    def setup_environment_file(self):
        """Setup environment configuration"""
        print("\n⚙️  Setting up environment configuration...")
        
        env_file = self.base_dir / '.env'
        
        if env_file.exists():
            print("ℹ️  .env file already exists")
            return
        
        # Create .env from template
        env_template = """# SOC AI Agent Configuration
# Fill in your actual values below

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here

# VirusTotal API Configuration  
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# AbuseDB API Configuration
ABUSEDB_API_KEY=your_abusedb_api_key_here

# Authorized Users (Telegram User IDs - comma separated)
# To get your Telegram user ID, message @userinfobot on Telegram
AUTHORIZED_USERS=123456789,987654321

# Configuration
DATABASE_PATH=soc_database.db
LOG_LEVEL=INFO
LOG_FILE=logs/soc_agent.log
ENABLE_AUTO_DETECTION=true
ENABLE_AI_ANALYSIS=true
MAX_FILE_SIZE=100MB
"""
        
        with open(env_file, 'w') as f:
            f.write(env_template)
        
        print("✅ Created .env template file")
        print("⚠️  Please edit .env file with your API keys and user IDs")
    
    def create_systemd_service(self):
        """Create systemd service for auto-start"""
        if not self.is_raspberry_pi:
            print("ℹ️  Systemd service creation skipped (not on Raspberry Pi)")
            return
        
        print("\n🔧 Creating systemd service...")
        
        service_content = f"""[Unit]
Description=SOC AI Agent
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory={self.base_dir}
Environment=PATH={self.base_dir}/soc_venv/bin
ExecStart={self.base_dir}/soc_venv/bin/python {self.base_dir}/soc_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        
        service_file = '/tmp/soc-agent.service'
        with open(service_file, 'w') as f:
            f.write(service_content)
        
        try:
            # Copy service file
            subprocess.run(['sudo', 'cp', service_file, '/etc/systemd/system/'], check=True)
            
            # Reload systemd and enable service
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            subprocess.run(['sudo', 'systemctl', 'enable', 'soc-agent'], check=True)
            
            print("✅ Systemd service created and enabled")
            print("ℹ️  Use 'sudo systemctl start soc-agent' to start the service")
            print("ℹ️  Use 'sudo systemctl status soc-agent' to check status")
            
        except subprocess.CalledProcessError:
            print("❌ Failed to create systemd service")
    
    def download_ai_models(self, venv_path):
        """Download and cache AI models"""
        print("\n🤖 Downloading AI models...")
        
        if self.is_raspberry_pi:
            python_path = os.path.join(venv_path, 'bin', 'python')
        else:
            python_path = os.path.join(venv_path, 'Scripts', 'python')
        
        download_script = '''
import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

print("Downloading DistilBERT model...")
try:
    tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased-finetuned-sst-2-english")
    model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased-finetuned-sst-2-english")
    print("✅ DistilBERT model downloaded")
except Exception as e:
    print(f"❌ Error downloading DistilBERT: {e}")

print("Downloading DistilGPT2 model...")
try:
    from transformers import GPT2LMHeadModel, GPT2Tokenizer
    tokenizer = GPT2Tokenizer.from_pretrained("distilgpt2")
    model = GPT2LMHeadModel.from_pretrained("distilgpt2")
    print("✅ DistilGPT2 model downloaded")
except Exception as e:
    print(f"❌ Error downloading DistilGPT2: {e}")

print("Models cached successfully!")
'''
        
        try:
            result = subprocess.run([python_path, '-c', download_script], 
                                  capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                print("✅ AI models downloaded and cached")
            else:
                print("⚠️  Some models may not have downloaded correctly")
                print(result.stderr)
        except subprocess.TimeoutExpired:
            print("⚠️  Model download timed out - they will download on first use")
        except Exception as e:
            print(f"⚠️  Model download failed: {e}")
    
    def create_startup_script(self, venv_path):
        """Create startup script"""
        print("\n📜 Creating startup script...")
        
        if self.is_raspberry_pi:
            python_path = os.path.join(venv_path, 'bin', 'python')
        else:
            python_path = os.path.join(venv_path, 'Scripts', 'python')
        
        startup_script = f"""#!/bin/bash
# SOC AI Agent Startup Script

echo "Starting SOC AI Agent..."

# Activate virtual environment and run
cd {self.base_dir}
{python_path} soc_agent.py
"""
        
        script_path = self.base_dir / 'start_soc_agent.sh'
        with open(script_path, 'w') as f:
            f.write(startup_script)
        
        # Make executable
        os.chmod(script_path, 0o755)
        
        print("✅ Startup script created: start_soc_agent.sh")
    
    def run_setup(self):
        """Run complete setup process"""
        print("🛡️  SOC AI Agent Setup Starting...\n")
        
        # Check requirements
        if not self.check_requirements():
            print("❌ Requirements check failed")
            return False
        
        # Install system dependencies
        try:
            self.install_system_dependencies()
        except Exception as e:
            print(f"⚠️  System dependencies installation failed: {e}")
        
        # Create virtual environment
        venv_path = self.create_virtual_environment()
        if not venv_path:
            print("❌ Setup failed at virtual environment creation")
            return False
        
        # Install Python dependencies
        if not self.install_python_dependencies(venv_path):
            print("❌ Setup failed at Python dependencies installation")
            return False
        
        # Create directory structure
        self.create_directory_structure()
        
        # Setup environment file
        self.setup_environment_file()
        
        # Download AI models
        self.download_ai_models(venv_path)
        
        # Create startup script
        self.create_startup_script(venv_path)
        
        # Create systemd service (Raspberry Pi only)
        self.create_systemd_service()
        
        print("\n✅ Setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Edit .env file with your API keys and Telegram user IDs")
        print("2. Run: ./start_soc_agent.sh")
        print("3. Test the bot by messaging it on Telegram")
        
        if self.is_raspberry_pi:
            print("4. (Optional) Start as service: sudo systemctl start soc-agent")
        
        print("\n🔗 Required API keys:")
        print("• Telegram Bot Token: https://t.me/BotFather")
        print("• VirusTotal API: https://www.virustotal.com/gui/my-apikey")
        print("• AbuseDB API: https://www.abuseipdb.com/api")
        
        return True

def main():
    """Main setup function"""
    setup = SOCAgentSetup()
    
    print("SOC AI Agent - Automated Setup")
    print("=" * 40)
    
    try:
        success = setup.run_setup()
        if success:
            print("\n🎉 Setup completed! Your SOC AI Agent is ready.")
        else:
            print("\n❌ Setup failed. Please check the errors above.")
            return 1
    except KeyboardInterrupt:
        print("\n⚠️  Setup interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error during setup: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
