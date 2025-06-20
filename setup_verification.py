#!/usr/bin/env python3
"""
Setup script for SOC AI Agent Verification System
"""

import os
import secrets
import sqlite3
from pathlib import Path

def generate_secure_code():
    """Generate a secure verification code"""
    words = ['Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot']
    numbers = secrets.randbelow(9999)
    word = secrets.choice(words)
    return f"SOC{word}{numbers:04d}"

def setup_environment():
    """Setup environment file with secure defaults"""
    env_file = Path('.env')
    
    if env_file.exists():
        print("📄 .env file already exists")
        choice = input("Do you want to update verification settings? (y/N): ")
        if choice.lower() != 'y':
            return
    
    print("🔐 Setting up Secure SOC AI Agent")
    print("=" * 50)
    
    # Get existing values or defaults
    existing_env = {}
    if env_file.exists():
        with open(env_file, 'r') as f:
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    key, value = line.strip().split('=', 1)
                    existing_env[key] = value
    
    # Bot token
    bot_token = input(f"Telegram Bot Token [{existing_env.get('TELEGRAM_BOT_TOKEN', 'your_bot_token_here')}]: ").strip()
    if not bot_token:
        bot_token = existing_env.get('TELEGRAM_BOT_TOKEN', 'your_bot_token_here')
    
    # Verification code
    current_code = existing_env.get('VERIFICATION_CODE', '')
    suggested_code = generate_secure_code()
    print(f"\nCurrent verification code: {current_code}")
    print(f"Suggested new code: {suggested_code}")
    verification_code = input(f"Verification Code [{suggested_code}]: ").strip()
    if not verification_code:
        verification_code = suggested_code
    
    # Admin user ID
    admin_id = input(f"Your Telegram User ID (admin) [{existing_env.get('ADMIN_USER_IDS', 'your_admin_user_id')}]: ").strip()
    if not admin_id:
        admin_id = existing_env.get('ADMIN_USER_IDS', 'your_admin_user_id')
    
    # Admin approval setting
    approval_required = input("Require admin approval for new users? (Y/n): ").strip().lower()
    admin_approval = 'false' if approval_required == 'n' else 'true'
    
    # API Keys
    vt_key = input(f"VirusTotal API Key [{existing_env.get('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key')}]: ").strip()
    if not vt_key:
        vt_key = existing_env.get('VIRUSTOTAL_API_KEY', 'your_virustotal_api_key')
    
    abuse_key = input(f"AbuseIPDB API Key [{existing_env.get('ABUSEDB_API_KEY', 'your_abusedb_api_key')}]: ").strip()
    if not abuse_key:
        abuse_key = existing_env.get('ABUSEDB_API_KEY', 'your_abusedb_api_key')
    
    # Create .env file
    env_content = f"""# SOC AI Agent - Secure Configuration

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN={bot_token}

# Security & Verification Settings
VERIFICATION_CODE={verification_code}
ADMIN_APPROVAL={admin_approval}
VERIFICATION_TIMEOUT=300

# User Access Control
ALLOWED_USER_IDS=
ADMIN_USER_IDS={admin_id}

# API Keys
VIRUSTOTAL_API_KEY={vt_key}
ABUSEDB_API_KEY={abuse_key}

# AI Configuration
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=phi3.5

# Database
DATABASE_PATH=soc_agent_secure.db

# Additional Security Settings
MAX_VERIFICATION_ATTEMPTS=5
SESSION_TIMEOUT=86400
LOG_LEVEL=INFO
ENABLE_AUDIT_LOG=true
"""
    
    with open('.env', 'w') as f:
        f.write(env_content)
    
    print("\n✅ Environment configured successfully!")
    print(f"🔑 Verification Code: {verification_code}")
    print(f"👑 Admin User ID: {admin_id}")
    print(f"📝 Admin Approval: {'Enabled' if admin_approval == 'true' else 'Disabled'}")

def setup_database():
    """Initialize the secure database"""
    print("\n🗄️ Initializing secure database...")
    
    try:
        conn = sqlite3.connect('soc_agent_secure.db')
        cursor = conn.cursor()
        
        # Create IOCs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL,
                description TEXT,
                threat_type TEXT,
                source TEXT,
                confidence INTEGER DEFAULT 50,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create verified users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verified_users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                verification_code TEXT,
                verification_method TEXT,
                verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_by INTEGER,
                access_level TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active',
                last_activity TIMESTAMP,
                session_token TEXT
            )
        ''')
        
        # Create verification attempts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                attempt_type TEXT,
                attempt_data TEXT,
                success BOOLEAN,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT
            )
        ''')
        
        # Create pending approvals table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                first_name TEXT,
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verification_code TEXT,
                status TEXT DEFAULT 'pending'
            )
        ''')
        
        conn.commit()
        conn.close()
        
        print("✅ Database initialized with all tables")
        
        # Test table creation
        conn = sqlite3.connect('soc_agent_secure.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        conn.close()
        
        print("📋 Created tables:")
        for table in tables:
            print(f"   - {table[0]}")
            
        return True
        
    except Exception as e:
        print(f"❌ Database initialization error: {e}")
        return False

def add_admin_user():
    """Add an admin user directly to the database"""
    # Check if database exists and has tables
    if not os.path.exists('soc_agent_secure.db'):
        print("❌ Database not found. Please initialize database first (Option 2).")
        return
    
    try:
        # Check if tables exist
        conn = sqlite3.connect('soc_agent_secure.db')
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='verified_users';")
        if not cursor.fetchone():
            print("❌ Database tables not found. Please initialize database first (Option 2).")
            conn.close()
            return
        conn.close()
        
        user_id = input("Enter admin Telegram User ID: ").strip()
        username = input("Enter admin username (optional): ").strip()
        name = input("Enter admin name: ").strip()
        
        if not user_id or not user_id.isdigit():
            print("❌ Invalid user ID")
            return
        
        conn = sqlite3.connect('soc_agent_secure.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO verified_users 
            (user_id, username, first_name, verification_method, access_level, session_token)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (int(user_id), username, name, 'manual_admin', 'admin', secrets.token_urlsafe(32)))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Admin user {user_id} ({name}) added successfully")
        print(f"👑 Access Level: Admin")
        print(f"🔐 Status: Active")
        
    except Exception as e:
        print(f"❌ Error adding admin user: {e}")
        print("💡 Try initializing the database first (Option 2)")

def show_verification_stats():
    """Show current verification statistics"""
    if not os.path.exists('soc_agent_secure.db'):
        print("❌ Database not found. Please initialize database first (Option 2).")
        return
    
    try:
        conn = sqlite3.connect('soc_agent_secure.db')
        cursor = conn.cursor()
        
        # Check if tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='verified_users';")
        if not cursor.fetchone():
            print("❌ Database tables not found. Please initialize database first (Option 2).")
            conn.close()
            return
        
        # Verified users
        cursor.execute('SELECT COUNT(*) FROM verified_users WHERE status = "active"')
        verified_count = cursor.fetchone()[0]
        
        # Pending approvals
        cursor.execute('SELECT COUNT(*) FROM pending_approvals WHERE status = "pending"')
        pending_count = cursor.fetchone()[0]
        
        # Recent attempts
        cursor.execute('SELECT COUNT(*) FROM verification_attempts WHERE timestamp > datetime("now", "-24 hours")')
        recent_attempts = cursor.fetchone()[0]
        
        print("\n📊 Verification Statistics:")
        print("-" * 30)
        print(f"✅ Verified Users: {verified_count}")
        print(f"⏳ Pending Approvals: {pending_count}")
        print(f"🔍 Recent Attempts (24h): {recent_attempts}")
        
        # Show recent verified users
        cursor.execute('''
            SELECT username, first_name, verified_at, access_level 
            FROM verified_users 
            WHERE status = "active" 
            ORDER BY verified_at DESC 
            LIMIT 5
        ''')
        
        recent_users = cursor.fetchall()
        if recent_users:
            print(f"\n👥 Recent Verified Users:")
            for username, name, verified_at, level in recent_users:
                print(f"   {name} (@{username or 'N/A'}) - {level} - {verified_at}")
        else:
            print(f"\n👥 No verified users found.")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error getting stats: {e}")
        print("💡 Try initializing the database first (Option 2)")

def main():
    """Main setup menu"""
    while True:
        print("\n🛡️ SOC AI Agent - Verification Setup")
        print("=" * 40)
        print("1. 🔧 Setup Environment (.env)")
        print("2. 🗄️ Initialize Database")
        print("3. 👑 Add Admin User")
        print("4. 📊 Show Statistics")
        print("5. 🚪 Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            setup_environment()
        elif choice == '2':
            setup_database()
        elif choice == '3':
            add_admin_user()
        elif choice == '4':
            show_verification_stats()
        elif choice == '5':
            print("👋 Setup complete!")
            break
        else:
            print("❌ Invalid option")

if __name__ == '__main__':
    main()
