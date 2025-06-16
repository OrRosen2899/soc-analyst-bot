#!/usr/bin/env python3
"""
SOC AI Agent - Telegram Bot for Security Analysis
Combines VirusTotal, AbuseIPDB, and Ollama AI for comprehensive threat analysis
"""

import os
import json
import sqlite3
import hashlib
import ipaddress
import re
import csv
import requests
import asyncio
import aiofiles
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse
import base64

import telegram
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackQueryHandler, ContextTypes
from telegram.constants import ParseMode

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class SOCAgent:
    def __init__(self):
        # Load environment variables
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abusedb_api_key = os.getenv('ABUSEDB_API_KEY')
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'llama2')
        self.db_path = os.getenv('DATABASE_PATH', 'soc_agent.db')
        self.allowed_users = [int(x) for x in os.getenv('ALLOWED_USER_IDS', '').split(',') if x.strip()]
        
        # Initialize database
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for IOCs"""
        conn = sqlite3.connect(self.db_path)
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
        
        conn.commit()
        conn.close()
        
    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized"""
        if not self.allowed_users:
            return True  # If no restriction, allow all
        return user_id in self.allowed_users
        
    def detect_indicator_type(self, indicator: str) -> str:
        """Detect the type of indicator"""
        indicator = indicator.strip()
        
        # Hash detection
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):
            return 'md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', indicator):
            return 'sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', indicator):
            return 'sha256'
        
        # IP detection
        try:
            ipaddress.ip_address(indicator)
            return 'ip'
        except ValueError:
            pass
            
        # URL detection
        if indicator.startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        elif '.' in indicator and not ' ' in indicator:
            return 'domain'
            
        return 'unknown'
        
    async def check_virustotal(self, indicator: str, indicator_type: str) -> Dict:
        """Check indicator against VirusTotal"""
        if not self.vt_api_key:
            return {'error': 'VirusTotal API key not configured'}
            
        headers = {'x-apikey': self.vt_api_key}
        base_url = 'https://www.virustotal.com/api/v3'
        
        try:
            if indicator_type in ['md5', 'sha1', 'sha256']:
                url = f"{base_url}/files/{indicator}"
            elif indicator_type == 'ip':
                url = f"{base_url}/ip_addresses/{indicator}"
            elif indicator_type == 'domain':
                url = f"{base_url}/domains/{indicator}"
            elif indicator_type == 'url':
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip('=')
                url = f"{base_url}/urls/{url_id}"
            else:
                return {'error': f'Unsupported indicator type for VirusTotal: {indicator_type}'}
                
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {'error': 'Not found in VirusTotal database'}
            else:
                return {'error': f'VirusTotal API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'VirusTotal request failed: {str(e)}'}
            
    async def check_abuseipdb(self, indicator: str, indicator_type: str) -> Dict:
        """Check IP against AbuseIPDB"""
        if not self.abusedb_api_key or indicator_type != 'ip':
            return {'error': 'AbuseIPDB only supports IP addresses'}
            
        headers = {
            'Key': self.abusedb_api_key,
            'Accept': 'application/json'
        }
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {
                'ipAddress': indicator,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'AbuseIPDB API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': f'AbuseIPDB request failed: {str(e)}'}
            
    async def check_local_iocs(self, indicator: str) -> List[Dict]:
        """Check indicator against local IOC database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT indicator, type, description, threat_type, source, confidence, metadata, created_at
            FROM iocs 
            WHERE indicator = ? OR indicator LIKE ?
        ''', (indicator, f'%{indicator}%'))
        
        results = []
        for row in cursor.fetchall():
            metadata = {}
            try:
                metadata = json.loads(row[6] or '{}')
            except (json.JSONDecodeError, TypeError):
                metadata = {}
                
            results.append({
                'indicator': row[0],
                'type': row[1],
                'description': row[2],
                'threat_type': row[3],
                'source': row[4],
                'confidence': row[5],
                'metadata': metadata,
                'created_at': row[7]
            })
            
        conn.close()
        return results
        
    async def analyze_with_ollama(self, indicator: str, indicator_type: str, context_data: Dict) -> str:
        """Analyze indicator using Ollama AI"""
        try:
            prompt = f"""
            As a cybersecurity analyst, analyze this {indicator_type}: {indicator}
            
            Context from threat intelligence:
            {json.dumps(context_data, indent=2)}
            
            Provide a comprehensive security analysis including:
            1. Risk assessment (High/Medium/Low)
            2. Potential threats or legitimate uses
            3. Recommended actions
            4. Key indicators of compromise
            
            Keep the response concise but informative.
            """
            
            payload = {
                'model': self.ollama_model,
                'prompt': prompt,
                'stream': False
            }
            
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json().get('response', 'No analysis available')
            else:
                return f"AI analysis unavailable (Error: {response.status_code})"
                
        except Exception as e:
            return f"AI analysis failed: {str(e)}"
            
    def save_analysis(self, user_id: int, indicator: str, analysis_type: str, results: Dict):
        """Save analysis to history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_history (user_id, indicator, analysis_type, results)
            VALUES (?, ?, ?, ?)
        ''', (user_id, indicator, analysis_type, json.dumps(results)))
        
        conn.commit()
        conn.close()
        
    def format_analysis_result(self, indicator: str, indicator_type: str, vt_result: Dict, 
                             abuse_result: Dict, local_iocs: List[Dict], ai_analysis: str) -> str:
        """Format comprehensive analysis results"""
        result = f"🔍 **Analysis Report**\n"
        result += f"**Indicator:** `{indicator}`\n"
        result += f"**Type:** {indicator_type.upper()}\n"
        result += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # VirusTotal Results
        result += "🦠 **VirusTotal Analysis:**\n"
        if 'error' in vt_result:
            result += f"❌ {vt_result['error']}\n"
        else:
            data = vt_result.get('data', {})
            attributes = data.get('attributes', {})
            
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                result += f"🚨 Detection: {malicious}/{total} engines flagged as malicious\n"
                
            if 'reputation' in attributes:
                result += f"📊 Reputation Score: {attributes['reputation']}\n"
                
        result += "\n"
        
        # AbuseIPDB Results
        if indicator_type == 'ip':
            result += "🚫 **AbuseIPDB Analysis:**\n"
            if 'error' in abuse_result:
                result += f"❌ {abuse_result['error']}\n"
            else:
                data = abuse_result.get('data', {})
                confidence = data.get('abuseConfidencePercentage', 0)
                result += f"⚠️ Abuse Confidence: {confidence}%\n"
                result += f"🏠 Country: {data.get('countryCode', 'Unknown')}\n"
                result += f"🏢 ISP: {data.get('isp', 'Unknown')}\n"
            result += "\n"
            
        # Local IOCs
        result += "📋 **Local IOC Database:**\n"
        if local_iocs:
            for ioc in local_iocs[:3]:  # Limit to 3 results
                result += f"⚠️ Match found: {ioc['threat_type']} (Confidence: {ioc['confidence']}%)\n"
                result += f"   Source: {ioc['source']}\n"
                
                # Show malware feed metadata if available
                metadata = ioc.get('metadata', {})
                if metadata and isinstance(metadata, dict):
                    if metadata.get('file_name'):
                        result += f"   📄 File: {metadata['file_name']}\n"
                    if metadata.get('file_type_guess'):
                        result += f"   📁 Type: {metadata['file_type_guess']}\n"
                    if metadata.get('signature'):
                        result += f"   🔍 Signature: {metadata['signature']}\n"
                    if metadata.get('vtpercent'):
                        result += f"   🦠 VT Detection: {metadata['vtpercent']}\n"
                    if metadata.get('first_seen_utc'):
                        result += f"   📅 First Seen: {metadata['first_seen_utc']}\n"
        else:
            result += "✅ No matches in local IOC database\n"
        result += "\n"
        
        # AI Analysis
        result += "🤖 **AI Security Analysis:**\n"
        result += ai_analysis
        
        return result
        
    def load_iocs_from_file(self, file_path: str, source: str = "manual_upload") -> int:
        """Load IOCs from CSV file with support for malware analysis format"""
        loaded_count = 0
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # Try to detect if it's CSV
                sample = file.read(1024)
                file.seek(0)
                
                if ',' in sample or '\t' in sample:
                    # Detect delimiter
                    delimiter = ',' if ',' in sample else '\t'
                    reader = csv.DictReader(file, delimiter=delimiter)
                    
                    for row in reader:
                        # Handle malware analysis feed format
                        if 'sha256_hash' in row or 'md5_hash' in row or 'sha1_hash' in row:
                            loaded_count += self._process_malware_feed_row(row, cursor, source)
                        # Handle standard IOC format
                        elif 'indicator' in row:
                            loaded_count += self._process_standard_ioc_row(row, cursor, source)
                        else:
                            # Try to auto-detect format
                            loaded_count += self._process_generic_row(row, cursor, source)
                            
                else:
                    # Plain text file, one indicator per line
                    for line in file:
                        indicator = line.strip()
                        if not indicator or indicator.startswith('#'):
                            continue
                            
                        ioc_type = self.detect_indicator_type(indicator)
                        try:
                            cursor.execute('''
                                INSERT OR REPLACE INTO iocs 
                                (indicator, type, description, threat_type, source, confidence, metadata)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (indicator, ioc_type, f"Imported from {source}", "malware", source, 50, "{}"))
                            loaded_count += 1
                        except sqlite3.Error:
                            continue
                            
            conn.commit()
            
        except Exception as e:
            logger.error(f"Error loading IOCs: {e}")
            
        finally:
            conn.close()
            
        return loaded_count
    
    def _process_malware_feed_row(self, row: Dict, cursor, source: str) -> int:
        """Process malware analysis feed row format"""
        loaded_count = 0
        
        # Extract metadata
        metadata = {
            'first_seen_utc': row.get('first_seen_utc', ''),
            'reporter': row.get('reporter', ''),
            'file_name': row.get('file_name', ''),
            'file_type_guess': row.get('file_type_guess', ''),
            'mime_type': row.get('mime_type', ''),
            'signature': row.get('signature', ''),
            'clamav': row.get('clamav', ''),
            'vtpercent': row.get('vtpercent', ''),
            'imphash': row.get('imphash', ''),
            'ssdeep': row.get('ssdeep', ''),
            'tlsh': row.get('tlsh', '')
        }
        
        # Create description from available data
        file_name = row.get('file_name', 'unknown_file')
        file_type = row.get('file_type_guess', row.get('mime_type', 'unknown'))
        signature = row.get('signature', '')
        
        description_parts = [f"File: {file_name}"]
        if file_type != 'unknown':
            description_parts.append(f"Type: {file_type}")
        if signature:
            description_parts.append(f"Signature: {signature}")
            
        description = " | ".join(description_parts)
        
        # Determine confidence from VT percentage if available
        confidence = 75  # Default confidence
        try:
            vt_percent = row.get('vtpercent', '')
            if vt_percent and vt_percent != '':
                vt_val = float(vt_percent.strip('%'))
                confidence = min(95, max(50, int(vt_val)))
        except (ValueError, TypeError):
            pass
        
        # Process each hash type
        hash_types = ['sha256_hash', 'md5_hash', 'sha1_hash']
        for hash_field in hash_types:
            hash_value = row.get(hash_field, '').strip()
            if hash_value and hash_value.lower() not in ['', 'null', 'none', 'n/a']:
                hash_type = hash_field.replace('_hash', '')
                
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO iocs 
                        (indicator, type, description, threat_type, source, confidence, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (hash_value, hash_type, description, "malware", source, confidence, json.dumps(metadata)))
                    loaded_count += 1
                except sqlite3.Error as e:
                    logger.error(f"Error inserting {hash_type} hash {hash_value}: {e}")
                    continue
        
        return loaded_count
    
    def _process_standard_ioc_row(self, row: Dict, cursor, source: str) -> int:
        """Process standard IOC format"""
        indicator = row.get('indicator', '').strip()
        if not indicator:
            return 0
            
        ioc_type = self.detect_indicator_type(indicator)
        description = row.get('description', '')
        threat_type = row.get('threat_type', 'unknown')
        confidence = int(row.get('confidence', 50))
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO iocs 
                (indicator, type, description, threat_type, source, confidence, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (indicator, ioc_type, description, threat_type, source, confidence, "{}"))
            return 1
        except sqlite3.Error:
            return 0
    
    def _process_generic_row(self, row: Dict, cursor, source: str) -> int:
        """Process generic row by trying to find hash-like values"""
        loaded_count = 0
        
        for key, value in row.items():
            value = str(value).strip()
            if not value or value.lower() in ['', 'null', 'none', 'n/a']:
                continue
                
            ioc_type = self.detect_indicator_type(value)
            if ioc_type != 'unknown':
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO iocs 
                        (indicator, type, description, threat_type, source, confidence, metadata)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (value, ioc_type, f"Extracted from field: {key}", "unknown", source, 50, json.dumps({key: value})))
                    loaded_count += 1
                except sqlite3.Error:
                    continue
                    
        return loaded_count

# Bot Handlers
soc_agent = SOCAgent()

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command handler"""
    if not soc_agent.is_authorized(update.effective_user.id):
        await update.message.reply_text("❌ Unauthorized access")
        return
        
    keyboard = [
        [InlineKeyboardButton("🔍 Analyze Indicator", callback_data="analyze")],
        [InlineKeyboardButton("📊 Analysis History", callback_data="history")],
        [InlineKeyboardButton("📋 IOC Stats", callback_data="stats")],
        [InlineKeyboardButton("ℹ️ Help", callback_data="help")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = """
🛡️ **SOC AI Agent**

Welcome to your personal Security Operations Center!

I can analyze:
• 🌐 URLs and Domains
• 📄 File Hashes (MD5, SHA1, SHA256)
• 🌍 IP Addresses
• 📝 Scripts and Code

**Features:**
✅ VirusTotal Integration
✅ AbuseIPDB Lookup
✅ Local IOC Database
✅ AI-Powered Analysis
✅ Threat Intelligence

Send me any indicator to analyze, or use the buttons below.
"""
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle incoming messages with indicators"""
    if not soc_agent.is_authorized(update.effective_user.id):
        await update.message.reply_text("❌ Unauthorized access")
        return
        
    indicator = update.message.text.strip()
    indicator_type = soc_agent.detect_indicator_type(indicator)
    
    if indicator_type == 'unknown':
        await update.message.reply_text(
            "❓ Could not detect indicator type. Please send:\n"
            "• URL (http://example.com)\n"
            "• IP address (192.168.1.1)\n"
            "• Domain (example.com)\n"
            "• File hash (MD5/SHA1/SHA256)"
        )
        return
        
    # Show typing action
    await update.message.reply_chat_action("typing")
    
    # Send initial message
    analysis_msg = await update.message.reply_text(
        f"🔍 Analyzing {indicator_type.upper()}: `{indicator}`\n\n⏳ Please wait...",
        parse_mode=ParseMode.MARKDOWN
    )
    
    try:
        # Perform all checks concurrently
        vt_task = soc_agent.check_virustotal(indicator, indicator_type)
        abuse_task = soc_agent.check_abuseipdb(indicator, indicator_type)
        local_task = soc_agent.check_local_iocs(indicator)
        
        vt_result, abuse_result, local_iocs = await asyncio.gather(vt_task, abuse_task, local_task)
        
        # Prepare context for AI analysis
        context_data = {
            'virustotal': vt_result,
            'abuseipdb': abuse_result,
            'local_iocs': local_iocs
        }
        
        # Get AI analysis
        ai_analysis = await soc_agent.analyze_with_ollama(indicator, indicator_type, context_data)
        
        # Format and send results
        result_text = soc_agent.format_analysis_result(
            indicator, indicator_type, vt_result, abuse_result, local_iocs, ai_analysis
        )
        
        # Save to history
        soc_agent.save_analysis(update.effective_user.id, indicator, indicator_type, context_data)
        
        # Update message with results
        await analysis_msg.edit_text(result_text, parse_mode=ParseMode.MARKDOWN)
        
    except Exception as e:
        await analysis_msg.edit_text(f"❌ Analysis failed: {str(e)}")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle button callbacks"""
    query = update.callback_query
    await query.answer()
    
    if not soc_agent.is_authorized(query.from_user.id):
        await query.edit_message_text("❌ Unauthorized access")
        return
    
    if query.data == "analyze":
        await query.edit_message_text(
            "🔍 **Send me an indicator to analyze:**\n\n"
            "• URL: `https://example.com`\n"
            "• IP: `192.168.1.1`\n"
            "• Domain: `example.com`\n"
            "• Hash: `d41d8cd98f00b204e9800998ecf8427e`\n\n"
            "Just type or paste it in the chat!",
            parse_mode=ParseMode.MARKDOWN
        )
    elif query.data == "help":
        help_text = """
🛡️ **SOC AI Agent Help**

**Supported Indicators:**
• 🌐 URLs and domains
• 🌍 IP addresses (IPv4/IPv6)
• 📄 File hashes (MD5, SHA1, SHA256)

**Commands:**
• Send any indicator to analyze it
• `/start` - Show main menu
• `/stats` - Show IOC database statistics

**Analysis Sources:**
• VirusTotal - Malware detection
• AbuseIPDB - IP reputation
• Local IOCs - Custom threat intelligence
• AI Analysis - Contextual assessment

**Features:**
✅ Real-time threat analysis
✅ Historical tracking
✅ Risk assessment
✅ Actionable recommendations

For support, contact your administrator.
"""
        await query.edit_message_text(help_text, parse_mode=ParseMode.MARKDOWN)
        
    elif query.data == "stats":
        conn = sqlite3.connect(soc_agent.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total_iocs = cursor.fetchone()[0]
        
        cursor.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type")
        type_counts = cursor.fetchall()
        
        cursor.execute("SELECT COUNT(*) FROM analysis_history WHERE user_id = ?", (query.from_user.id,))
        user_analyses = cursor.fetchone()[0]
        
        conn.close()
        
        stats_text = f"""
📊 **Database Statistics**

**IOC Database:**
• Total IOCs: {total_iocs}

**By Type:**
"""
        for ioc_type, count in type_counts:
            stats_text += f"• {ioc_type.upper()}: {count}\n"
            
        stats_text += f"\n**Your Activity:**\n• Analyses performed: {user_analyses}"
        
        await query.edit_message_text(stats_text, parse_mode=ParseMode.MARKDOWN)

def main():
    """Main function to run the bot"""
    if not soc_agent.bot_token:
        print("❌ TELEGRAM_BOT_TOKEN not found in environment variables")
        return
        
    print("🛡️ Starting SOC AI Agent...")
    print(f"📊 Database: {soc_agent.db_path}")
    print(f"🤖 Ollama: {soc_agent.ollama_url}")
    print(f"🔑 APIs configured: VT={bool(soc_agent.vt_api_key)}, AbuseDB={bool(soc_agent.abusedb_api_key)}")
    
    # Create application
    application = Application.builder().token(soc_agent.bot_token).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    # Start bot
    print("✅ SOC AI Agent is running!")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
