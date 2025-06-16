import os
import logging
import asyncio
import hashlib
import requests
import json
import re
import socket
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import tempfile
import magic
import yara

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, 
    CallbackQueryHandler, ContextTypes, filters
)
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class SOCAnalyzer:
    def __init__(self):
        self.ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'llama2')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.max_file_size = 50 * 1024 * 1024  # 50MB
        
    async def analyze_with_ollama(self, prompt: str) -> str:
        """Analyze data using Ollama LLM"""
        try:
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False
            }
            
            response = requests.post(
                f"{self.ollama_base_url}/api/generate",
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                return response.json().get('response', 'No response from AI')
            else:
                return f"❌ AI analysis failed: {response.status_code}"
                
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")
            return f"❌ AI analysis error: {str(e)}"
    
    async def analyze_hash(self, hash_value: str) -> Dict:
        """Analyze file hash"""
        hash_type = self.detect_hash_type(hash_value)
        result = {
            'type': 'hash',
            'value': hash_value,
            'hash_type': hash_type,
            'status': 'unknown',
            'details': [],
            'recommendations': []
        }
        
        # VirusTotal lookup if API key available
        if self.virustotal_api_key and hash_type in ['md5', 'sha1', 'sha256']:
            vt_result = await self.virustotal_hash_lookup(hash_value)
            if vt_result:
                result.update(vt_result)
        
        # AI analysis
        ai_prompt = f"""
        As a cybersecurity expert, analyze this {hash_type} hash: {hash_value}
        
        Please provide:
        1. Risk assessment (Clean/Suspicious/Malicious)
        2. Potential threat indicators
        3. Recommended actions
        4. Additional investigation steps
        
        Be concise and actionable.
        """
        
        ai_analysis = await self.analyze_with_ollama(ai_prompt)
        result['ai_analysis'] = ai_analysis
        
        return result
    
    async def analyze_ip(self, ip_address: str) -> Dict:
        """Analyze IP address"""
        result = {
            'type': 'ip',
            'value': ip_address,
            'status': 'unknown',
            'details': [],
            'recommendations': []
        }
        
        # Basic IP validation and info
        try:
            socket.inet_aton(ip_address)
            result['valid'] = True
            
            # Check if private IP
            if self.is_private_ip(ip_address):
                result['scope'] = 'private'
                result['status'] = 'clean'
            else:
                result['scope'] = 'public'
                
        except socket.error:
            result['valid'] = False
            result['status'] = 'invalid'
            return result
        
        # AI analysis
        ai_prompt = f"""
        As a cybersecurity expert, analyze this IP address: {ip_address}
        
        Please provide:
        1. Risk assessment (Clean/Suspicious/Malicious)
        2. Potential threats (if any)
        3. Recommended actions
        4. Investigation steps
        
        Consider common threat indicators for IP addresses.
        """
        
        ai_analysis = await self.analyze_with_ollama(ai_prompt)
        result['ai_analysis'] = ai_analysis
        
        return result
    
    async def analyze_url(self, url: str) -> Dict:
        """Analyze URL"""
        result = {
            'type': 'url',
            'value': url,
            'status': 'unknown',
            'details': [],
            'recommendations': []
        }
        
        # Parse URL
        try:
            parsed = urlparse(url)
            result['domain'] = parsed.netloc
            result['scheme'] = parsed.scheme
            result['path'] = parsed.path
        except Exception as e:
            result['error'] = f"URL parsing failed: {e}"
            return result
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-zA-Z0-9]{20,}',  # Long random strings
            r'download|install|update|security|urgent|verify'  # Common phishing words
        ]
        
        suspicious_found = []
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_found.append(pattern)
        
        if suspicious_found:
            result['suspicious_patterns'] = suspicious_found
            result['status'] = 'suspicious'
        
        # AI analysis
        ai_prompt = f"""
        As a cybersecurity expert, analyze this URL: {url}
        
        Please provide:
        1. Risk assessment (Clean/Suspicious/Malicious)
        2. Potential threats (phishing, malware, etc.)
        3. Recommended actions
        4. Safe browsing tips
        
        Look for suspicious patterns, domain reputation, and common threat indicators.
        """
        
        ai_analysis = await self.analyze_with_ollama(ai_prompt)
        result['ai_analysis'] = ai_analysis
        
        return result
    
    async def analyze_file(self, file_path: str, filename: str) -> Dict:
        """Analyze uploaded file"""
        result = {
            'type': 'file',
            'filename': filename,
            'status': 'unknown',
            'details': [],
            'recommendations': []
        }
        
        try:
            # File basic info
            file_size = os.path.getsize(file_path)
            result['size'] = file_size
            
            if file_size > self.max_file_size:
                result['error'] = 'File too large for analysis'
                return result
            
            # File type detection
            file_type = magic.from_file(file_path, mime=True)
            result['mime_type'] = file_type
            
            # Calculate hashes
            with open(file_path, 'rb') as f:
                content = f.read()
                result['md5'] = hashlib.md5(content).hexdigest()
                result['sha256'] = hashlib.sha256(content).hexdigest()
            
            # Basic file analysis
            if file_type.startswith('text/'):
                # Text file analysis
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text_content = f.read()[:5000]  # First 5KB
                
                ai_prompt = f"""
                As a cybersecurity expert, analyze this text file content:
                
                Filename: {filename}
                Type: {file_type}
                Size: {file_size} bytes
                
                Content preview:
                {text_content}
                
                Please provide:
                1. Risk assessment (Clean/Suspicious/Malicious)
                2. Potential threats
                3. Recommended actions
                4. Code analysis (if applicable)
                """
                
            else:
                # Binary file analysis
                ai_prompt = f"""
                As a cybersecurity expert, analyze this file:
                
                Filename: {filename}
                Type: {file_type}
                Size: {file_size} bytes
                MD5: {result['md5']}
                SHA256: {result['sha256']}
                
                Please provide:
                1. Risk assessment (Clean/Suspicious/Malicious)
                2. Potential threats based on file type and metadata
                3. Recommended actions
                4. Investigation steps
                """
            
            ai_analysis = await self.analyze_with_ollama(ai_prompt)
            result['ai_analysis'] = ai_analysis
            
        except Exception as e:
            result['error'] = f"File analysis failed: {e}"
        
        return result
    
    def detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length"""
        hash_length = len(hash_value)
        if hash_length == 32:
            return 'md5'
        elif hash_length == 40:
            return 'sha1'
        elif hash_length == 64:
            return 'sha256'
        else:
            return 'unknown'
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range"""
        private_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8'
        ]
        # Simple check for common private ranges
        return (ip.startswith('10.') or 
                ip.startswith('192.168.') or 
                ip.startswith('172.') or 
                ip.startswith('127.'))
    
    async def virustotal_hash_lookup(self, hash_value: str) -> Optional[Dict]:
        """Lookup hash in VirusTotal"""
        if not self.virustotal_api_key:
            return None
        
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                clean = stats.get('harmless', 0)
                
                if malicious > 0:
                    status = 'malicious'
                elif suspicious > 0:
                    status = 'suspicious'
                else:
                    status = 'clean'
                
                return {
                    'virustotal': {
                        'malicious': malicious,
                        'suspicious': suspicious,
                        'clean': clean,
                        'status': status
                    }
                }
            
        except Exception as e:
            logger.error(f"VirusTotal lookup error: {e}")
        
        return None

class SOCBot:
    def __init__(self):
        self.analyzer = SOCAnalyzer()
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        
        if not self.bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN not found in environment variables")
    
    def get_main_keyboard(self):
        """Create main menu keyboard"""
        keyboard = [
            [InlineKeyboardButton("🔍 Analyze Hash", callback_data='analyze_hash')],
            [InlineKeyboardButton("🌐 Analyze IP", callback_data='analyze_ip')],
            [InlineKeyboardButton("🔗 Analyze URL", callback_data='analyze_url')],
            [InlineKeyboardButton("📄 Analyze File", callback_data='analyze_file')],
            [InlineKeyboardButton("📧 Analyze Email", callback_data='analyze_email')],
            [InlineKeyboardButton("ℹ️ Help", callback_data='help'),
             InlineKeyboardButton("📊 Status", callback_data='status')]
        ]
        return InlineKeyboardMarkup(keyboard)
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        welcome_message = """
🛡️ **AI SOC Analyst Bot** 🛡️

Welcome to your private Security Operations Center!

I can analyze:
• 🔍 File hashes (MD5, SHA1, SHA256)
• 🌐 IP addresses
• 🔗 URLs and domains
• 📄 Files and scripts
• 📧 Email content

Simply choose an analysis type below or send me data directly!

🔒 **Privacy**: All analysis is done locally on your device.
"""
        
        await update.message.reply_text(
            welcome_message,
            parse_mode='Markdown',
            reply_markup=self.get_main_keyboard()
        )
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_text = """
🛡️ **SOC Analyst Bot Help**

**Quick Analysis:**
• Send any hash, IP, or URL directly
• Upload files for analysis
• Forward suspicious emails

**Commands:**
• /start - Main menu
• /help - This help message
• /status - Bot status

**Supported Formats:**
• Hashes: MD5, SHA1, SHA256
• IPs: IPv4 addresses
• URLs: Any web link
• Files: Text, scripts, documents (max 50MB)

**Features:**
• Local AI analysis
• VirusTotal integration (if configured)
• Threat assessment
• Actionable recommendations

Need more help? Contact your administrator.
"""
        
        await update.message.reply_text(
            help_text,
            parse_mode='Markdown',
            reply_markup=self.get_main_keyboard()
        )
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle incoming messages"""
        message_text = update.message.text
        
        if not message_text:
            return
        
        # Auto-detect content type
        analysis_result = None
        
        # Check if it's a hash
        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', message_text):
            await update.message.reply_text("🔍 Analyzing hash...")
            analysis_result = await self.analyzer.analyze_hash(message_text)
        
        # Check if it's an IP
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', message_text):
            await update.message.reply_text("🌐 Analyzing IP address...")
            analysis_result = await self.analyzer.analyze_ip(message_text)
        
        # Check if it's a URL
        elif message_text.startswith(('http://', 'https://', 'ftp://')):
            await update.message.reply_text("🔗 Analyzing URL...")
            analysis_result = await self.analyzer.analyze_url(message_text)
        
        else:
            # Default: analyze as general text
            await update.message.reply_text("📝 Analyzing text content...")
            ai_prompt = f"""
            As a cybersecurity expert, analyze this text for potential security threats:
            
            {message_text}
            
            Please provide:
            1. Risk assessment
            2. Potential threats
            3. Recommended actions
            """
            
            ai_analysis = await self.analyzer.analyze_with_ollama(ai_prompt)
            analysis_result = {
                'type': 'text',
                'value': message_text[:100] + '...' if len(message_text) > 100 else message_text,
                'ai_analysis': ai_analysis
            }
        
        if analysis_result:
            response = self.format_analysis_result(analysis_result)
            await update.message.reply_text(
                response,
                parse_mode='Markdown',
                reply_markup=self.get_main_keyboard()
            )
    
    async def handle_document(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle file uploads"""
        document = update.message.document
        
        if document.file_size > self.analyzer.max_file_size:
            await update.message.reply_text("❌ File too large (max 50MB)")
            return
        
        await update.message.reply_text("📄 Downloading and analyzing file...")
        
        try:
            # Download file
            file = await context.bot.get_file(document.file_id)
            
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                await file.download_to_drive(tmp_file.name)
                
                # Analyze file
                analysis_result = await self.analyzer.analyze_file(
                    tmp_file.name, 
                    document.file_name
                )
                
                # Clean up
                os.unlink(tmp_file.name)
            
            response = self.format_analysis_result(analysis_result)
            await update.message.reply_text(
                response,
                parse_mode='Markdown',
                reply_markup=self.get_main_keyboard()
            )
            
        except Exception as e:
            await update.message.reply_text(f"❌ File analysis failed: {e}")
    
    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle button callbacks"""
        query = update.callback_query
        await query.answer()
        
        if query.data == 'help':
            await self.help_command(update, context)
        
        elif query.data == 'status':
            status_text = f"""
🤖 **Bot Status**

✅ Bot: Running
🧠 AI Model: {self.analyzer.ollama_model}
🔗 Ollama: {self.analyzer.ollama_base_url}
🛡️ VirusTotal: {'✅ Configured' if self.analyzer.virustotal_api_key else '❌ Not configured'}

📊 **Capabilities:**
• Hash analysis
• IP analysis  
• URL analysis
• File analysis
• Email analysis

⏰ Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            await query.edit_message_text(
                status_text,
                parse_mode='Markdown',
                reply_markup=self.get_main_keyboard()
            )
        
        else:
            instructions = {
                'analyze_hash': '🔍 Send me a hash (MD5, SHA1, or SHA256) to analyze',
                'analyze_ip': '🌐 Send me an IP address to analyze',
                'analyze_url': '🔗 Send me a URL to analyze',
                'analyze_file': '📄 Upload a file to analyze',
                'analyze_email': '📧 Forward an email or paste email content to analyze'
            }
            
            instruction = instructions.get(query.data, 'Unknown option')
            await query.edit_message_text(
                instruction,
                reply_markup=self.get_main_keyboard()
            )
    
    def format_analysis_result(self, result: Dict) -> str:
        """Format analysis result for display"""
        if 'error' in result:
            return f"❌ **Error:** {result['error']}"
        
        # Status emoji
        status_emoji = {
            'clean': '✅',
            'suspicious': '⚠️',
            'malicious': '🚨',
            'unknown': '❓'
        }.get(result.get('status', 'unknown'), '❓')
        
        response = f"{status_emoji} **Analysis Result**\n\n"
        response += f"**Type:** {result['type'].title()}\n"
        response += f"**Value:** `{result.get('value', 'N/A')}`\n"
        response += f"**Status:** {result.get('status', 'unknown').title()}\n\n"
        
        # Add specific details
        if result['type'] == 'hash':
            response += f"**Hash Type:** {result.get('hash_type', 'unknown').upper()}\n"
            
            if 'virustotal' in result:
                vt = result['virustotal']
                response += f"**VirusTotal:** {vt['malicious']}🚨 {vt['suspicious']}⚠️ {vt['clean']}✅\n"
        
        elif result['type'] == 'ip':
            response += f"**Scope:** {result.get('scope', 'unknown').title()}\n"
        
        elif result['type'] == 'url':
            response += f"**Domain:** {result.get('domain', 'N/A')}\n"
            if 'suspicious_patterns' in result:
                response += f"**Suspicious Patterns Found:** {len(result['suspicious_patterns'])}\n"
        
        elif result['type'] == 'file':
            response += f"**Size:** {result.get('size', 0)} bytes\n"
            response += f"**Type:** {result.get('mime_type', 'unknown')}\n"
            if 'md5' in result:
                response += f"**MD5:** `{result['md5']}`\n"
        
        # Add AI analysis
        if 'ai_analysis' in result:
            response += f"\n🤖 **AI Analysis:**\n{result['ai_analysis']}\n"
        
        return response
    
    def run(self):
        """Run the bot"""
        application = Application.builder().token(self.bot_token).build()
        
        # Add handlers
        application.add_handler(CommandHandler("start", self.start_command))
        application.add_handler(CommandHandler("help", self.help_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        application.add_handler(MessageHandler(filters.Document.ALL, self.handle_document))
        application.add_handler(CallbackQueryHandler(self.handle_callback))
        
        logger.info("🛡️ SOC Analyst Bot starting...")
        application.run_polling()

def main():
    """Main function"""
    try:
        bot = SOCBot()
        bot.run()
    except Exception as e:
        logger.error(f"Bot startup failed: {e}")
        raise

if __name__ == '__main__':
    main()
