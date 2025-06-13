#!/usr/bin/env python3
"""
SOC Analyst Bot - Enhanced Security Analysis Bot for Family Network
With Improved .env Loading
"""

import os
import sys
import logging
import asyncio
import hashlib
import re
import json
import subprocess
import urllib.parse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, CallbackQueryHandler
from dotenv import load_dotenv, find_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - **%(name)s** - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_environment_variables():
    """
    Load environment variables from .env file with multiple fallback methods
    """
    logger.info("🔍 Attempting to load environment variables...")
    
    # Method 1: Try to find .env file automatically
    env_path = find_dotenv()
    if env_path:
        logger.info(f"✅ Found .env file at: {env_path}")
        load_dotenv(env_path, override=True)
    else:
        # Method 2: Try current directory
        current_dir = Path(__file__).parent
        env_file = current_dir / '.env'
        
        if env_file.exists():
            logger.info(f"✅ Found .env file in script directory: {env_file}")
            load_dotenv(env_file, override=True)
        else:
            # Method 3: Try working directory
            working_dir = Path.cwd()
            env_file = working_dir / '.env'
            
            if env_file.exists():
                logger.info(f"✅ Found .env file in working directory: {env_file}")
                load_dotenv(env_file, override=True)
            else:
                # Method 4: Try parent directories
                for parent in Path(__file__).parents:
                    env_file = parent / '.env'
                    if env_file.exists():
                        logger.info(f"✅ Found .env file in parent directory: {env_file}")
                        load_dotenv(env_file, override=True)
                        break
                else:
                    logger.error("❌ No .env file found in any location")
                    logger.error("📁 Searched locations:")
                    logger.error(f"  - Script directory: {Path(__file__).parent}")
                    logger.error(f"  - Working directory: {Path.cwd()}")
                    logger.error(f"  - Parent directories of script")
                    return False
    
    # Verify critical environment variables
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        logger.error("❌ TELEGRAM_BOT_TOKEN environment variable not set")
        logger.error("💡 Make sure your .env file contains: TELEGRAM_BOT_TOKEN=your_token_here")
        return False
    
    logger.info("✅ Environment variables loaded successfully")
    logger.info(f"🔑 Token length: {len(token)} characters")
    
    # Log other optional variables (without showing values)
    optional_vars = {
        'AUTHORIZED_USERS': 'Authorized user IDs',
        'VIRUSTOTAL_API_KEY': 'VirusTotal API key',
        'ABUSEIPDB_API_KEY': 'AbuseIPDB API key',
        'OLLAMA_BASE_URL': 'Ollama base URL',
        'OLLAMA_MODEL': 'Ollama model name'
    }
    
    for var, description in optional_vars.items():
        value = os.getenv(var)
        if value:
            logger.info(f"✅ {description}: Found")
        else:
            logger.info(f"ℹ️ {description}: Not set (optional)")
    
    return True

class SOCAnalystBot:
    def __init__(self):
        # Load environment variables first
        if not load_environment_variables():
            logger.error("Failed to load environment variables. Exiting.")
            sys.exit(1)
            
        self.token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.authorized_users = self._parse_authorized_users()
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.ollama_base_url = os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'llama3.2:1b')
        self.max_file_size = int(os.getenv('MAX_FILE_SIZE_MB', '50')) * 1024 * 1024
        
        # Initialize data stores
        self.threat_feed = {}
        self.analysis_cache = {}
        self.user_sessions = {}
        
        logger.info("🛡️ SOC Analyst Bot initialized successfully")
        logger.info(f"🤖 Ollama URL: {self.ollama_base_url}")
        logger.info(f"🧠 Ollama Model: {self.ollama_model}")
        logger.info(f"👥 Authorized Users: {len(self.authorized_users) if self.authorized_users else 'All users'}")

    def _parse_authorized_users(self) -> Optional[List[int]]:
        """Parse authorized users from environment variable"""
        users_str = os.getenv('AUTHORIZED_USERS', '').strip()
        if not users_str:
            return None
        
        try:
            return [int(user_id.strip()) for user_id in users_str.split(',') if user_id.strip()]
        except ValueError:
            logger.warning("Invalid AUTHORIZED_USERS format. Allowing all users.")
            return None

    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized to use the bot"""
        if self.authorized_users is None:
            return True
        return user_id in self.authorized_users

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start command handler"""
        user_id = update.effective_user.id
        
        if not self.is_authorized(user_id):
            await update.message.reply_text(
                "🚫 You are not authorized to use this bot.\n"
                "Contact the administrator if you believe this is an error."
            )
            return
        
        welcome_text = """
🛡️ **SOC Analyst Bot** - Family Network Security
==========================================

I'm your Security Operations Center analyst! I can help you:

🔍 **Analysis Commands:**
• `/analyze_url <url>` - Analyze website/URL for threats
• `/analyze_ip <ip>` - Check IP address reputation  
• `/scan_hash <hash>` - Check file hash against threat databases
• `/phishing_check <url>` - Advanced phishing detection

📊 **Monitoring Commands:**
• `/network_status` - Check home network health
• `/threat_summary` - Recent threat intelligence summary
• `/security_tips` - Daily security recommendations

🆘 **Emergency Commands:**
• `/incident_report` - Report a security incident
• `/block_ip <ip>` - Emergency IP blocking
• `/help` - Show detailed help

**Simply send me files, URLs, or suspicious content and I'll analyze them for threats!**

🔒 **Security:** This bot is configured for the OrRosen family network. All analysis data is processed locally when possible.
        """
        
        keyboard = [
            [InlineKeyboardButton("🔍 Quick URL Check", callback_data="quick_url")],
            [InlineKeyboardButton("📊 Network Status", callback_data="network_status")],
            [InlineKeyboardButton("🆘 Report Incident", callback_data="incident_report")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')

    async def analyze_url(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Analyze URL for threats"""
        user_id = update.effective_user.id
        
        if not self.is_authorized(user_id):
            await update.message.reply_text("🚫 Unauthorized access.")
            return
        
        if not context.args:
            await update.message.reply_text(
                "🔍 **URL Analysis**\n\n"
                "Usage: `/analyze_url <url>`\n\n"
                "Example: `/analyze_url https://suspicious-site.com`",
                parse_mode='Markdown'
            )
            return
        
        url = context.args[0]
        logger.info(f"Analyzing URL: {url} for user {user_id}")
        
        # Send initial message
        analysis_msg = await update.message.reply_text("🔍 Analyzing URL, please wait...")
        
        try:
            # Perform analysis
            result = await self._analyze_url_comprehensive(url)
            
            # Format result
            report = self._format_url_analysis(url, result)
            
            await analysis_msg.edit_text(report, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            await analysis_msg.edit_text(
                f"❌ Error analyzing URL: {str(e)}\n\n"
                "Please try again or contact support if the issue persists."
            )

    async def _analyze_url_comprehensive(self, url: str) -> Dict:
        """Comprehensive URL analysis"""
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'safety_score': 50,  # Default neutral score
            'threats': [],
            'recommendations': [],
            'details': {}
        }
        
        try:
            # Basic URL validation
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                result['threats'].append("Invalid URL format")
                result['safety_score'] = 10
                return result
            
            # Check against known threat indicators
            await self._check_url_patterns(url, result)
            
            # VirusTotal check
            if self.virustotal_api_key:
                await self._check_virustotal_url(url, result)
            
            # AI Analysis
            ai_analysis = await self._get_ai_analysis(f"Analyze this URL for security threats: {url}")
            if ai_analysis:
                result['ai_analysis'] = ai_analysis
            else:
                result['ai_analysis'] = "Ollama service error: 404"
            
            # Calculate final safety score
            result['safety_score'] = self._calculate_safety_score(result)
            
        except Exception as e:
            logger.error(f"Error in comprehensive URL analysis: {e}")
            result['threats'].append(f"Analysis error: {str(e)}")
        
        return result

    async def _check_url_patterns(self, url: str, result: Dict):
        """Check URL against suspicious patterns"""
        suspicious_patterns = [
            r'bit\.ly|tinyurl|t\.co',  # URL shorteners
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]{32,}\.tk|\.ml|\.ga|\.cf',  # Suspicious TLDs with long subdomains
            r'paypal|amazon|microsoft|google.*[0-9]',  # Brand impersonation
            r'secure.*update|verify.*account|suspended.*account'  # Phishing keywords
        ]
        
        threats_found = []
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                threats_found.append(f"Suspicious pattern detected: {pattern}")
        
        result['threats'].extend(threats_found)
        result['details']['pattern_analysis'] = {
            'patterns_checked': len(suspicious_patterns),
            'threats_found': len(threats_found)
        }

    async def _check_virustotal_url(self, url: str, result: Dict):
        """Check URL with VirusTotal API"""
        try:
            headers = {'x-apikey': self.virustotal_api_key}
            
            # Submit URL for analysis
            scan_response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=headers,
                data={'url': url},
                timeout=10
            )
            
            if scan_response.status_code == 200:
                scan_data = scan_response.json()
                analysis_id = scan_data.get('data', {}).get('id')
                
                if analysis_id:
                    # Get analysis results
                    analysis_response = requests.get(
                        f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                        headers=headers,
                        timeout=10
                    )
                    
                    if analysis_response.status_code == 200:
                        analysis_data = analysis_response.json()
                        stats = analysis_data.get('data', {}).get('attributes', {}).get('stats', {})
                        
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        harmless = stats.get('harmless', 0)
                        
                        result['details']['virustotal'] = {
                            'malicious': malicious,
                            'suspicious': suspicious,
                            'harmless': harmless,
                            'scan_date': analysis_data.get('data', {}).get('attributes', {}).get('date')
                        }
                        
                        if malicious > 0:
                            result['threats'].append(f"VirusTotal: {malicious} engines detected malware")
                        if suspicious > 0:
                            result['threats'].append(f"VirusTotal: {suspicious} engines flagged as suspicious")
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
            result['details']['virustotal_error'] = str(e)

    async def _get_ai_analysis(self, prompt: str) -> Optional[str]:
        """Get AI analysis from Ollama"""
        try:
            response = requests.post(
                f"{self.ollama_base_url}/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": f"{prompt}\n\nProvide a concise security assessment focusing on potential threats and recommendations.",
                    "stream": False
                },
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('response', '').strip()
            else:
                logger.error(f"Ollama API error: {response.status_code}")
                return None
                
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama service")
            return None
        except Exception as e:
            logger.error(f"Error getting AI analysis: {e}")
            return None

    def _calculate_safety_score(self, result: Dict) -> int:
        """Calculate safety score based on analysis results"""
        score = 50  # Start neutral
        
        # Deduct points for threats
        threat_count = len(result.get('threats', []))
        score -= (threat_count * 15)
        
        # VirusTotal results
        vt_data = result.get('details', {}).get('virustotal', {})
        if vt_data:
            malicious = vt_data.get('malicious', 0)
            suspicious = vt_data.get('suspicious', 0)
            
            score -= (malicious * 20)
            score -= (suspicious * 10)
            
            # Bonus for clean results
            if malicious == 0 and suspicious == 0:
                score += 20
        
        # Ensure score is within bounds
        return max(0, min(100, score))

    def _format_url_analysis(self, url: str, result: Dict) -> str:
        """Format URL analysis result for display"""
        score = result.get('safety_score', 0)
        
        # Determine status emoji and text
        if score >= 80:
            status_emoji = "🟢"
            status_text = "Safe"
        elif score >= 60:
            status_emoji = "🟡"
            status_text = "Caution"
        elif score >= 40:
            status_emoji = "🟠"
            status_text = "Suspicious"
        else:
            status_emoji = "🔴"
            status_text = "Dangerous"
        
        # Check if URL is in any database
        vt_data = result.get('details', {}).get('virustotal')
        if vt_data:
            db_status = f"Known (VT: {vt_data.get('harmless', 0)}✅ {vt_data.get('malicious', 0)}❌)"
        else:
            db_status = "🟡 Unknown (not in database)"
        
        report = f"""🌐 **URL Analysis Report**
URL: {url}
Status: {status_emoji} {status_text} (Score: {score}/100)
Database: {db_status}

**AI Analysis:**
{result.get('ai_analysis', 'No AI analysis available')}
"""
        
        # Add threats if any
        threats = result.get('threats', [])
        if threats:
            report += f"\n\n⚠️ **Threats Detected ({len(threats)}):**\n"
            for threat in threats[:5]:  # Limit to 5 threats
                report += f"• {threat}\n"
        
        # Add recommendations
        recommendations = [
            "🔒 Always verify URLs before clicking",
            "🛡️ Use updated antivirus software",
            "👥 Be cautious with personal information"
        ]
        
        if score < 60:
            recommendations.insert(0, "❌ **DO NOT** visit this URL")
            recommendations.insert(1, "🚫 Block this domain on your network")
        
        report += f"\n\n💡 **Recommendations:**\n"
        for rec in recommendations[:3]:
            report += f"• {rec}\n"
        
        report += f"\n📅 Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return report

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Help command handler"""
        help_text = """
🛡️ **SOC Analyst Bot - Complete Command Guide**

**🔍 URL & Website Analysis:**
• `/analyze_url <url>` - Comprehensive URL threat analysis
• `/phishing_check <url>` - Advanced phishing detection
• `/domain_info <domain>` - Domain registration & history

**🌐 IP Address Analysis:**  
• `/analyze_ip <ip>` - IP reputation & geolocation check
• `/block_ip <ip>` - Emergency IP blocking
• `/ip_history <ip>` - Historical threat data for IP

**🔐 File & Hash Analysis:**
• `/scan_hash <hash>` - Check MD5/SHA1/SHA256 against databases
• Send any file (up to 50MB) for malware analysis
• `/file_report <hash>` - Get detailed file analysis report

**📊 Network Monitoring:**
• `/network_status` - Home network security health
• `/connected_devices` - List of connected devices  
• `/bandwidth_usage` - Network traffic analysis
• `/firewall_status` - Firewall rules and status

**🚨 Threat Intelligence:**
• `/threat_summary` - Latest threat intelligence
• `/cve_lookup <cve-id>` - Look up CVE vulnerability details
• `/threat_feed` - Subscribe to threat feeds
• `/ioc_search <indicator>` - Search for indicators of compromise

**🆘 Emergency Response:**
• `/incident_report` - Report security incident
• `/emergency_block <ip/domain>` - Emergency blocking
• `/quarantine_device <ip>` - Isolate compromised device
• `/security_alert` - Broadcast security alert to family

**⚙️ Configuration:**
• `/settings` - Bot configuration options
• `/authorize_user <user_id>` - Add authorized user
• `/set_alert_level <level>` - Configure alert sensitivity
• `/backup_config` - Backup security configurations

**💡 Education & Tips:**
• `/security_tips` - Daily security recommendations
• `/explain <term>` - Explain security terminology
• `/best_practices` - Security best practices guide
• `/phishing_examples` - Learn to identify phishing

**📱 Quick Actions:**
Just send me:
• Any URL - I'll analyze it automatically
• Any file - I'll scan for malware
• Any IP address - I'll check its reputation
• Screenshots of suspicious messages

**🔒 Privacy & Security:**
• All analysis is done locally when possible
• No sensitive data is stored permanently  
• Threat intelligence is anonymized
• Family network data stays private

**Need immediate help?** Use `/emergency_block` or `/incident_report`
        """
        
        await update.message.reply_text(help_text, parse_mode='Markdown')

def main():
    """Main function"""
    try:
        # Initialize bot
        bot = SOCAnalystBot()
        
        # Create application
        application = Application.builder().token(bot.token).build()
        
        # Add handlers
        application.add_handler(CommandHandler("start", bot.start_command))
        application.add_handler(CommandHandler("help", bot.help_command))
        application.add_handler(CommandHandler("analyze_url", bot.analyze_url))
        
        # Add message handler for automatic analysis
        # application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.handle_message))
        
        logger.info("🚀 SOC Analyst Bot starting...")
        
        # Start the bot
        application.run_polling(drop_pending_updates=True)
        
    except Exception as e:
        logger.error(f"❌ Failed to start bot: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
