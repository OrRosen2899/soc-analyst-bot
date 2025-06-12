#!/usr/bin/env python3
"""
Private SOC Analyst Bot
A Telegram-based security analysis bot using Ollama for AI analysis
Compatible with Raspberry Pi 4
"""

import os
import asyncio
import logging
import hashlib
import requests
import json
import magic
import yara
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from telegram import Update, Document
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from telegram.constants import ParseMode
import aiohttp
import aiofiles
from pathlib import Path

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """Handle threat intelligence lookups using free APIs"""
    
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY', '')
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def check_hash(self, file_hash: str) -> Dict:
        """Check file hash against VirusTotal"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}
        
        url = f"https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': self.vt_api_key,
            'resource': file_hash
        }
        
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'positives': data.get('positives', 0),
                        'total': data.get('total', 0),
                        'scan_date': data.get('scan_date', ''),
                        'permalink': data.get('permalink', ''),
                        'found': data.get('response_code') == 1
                    }
        except Exception as e:
            logger.error(f"VirusTotal hash check error: {e}")
        
        return {"error": "Failed to check hash"}
    
    async def check_url(self, url: str) -> Dict:
        """Check URL reputation"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}
        
        vt_url = "https://www.virustotal.com/vtapi/v2/url/report"
        params = {
            'apikey': self.vt_api_key,
            'resource': url
        }
        
        try:
            async with self.session.get(vt_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'positives': data.get('positives', 0),
                        'total': data.get('total', 0),
                        'scan_date': data.get('scan_date', ''),
                        'permalink': data.get('permalink', ''),
                        'found': data.get('response_code') == 1
                    }
        except Exception as e:
            logger.error(f"URL check error: {e}")
        
        return {"error": "Failed to check URL"}
    
    async def check_ip(self, ip: str) -> Dict:
        """Check IP reputation using AbuseIPDB"""
        if not self.abuseipdb_key:
            return {"error": "AbuseIPDB API key not configured"}
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': self.abuseipdb_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        
        try:
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {})
        except Exception as e:
            logger.error(f"IP check error: {e}")
        
        return {"error": "Failed to check IP"}

class FileAnalyzer:
    """Analyze uploaded files for threats"""
    
    def __init__(self):
        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)
        self.yara_rules = self._load_yara_rules()
    
    def _load_yara_rules(self):
        """Load YARA rules for malware detection"""
        try:
            # Basic YARA rules - you can expand this
            rules_content = """
            rule Suspicious_Executable
            {
                meta:
                    description = "Detects suspicious executable patterns"
                strings:
                    $mz = { 4D 5A }
                    $pe = "PE"
                    $suspicious1 = "cmd.exe" nocase
                    $suspicious2 = "powershell" nocase
                    $suspicious3 = "CreateProcess" nocase
                condition:
                    $mz at 0 and $pe and any of ($suspicious*)
            }
            
            rule Suspicious_Script
            {
                meta:
                    description = "Detects suspicious script patterns"
                strings:
                    $js1 = "eval(" nocase
                    $js2 = "unescape(" nocase
                    $ps1 = "Invoke-Expression" nocase
                    $ps2 = "DownloadString" nocase
                    $py1 = "exec(" nocase
                    $py2 = "__import__" nocase
                condition:
                    any of them
            }
            """
            return yara.compile(source=rules_content)
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return None
    
    async def analyze_file(self, file_path: str) -> Dict:
        """Comprehensive file analysis"""
        try:
            # Get file info
            file_stats = os.stat(file_path)
            file_size = file_stats.st_size
            
            # Calculate hashes
            hashes = await self._calculate_hashes(file_path)
            
            # Get file type
            file_type = magic.from_file(file_path, mime=True)
            
            # YARA scan
            yara_matches = []
            if self.yara_rules:
                try:
                    matches = self.yara_rules.match(file_path)
                    yara_matches = [match.rule for match in matches]
                except Exception as e:
                    logger.error(f"YARA scan error: {e}")
            
            # Basic suspicious indicators
            suspicious_indicators = await self._check_suspicious_indicators(file_path, file_type)
            
            return {
                'filename': os.path.basename(file_path),
                'size': file_size,
                'type': file_type,
                'hashes': hashes,
                'yara_matches': yara_matches,
                'suspicious_indicators': suspicious_indicators,
                'risk_score': self._calculate_risk_score(yara_matches, suspicious_indicators)
            }
            
        except Exception as e:
            logger.error(f"File analysis error: {e}")
            return {"error": f"Analysis failed: {str(e)}"}
    
    async def _calculate_hashes(self, file_path: str) -> Dict:
        """Calculate MD5, SHA1, and SHA256 hashes"""
        hashes = {}
        hash_funcs = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        async with aiofiles.open(file_path, 'rb') as f:
            async for chunk in self._file_chunks(f):
                for hash_func in hash_funcs.values():
                    hash_func.update(chunk)
        
        return {name: hash_func.hexdigest() for name, hash_func in hash_funcs.items()}
    
    async def _file_chunks(self, file_obj, chunk_size=8192):
        """Async generator for file chunks"""
        while True:
            chunk = await file_obj.read(chunk_size)
            if not chunk:
                break
            yield chunk
    
    async def _check_suspicious_indicators(self, file_path: str, file_type: str) -> List[str]:
        """Check for suspicious file indicators"""
        indicators = []
        
        # Check file extension vs MIME type mismatch
        file_ext = Path(file_path).suffix.lower()
        if file_ext in ['.exe', '.scr', '.bat', '.cmd'] and 'executable' not in file_type:
            indicators.append("File extension/MIME type mismatch")
        
        # Check for double extensions
        if file_path.count('.') > 1:
            indicators.append("Multiple file extensions detected")
        
        # Check for suspicious file names
        suspicious_names = ['invoice', 'document', 'photo', 'update', 'patch']
        filename_lower = os.path.basename(file_path).lower()
        if any(name in filename_lower for name in suspicious_names) and file_ext in ['.exe', '.scr']:
            indicators.append("Suspicious filename for executable")
        
        return indicators
    
    def _calculate_risk_score(self, yara_matches: List, suspicious_indicators: List) -> int:
        """Calculate risk score (0-100)"""
        score = 0
        score += len(yara_matches) * 30
        score += len(suspicious_indicators) * 15
        return min(score, 100)

class OllamaAnalyzer:
    """Interface with Ollama for AI-powered analysis"""
    
    def __init__(self, model_name: str = "llama3.2"):
        self.model_name = model_name
        self.base_url = "http://localhost:11434"
    
    async def analyze_with_ai(self, analysis_data: Dict, artifact_type: str) -> str:
        """Get AI analysis and recommendations"""
        prompt = self._build_analysis_prompt(analysis_data, artifact_type)
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.model_name,
                    "prompt": prompt,
                    "stream": False
                }
                
                async with session.post(f"{self.base_url}/api/generate", json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('response', 'Analysis failed')
                    else:
                        return f"Ollama service error: {response.status}"
        except Exception as e:
            logger.error(f"Ollama analysis error: {e}")
            return f"AI analysis unavailable: {str(e)}"
    
    def _build_analysis_prompt(self, data: Dict, artifact_type: str) -> str:
        """Build analysis prompt for Ollama"""
        base_prompt = f"""
You are a cybersecurity analyst. Analyze the following {artifact_type} and provide:
1. Risk assessment (LOW/MEDIUM/HIGH)
2. Key findings
3. Recommended actions
4. Brief explanation in simple terms

Analysis data: {json.dumps(data, indent=2)}

Respond in a clear, professional format suitable for both technical and non-technical users.
"""
        return base_prompt

class SOCAnalystBot:
    """Main bot class"""
    
    def __init__(self, telegram_token: str):
        self.application = Application.builder().token(telegram_token).build()
        self.file_analyzer = FileAnalyzer()
        self.ollama_analyzer = OllamaAnalyzer()
        self.authorized_users = set(map(int, os.getenv('AUTHORIZED_USERS', '').split(','))) if os.getenv('AUTHORIZED_USERS') else set()
        
        # Add handlers
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("help", self.help_command))
        self.application.add_handler(CommandHandler("status", self.status_command))
        self.application.add_handler(MessageHandler(filters.Document.ALL, self.handle_file))
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text))
    
    def _is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized"""
        return not self.authorized_users or user_id in self.authorized_users
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        if not self._is_authorized(update.effective_user.id):
            await update.message.reply_text("❌ Unauthorized access")
            return
        
        welcome_msg = """
🛡️ **Private SOC Analyst Bot**

I'm your personal security analyst! Send me:
📁 Files to analyze
🌐 URLs to check
🔍 IP addresses to investigate
📧 Email content to examine
🔐 File hashes to lookup

Commands:
/help - Show detailed help
/status - Check system status

I'll analyze everything and give you clear recommendations!
        """
        await update.message.reply_text(welcome_msg, parse_mode=ParseMode.MARKDOWN)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        if not self._is_authorized(update.effective_user.id):
            return
        
        help_msg = """
🔍 **How to use SOC Analyst Bot:**

**File Analysis:**
📁 Send any file - I'll scan for malware and suspicious patterns

**URL Checking:**
🌐 Send a URL - I'll check its reputation and safety

**IP Investigation:**
🔍 Send an IP address - I'll check for malicious activity

**Hash Lookup:**
🔐 Send MD5/SHA1/SHA256 hash - I'll check threat databases

**Email Analysis:**
📧 Forward suspicious emails - I'll analyze headers and content

**Example inputs:**
- `https://suspicious-site.com`
- `192.168.1.1`
- `5d41402abc4b2a76b9719d911017c592`
- Forward email or paste email headers

I'll provide risk assessment and actionable recommendations!
        """
        await update.message.reply_text(help_msg, parse_mode=ParseMode.MARKDOWN)
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /status command"""
        if not self._is_authorized(update.effective_user.id):
            return
        
        # Check Ollama connection
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("http://localhost:11434/api/tags") as response:
                    ollama_status = "✅ Connected" if response.status == 200 else "❌ Error"
        except:
            ollama_status = "❌ Offline"
        
        # Check API keys
        vt_status = "✅ Configured" if os.getenv('VIRUSTOTAL_API_KEY') else "⚠️ Not configured"
        abuse_status = "✅ Configured" if os.getenv('ABUSEIPDB_API_KEY') else "⚠️ Not configured"
        
        status_msg = f"""
🔧 **System Status:**

**AI Engine:** {ollama_status}
**VirusTotal API:** {vt_status}
**AbuseIPDB API:** {abuse_status}

**Capabilities:**
- File scanning with YARA rules
- Hash lookups (when APIs configured)
- URL reputation checking
- IP address investigation
- AI-powered analysis

⚠️ *Configure API keys for full functionality*
        """
        await update.message.reply_text(status_msg, parse_mode=ParseMode.MARKDOWN)
    
    async def handle_file(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle uploaded files"""
        if not self._is_authorized(update.effective_user.id):
            return
        
        document = update.message.document
        await update.message.reply_text("📁 Analyzing file... Please wait.")
        
        try:
            # Download file
            file = await context.bot.get_file(document.file_id)
            file_path = self.file_analyzer.upload_dir / document.file_name
            await file.download_to_drive(file_path)
            
            # Analyze file
            analysis = await self.file_analyzer.analyze_file(str(file_path))
            
            if 'error' in analysis:
                await update.message.reply_text(f"❌ Analysis failed: {analysis['error']}")
                return
            
            # Get AI analysis
            ai_analysis = await self.ollama_analyzer.analyze_with_ai(analysis, "file")
            
            # Check hash against threat intel
            hash_results = {}
            if analysis.get('hashes', {}).get('sha256'):
                async with ThreatIntelligence() as ti:
                    hash_results = await ti.check_hash(analysis['hashes']['sha256'])
            
            # Format response
            response = self._format_file_analysis(analysis, ai_analysis, hash_results)
            await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)
            
            # Clean up
            os.remove(file_path)
            
        except Exception as e:
            logger.error(f"File handling error: {e}")
            await update.message.reply_text(f"❌ Error processing file: {str(e)}")
    
    async def handle_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages (URLs, IPs, hashes, emails)"""
        if not self._is_authorized(update.effective_user.id):
            return
        
        text = update.message.text.strip()
        
        # Detect input type and handle accordingly
        if self._is_url(text):
            await self._handle_url(update, text)
        elif self._is_ip(text):
            await self._handle_ip(update, text)
        elif self._is_hash(text):
            await self._handle_hash(update, text)
        elif self._is_email_content(text):
            await self._handle_email(update, text)
        else:
            await update.message.reply_text(
                "🤔 I'm not sure what to analyze. Please send:\n"
                "• A URL (http://...)\n"
                "• An IP address\n"
                "• A file hash\n"
                "• Email content\n"
                "• Or upload a file"
            )
    
    def _is_url(self, text: str) -> bool:
        """Check if text is a URL"""
        return text.startswith(('http://', 'https://')) or ('.' in text and ' ' not in text)
    
    def _is_ip(self, text: str) -> bool:
        """Check if text is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(text)
            return True
        except:
            return False
    
    def _is_hash(self, text: str) -> bool:
        """Check if text is a hash"""
        return len(text) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in text)
    
    def _is_email_content(self, text: str) -> bool:
        """Check if text contains email content"""
        email_indicators = ['from:', 'to:', 'subject:', 'received:', '@']
        return any(indicator in text.lower() for indicator in email_indicators)
    
    async def _handle_url(self, update: Update, url: str):
        """Handle URL analysis"""
        await update.message.reply_text("🌐 Analyzing URL... Please wait.")
        
        try:
            async with ThreatIntelligence() as ti:
                url_results = await ti.check_url(url)
            
            ai_analysis = await self.ollama_analyzer.analyze_with_ai(
                {'url': url, 'reputation_check': url_results}, 
                "URL"
            )
            
            response = self._format_url_analysis(url, url_results, ai_analysis)
            await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)
            
        except Exception as e:
            await update.message.reply_text(f"❌ URL analysis failed: {str(e)}")
    
    async def _handle_ip(self, update: Update, ip: str):
        """Handle IP analysis"""
        await update.message.reply_text("🔍 Investigating IP... Please wait.")
        
        try:
            async with ThreatIntelligence() as ti:
                ip_results = await ti.check_ip(ip)
            
            ai_analysis = await self.ollama_analyzer.analyze_with_ai(
                {'ip': ip, 'reputation_check': ip_results}, 
                "IP address"
            )
            
            response = self._format_ip_analysis(ip, ip_results, ai_analysis)
            await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)
            
        except Exception as e:
            await update.message.reply_text(f"❌ IP analysis failed: {str(e)}")
    
    async def _handle_hash(self, update: Update, file_hash: str):
        """Handle hash lookup"""
        await update.message.reply_text("🔐 Looking up hash... Please wait.")
        
        try:
            async with ThreatIntelligence() as ti:
                hash_results = await ti.check_hash(file_hash)
            
            ai_analysis = await self.ollama_analyzer.analyze_with_ai(
                {'hash': file_hash, 'threat_intel': hash_results}, 
                "file hash"
            )
            
            response = self._format_hash_analysis(file_hash, hash_results, ai_analysis)
            await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Hash lookup failed: {str(e)}")
    
    async def _handle_email(self, update: Update, email_content: str):
        """Handle email analysis"""
        await update.message.reply_text("📧 Analyzing email... Please wait.")
        
        try:
            # Extract URLs and IPs from email
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_content)
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', email_content)
            
            email_analysis = {
                'content_length': len(email_content),
                'urls_found': urls,
                'ips_found': ips,
                'has_attachments': 'attachment' in email_content.lower(),
                'suspicious_keywords': self._find_suspicious_keywords(email_content)
            }
            
            ai_analysis = await self.ollama_analyzer.analyze_with_ai(email_analysis, "email")
            
            response = self._format_email_analysis(email_analysis, ai_analysis)
            await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)
            
        except Exception as e:
            await update.message.reply_text(f"❌ Email analysis failed: {str(e)}")
    
    def _find_suspicious_keywords(self, content: str) -> List[str]:
        """Find suspicious keywords in email content"""
        suspicious_keywords = [
            'urgent', 'verify account', 'suspended', 'click here', 'download now',
            'wire transfer', 'bitcoin', 'cryptocurrency', 'lottery', 'inheritance',
            'tax refund', 'irs', 'paypal', 'amazon', 'microsoft', 'apple'
        ]
        found = []
        content_lower = content.lower()
        for keyword in suspicious_keywords:
            if keyword in content_lower:
                found.append(keyword)
        return found
    
    def _format_file_analysis(self, analysis: Dict, ai_analysis: str, hash_results: Dict) -> str:
        """Format file analysis response"""
        risk_level = "🔴 HIGH" if analysis['risk_score'] > 70 else "🟡 MEDIUM" if analysis['risk_score'] > 30 else "🟢 LOW"
        
        response = f"""
🛡️ **File Analysis Report**

**File:** `{analysis['filename']}`
**Size:** {analysis['size']} bytes
**Type:** {analysis['type']}
**Risk Level:** {risk_level}

**Hashes:**
- MD5: `{analysis['hashes']['md5']}`
- SHA256: `{analysis['hashes']['sha256']}`

**Detections:**
- YARA matches: {len(analysis['yara_matches'])}
- Suspicious indicators: {len(analysis['suspicious_indicators'])}
        """
        
        if hash_results.get('found'):
            response += f"\n**Threat Intelligence:**\n• VirusTotal: {hash_results['positives']}/{hash_results['total']} detections"
        
        response += f"\n\n**AI Analysis:**\n{ai_analysis}"
        
        return response
    
    def _format_url_analysis(self, url: str, results: Dict, ai_analysis: str) -> str:
        """Format URL analysis response"""
        if results.get('found'):
            risk = "🔴 MALICIOUS" if results['positives'] > 0 else "🟢 CLEAN"
            response = f"""
🌐 **URL Analysis Report**

**URL:** `{url}`
**Status:** {risk}
**Detections:** {results.get('positives', 0)}/{results.get('total', 0)}

**AI Analysis:**
{ai_analysis}
            """
        else:
            response = f"""
🌐 **URL Analysis Report**

**URL:** `{url}`
**Status:** 🟡 Unknown (not in database)

**AI Analysis:**
{ai_analysis}
            """
        
        return response
    
    def _format_ip_analysis(self, ip: str, results: Dict, ai_analysis: str) -> str:
        """Format IP analysis response"""
        if 'error' not in results:
            confidence = results.get('abuseConfidencePercentage', 0)
            risk = "🔴 HIGH RISK" if confidence > 75 else "🟡 MEDIUM RISK" if confidence > 25 else "🟢 LOW RISK"
            
            response = f"""
🔍 **IP Analysis Report**

**IP Address:** `{ip}`
**Risk Level:** {risk}
**Abuse Confidence:** {confidence}%
**Country:** {results.get('countryName', 'Unknown')}
**ISP:** {results.get('isp', 'Unknown')}

**AI Analysis:**
{ai_analysis}
            """
        else:
            response = f"""
🔍 **IP Analysis Report**

**IP Address:** `{ip}`
**Status:** Analysis unavailable

**AI Analysis:**
{ai_analysis}
            """
        
        return response
    
    def _format_hash_analysis(self, file_hash: str, results: Dict, ai_analysis: str) -> str:
        """Format hash analysis response"""
        if results.get('found'):
            risk = "🔴 MALICIOUS" if results['positives'] > 0 else "🟢 CLEAN"
            response = f"""
🔐 **Hash Analysis Report**

**Hash:** `{file_hash}`
**Status:** {risk}
**Detections:** {results.get('positives', 0)}/{results.get('total', 0)}
**Scan Date:** {results.get('scan_date', 'Unknown')}

**AI Analysis:**
{ai_analysis}
            """
        else:
            response = f"""
🔐 **Hash Analysis Report**

**Hash:** `{file_hash}`
**Status:** 🟡 Unknown (not in database)

**AI Analysis:**
{ai_analysis}
            """
        
        return response
    
    def _format_email_analysis(self, analysis: Dict, ai_analysis: str) -> str:
        """Format email analysis response"""
        risk_score = len(analysis['suspicious_keywords']) * 20 + (30 if analysis['urls_found'] else 0)
        risk_level = "🔴 HIGH" if risk_score > 60 else "🟡 MEDIUM" if risk_score > 30 else "🟢 LOW"
        
        response = f"""
📧 **Email Analysis Report**

**Risk Level:** {risk_level}
**Content Length:** {analysis['content_length']} characters
**URLs Found:** {len(analysis['urls_found'])}
**IPs Found:** {len(analysis['ips_found'])}
**Suspicious Keywords:** {len(analysis['suspicious_keywords'])}

**AI Analysis:**
{ai_analysis}
        """
        
        if analysis['suspicious_keywords']:
            response += f"\n**Detected Keywords:** {', '.join(analysis['suspicious_keywords'])}"
        
        return response
    
    def run(self):
        """Start the bot"""
        logger.info("Starting SOC Analyst Bot...")
        self.application.run_polling()

def main():
    """Main function"""
    # Load environment variables
    telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not telegram_token:
        logger.error("TELEGRAM_BOT_TOKEN environment variable not set")
        return
    
    # Create and run bot
    bot = SOCAnalystBot(telegram_token)
    bot.run()

if __name__ == "__main__":
    main()
