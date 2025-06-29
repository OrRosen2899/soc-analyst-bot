#!/usr/bin/env python3
"""
SOC AI Agent - Security Operations Center AI Assistant
A comprehensive security analysis bot using Telegram, VirusTotal, AbuseDB, and Hugging Face models
"""

import os
import sqlite3
import hashlib
import requests
import json
import re
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse
import base64
import magic
from pathlib import Path

# Telegram bot imports
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, InputFile
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# Hugging Face imports
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch

# Environment variables
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('soc_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SOCAgent:
    def __init__(self):
        self.telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abusedb_api_key = os.getenv('ABUSEDB_API_KEY')
        self.authorized_users = list(map(int, os.getenv('AUTHORIZED_USERS', '').split(',')))
        
        # Initialize database
        self.init_database()
        
        # Initialize Hugging Face models
        self.init_ai_models()
        
        # VirusTotal and AbuseDB endpoints
        self.vt_base_url = "https://www.virustotal.com/vtapi/v2"
        self.abusedb_base_url = "https://api.abuseipdb.com/api/v2"
        
    def init_database(self):
        """Initialize SQLite database for IOCs"""
        self.conn = sqlite3.connect('soc_database.db', check_same_thread=False)
        cursor = self.conn.cursor()
        
        # Create IOCs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT UNIQUE NOT NULL,
                type TEXT NOT NULL,
                threat_level TEXT,
                description TEXT,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create analysis history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                indicator TEXT,
                analysis_type TEXT,
                results TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
        logger.info("Database initialized successfully")
    
    def init_ai_models(self):
        """Initialize Hugging Face models for security analysis"""
        try:
            # Use a lightweight model suitable for Raspberry Pi
            model_name = "distilbert-base-uncased-finetuned-sst-2-english"
            
            self.tokenizer = AutoTokenizer.from_pretrained(model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(model_name)
            
            # Create analysis pipeline
            self.sentiment_analyzer = pipeline(
                "sentiment-analysis",
                model=self.model,
                tokenizer=self.tokenizer,
                device=-1  # Use CPU for Raspberry Pi
            )
            
            # Initialize text generation for reports
            self.text_generator = pipeline(
                "text-generation",
                model="distilgpt2",
                device=-1,
                max_length=200
            )
            
            logger.info("AI models initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing AI models: {e}")
            self.sentiment_analyzer = None
            self.text_generator = None
    
    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized to use the bot"""
        return user_id in self.authorized_users
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start command handler"""
        user_id = update.effective_user.id
        
        if not self.is_authorized(user_id):
            await update.message.reply_text("❌ Unauthorized access. Contact administrator.")
            return
        
        keyboard = [
            [InlineKeyboardButton("🔍 Analyze URL", callback_data='analyze_url')],
            [InlineKeyboardButton("📁 Analyze File", callback_data='analyze_file')],
            [InlineKeyboardButton("🌐 Analyze IP", callback_data='analyze_ip')],
            [InlineKeyboardButton("🔢 Analyze Hash", callback_data='analyze_hash')],
            [InlineKeyboardButton("📊 View IOCs", callback_data='view_iocs')],
            [InlineKeyboardButton("📈 Statistics", callback_data='statistics')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        welcome_msg = """
🛡️ **SOC AI Agent** 🛡️

Welcome to your Security Operations Center AI Assistant!

**Available Commands:**
• `/start` - Show this menu
• `/help` - Get detailed help
• `/upload_iocs` - Upload IOC file (Admin only)

**Analysis Capabilities:**
• URL Security Analysis
• File Malware Detection
• IP Reputation Check
• Hash Verification
• Threat Intelligence Lookup

Choose an option below to begin:
        """
        
        await update.message.reply_text(welcome_msg, reply_markup=reply_markup, parse_mode='Markdown')
    
    async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline keyboard button presses"""
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        if not self.is_authorized(user_id):
            await query.edit_message_text("❌ Unauthorized access.")
            return
        
        data = query.data
        
        if data == 'analyze_url':
            await query.edit_message_text("🔗 Please send me the URL you want to analyze.")
            context.user_data['expecting'] = 'url'
        
        elif data == 'analyze_file':
            await query.edit_message_text("📁 Please send me the file you want to analyze.")
            context.user_data['expecting'] = 'file'
        
        elif data == 'analyze_ip':
            await query.edit_message_text("🌐 Please send me the IP address you want to analyze.")
            context.user_data['expecting'] = 'ip'
        
        elif data == 'analyze_hash':
            await query.edit_message_text("🔢 Please send me the hash you want to analyze.")
            context.user_data['expecting'] = 'hash'
        
        elif data == 'view_iocs':
            await self.show_iocs(query)
        
        elif data == 'statistics':
            await self.show_statistics(query)
    
    async def analyze_url(self, url: str, user_id: int) -> str:
        """Analyze URL using VirusTotal and AI"""
        try:
            # VirusTotal URL analysis
            vt_results = await self.virustotal_url_scan(url)
            
            # Check against IOC database
            ioc_match = self.check_ioc_database(url, 'url')
            
            # AI-based analysis
            ai_analysis = await self.ai_analyze_text(f"Analyzing URL: {url}")
            
            # Combine results
            report = self.generate_url_report(url, vt_results, ioc_match, ai_analysis)
            
            # Save to history
            self.save_analysis_history(user_id, url, 'url', report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {e}")
            return f"❌ Error analyzing URL: {str(e)}"
    
    async def analyze_ip(self, ip: str, user_id: int) -> str:
        """Analyze IP using AbuseDB and VirusTotal"""
        try:
            # AbuseDB analysis
            abuse_results = await self.abusedb_ip_check(ip)
            
            # VirusTotal IP analysis
            vt_results = await self.virustotal_ip_scan(ip)
            
            # Check against IOC database
            ioc_match = self.check_ioc_database(ip, 'ip')
            
            # Generate report
            report = self.generate_ip_report(ip, abuse_results, vt_results, ioc_match)
            
            # Save to history
            self.save_analysis_history(user_id, ip, 'ip', report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error analyzing IP {ip}: {e}")
            return f"❌ Error analyzing IP: {str(e)}"
    
    async def analyze_hash(self, hash_value: str, user_id: int) -> str:
        """Analyze hash using VirusTotal"""
        try:
            # VirusTotal hash analysis
            vt_results = await self.virustotal_hash_scan(hash_value)
            
            # Check against IOC database
            ioc_match = self.check_ioc_database(hash_value, 'hash')
            
            # Generate report
            report = self.generate_hash_report(hash_value, vt_results, ioc_match)
            
            # Save to history
            self.save_analysis_history(user_id, hash_value, 'hash', report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error analyzing hash {hash_value}: {e}")
            return f"❌ Error analyzing hash: {str(e)}"
    
    async def analyze_file(self, file_path: str, user_id: int) -> str:
        """Analyze file using VirusTotal and AI"""
        try:
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            
            # Get file type
            file_type = magic.from_file(file_path, mime=True)
            
            # VirusTotal file analysis
            vt_results = await self.virustotal_file_scan(file_path)
            
            # Check against IOC database
            ioc_match = self.check_ioc_database(file_hash, 'hash')
            
            # Generate report
            report = self.generate_file_report(file_path, file_hash, file_type, vt_results, ioc_match)
            
            # Save to history
            self.save_analysis_history(user_id, file_hash, 'file', report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
            return f"❌ Error analyzing file: {str(e)}"
    
    async def virustotal_url_scan(self, url: str) -> Dict:
        """Scan URL with VirusTotal"""
        try:
            params = {
                'apikey': self.virustotal_api_key,
                'url': url
            }
            response = requests.post(f"{self.vt_base_url}/url/scan", data=params)
            return response.json()
        except Exception as e:
            logger.error(f"VirusTotal URL scan error: {e}")
            return {"error": str(e)}
    
    async def virustotal_ip_scan(self, ip: str) -> Dict:
        """Scan IP with VirusTotal"""
        try:
            params = {'apikey': self.virustotal_api_key, 'ip': ip}
            response = requests.get(f"{self.vt_base_url}/ip-address/report", params=params)
            return response.json()
        except Exception as e:
            logger.error(f"VirusTotal IP scan error: {e}")
            return {"error": str(e)}
    
    async def virustotal_hash_scan(self, hash_value: str) -> Dict:
        """Scan hash with VirusTotal"""
        try:
            params = {'apikey': self.virustotal_api_key, 'resource': hash_value}
            response = requests.get(f"{self.vt_base_url}/file/report", params=params)
            return response.json()
        except Exception as e:
            logger.error(f"VirusTotal hash scan error: {e}")
            return {"error": str(e)}
    
    async def virustotal_file_scan(self, file_path: str) -> Dict:
        """Scan file with VirusTotal"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': f}
                params = {'apikey': self.virustotal_api_key}
                response = requests.post(f"{self.vt_base_url}/file/scan", files=files, params=params)
            return response.json()
        except Exception as e:
            logger.error(f"VirusTotal file scan error: {e}")
            return {"error": str(e)}
    
    async def abusedb_ip_check(self, ip: str) -> Dict:
        """Check IP with AbuseDB"""
        try:
            headers = {
                'Key': self.abusedb_api_key,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': ''}
            response = requests.get(f"{self.abusedb_base_url}/check", headers=headers, params=params)
            return response.json()
        except Exception as e:
            logger.error(f"AbuseDB IP check error: {e}")
            return {"error": str(e)}
    
    def check_ioc_database(self, indicator: str, ioc_type: str) -> Optional[Dict]:
        """Check if indicator exists in IOC database"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM iocs WHERE indicator = ? AND type = ?",
            (indicator, ioc_type)
        )
        result = cursor.fetchone()
        if result:
            return {
                'id': result[0],
                'indicator': result[1],
                'type': result[2],
                'threat_level': result[3],
                'description': result[4],
                'source': result[5],
                'first_seen': result[6],
                'last_updated': result[7]
            }
        return None
    
    async def ai_analyze_text(self, text: str) -> Dict:
        """Analyze text using AI models"""
        try:
            if self.sentiment_analyzer:
                sentiment = self.sentiment_analyzer(text[:512])  # Limit text length
                return {
                    'sentiment': sentiment[0]['label'],
                    'confidence': sentiment[0]['score']
                }
            return {'error': 'AI models not available'}
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return {'error': str(e)}
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def generate_url_report(self, url: str, vt_results: Dict, ioc_match: Optional[Dict], ai_analysis: Dict) -> str:
        """Generate comprehensive URL analysis report"""
        report = f"🔗 **URL Analysis Report**\n\n"
        report += f"**Target:** `{url}`\n"
        report += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # VirusTotal Results
        if 'positives' in vt_results:
            report += f"**VirusTotal Results:**\n"
            report += f"• Detections: {vt_results.get('positives', 0)}/{vt_results.get('total', 0)}\n"
            if vt_results.get('positives', 0) > 0:
                report += f"• ⚠️ **THREAT DETECTED** ⚠️\n"
            else:
                report += f"• ✅ Clean\n"
        
        # IOC Database Match
        if ioc_match:
            report += f"\n**IOC Database Match:**\n"
            report += f"• ⚠️ **KNOWN THREAT** ⚠️\n"
            report += f"• Threat Level: {ioc_match['threat_level']}\n"
            report += f"• Description: {ioc_match['description']}\n"
            report += f"• Source: {ioc_match['source']}\n"
        
        # AI Analysis
        if 'sentiment' in ai_analysis:
            report += f"\n**AI Analysis:**\n"
            report += f"• Sentiment: {ai_analysis['sentiment']}\n"
            report += f"• Confidence: {ai_analysis['confidence']:.2f}\n"
        
        return report
    
    def generate_ip_report(self, ip: str, abuse_results: Dict, vt_results: Dict, ioc_match: Optional[Dict]) -> str:
        """Generate comprehensive IP analysis report"""
        report = f"🌐 **IP Analysis Report**\n\n"
        report += f"**Target:** `{ip}`\n"
        report += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # AbuseDB Results
        if 'data' in abuse_results:
            data = abuse_results['data']
            report += f"**AbuseDB Results:**\n"
            report += f"• Abuse Confidence: {data.get('abuseConfidencePercentage', 0)}%\n"
            report += f"• Country: {data.get('countryCode', 'Unknown')}\n"
            report += f"• ISP: {data.get('isp', 'Unknown')}\n"
            if data.get('abuseConfidencePercentage', 0) > 25:
                report += f"• ⚠️ **HIGH ABUSE CONFIDENCE** ⚠️\n"
        
        # VirusTotal Results
        if 'detected_urls' in vt_results:
            detected = len(vt_results['detected_urls'])
            report += f"\n**VirusTotal Results:**\n"
            report += f"• Detected URLs: {detected}\n"
            if detected > 0:
                report += f"• ⚠️ **MALICIOUS URLS DETECTED** ⚠️\n"
        
        # IOC Database Match
        if ioc_match:
            report += f"\n**IOC Database Match:**\n"
            report += f"• ⚠️ **KNOWN THREAT** ⚠️\n"
            report += f"• Threat Level: {ioc_match['threat_level']}\n"
            report += f"• Description: {ioc_match['description']}\n"
        
        return report
    
    def generate_hash_report(self, hash_value: str, vt_results: Dict, ioc_match: Optional[Dict]) -> str:
        """Generate comprehensive hash analysis report"""
        report = f"🔢 **Hash Analysis Report**\n\n"
        report += f"**Target:** `{hash_value}`\n"
        report += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # VirusTotal Results
        if 'positives' in vt_results:
            report += f"**VirusTotal Results:**\n"
            report += f"• Detections: {vt_results.get('positives', 0)}/{vt_results.get('total', 0)}\n"
            if vt_results.get('positives', 0) > 0:
                report += f"• ⚠️ **MALWARE DETECTED** ⚠️\n"
                if 'scans' in vt_results:
                    report += f"• Detected by: {', '.join([k for k, v in vt_results['scans'].items() if v['detected']][:5])}\n"
            else:
                report += f"• ✅ Clean\n"
        
        # IOC Database Match
        if ioc_match:
            report += f"\n**IOC Database Match:**\n"
            report += f"• ⚠️ **KNOWN THREAT** ⚠️\n"
            report += f"• Threat Level: {ioc_match['threat_level']}\n"
            report += f"• Description: {ioc_match['description']}\n"
        
        return report
    
    def generate_file_report(self, file_path: str, file_hash: str, file_type: str, vt_results: Dict, ioc_match: Optional[Dict]) -> str:
        """Generate comprehensive file analysis report"""
        report = f"📁 **File Analysis Report**\n\n"
        report += f"**File:** `{os.path.basename(file_path)}`\n"
        report += f"**Hash:** `{file_hash}`\n"
        report += f"**Type:** `{file_type}`\n"
        report += f"**Size:** `{os.path.getsize(file_path)} bytes`\n"
        report += f"**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # VirusTotal Results
        if 'positives' in vt_results:
            report += f"**VirusTotal Results:**\n"
            report += f"• Detections: {vt_results.get('positives', 0)}/{vt_results.get('total', 0)}\n"
            if vt_results.get('positives', 0) > 0:
                report += f"• ⚠️ **MALWARE DETECTED** ⚠️\n"
            else:
                report += f"• ✅ Clean\n"
        
        # IOC Database Match
        if ioc_match:
            report += f"\n**IOC Database Match:**\n"
            report += f"• ⚠️ **KNOWN THREAT** ⚠️\n"
            report += f"• Threat Level: {ioc_match['threat_level']}\n"
            report += f"• Description: {ioc_match['description']}\n"
        
        return report
    
    def save_analysis_history(self, user_id: int, indicator: str, analysis_type: str, results: str):
        """Save analysis to history database"""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO analysis_history (user_id, indicator, analysis_type, results) VALUES (?, ?, ?, ?)",
            (user_id, indicator, analysis_type, results)
        )
        self.conn.commit()
    
    async def show_iocs(self, query):
        """Show IOCs from database"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total_iocs = cursor.fetchone()[0]
        
        cursor.execute("SELECT type, COUNT(*) FROM iocs GROUP BY type")
        type_counts = dict(cursor.fetchall())
        
        message = f"📊 **IOC Database Status**\n\n"
        message += f"**Total IOCs:** {total_iocs}\n\n"
        message += "**By Type:**\n"
        for ioc_type, count in type_counts.items():
            message += f"• {ioc_type}: {count}\n"
        
        await query.edit_message_text(message, parse_mode='Markdown')
    
    async def show_statistics(self, query):
        """Show analysis statistics"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analysis_history")
        total_analyses = cursor.fetchone()[0]
        
        cursor.execute("SELECT analysis_type, COUNT(*) FROM analysis_history GROUP BY analysis_type")
        type_counts = dict(cursor.fetchall())
        
        message = f"📈 **Analysis Statistics**\n\n"
        message += f"**Total Analyses:** {total_analyses}\n\n"
        message += "**By Type:**\n"
        for analysis_type, count in type_counts.items():
            message += f"• {analysis_type}: {count}\n"
        
        await query.edit_message_text(message, parse_mode='Markdown')
    
    async def message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages and files"""
        user_id = update.effective_user.id
        
        if not self.is_authorized(user_id):
            await update.message.reply_text("❌ Unauthorized access.")
            return
        
        expecting = context.user_data.get('expecting')
        
        if update.message.document:
            # Handle file upload
            if expecting == 'file':
                await update.message.reply_text("📥 Analyzing file... Please wait.")
                
                file = await context.bot.get_file(update.message.document.file_id)
                file_path = f"temp_{update.message.document.file_name}"
                await file.download_to_drive(file_path)
                
                result = await self.analyze_file(file_path, user_id)
                
                # Clean up temp file
                os.remove(file_path)
                
                await update.message.reply_text(result, parse_mode='Markdown')
                context.user_data.pop('expecting', None)
        
        elif update.message.text:
            text = update.message.text.strip()
            
            if expecting == 'url':
                await update.message.reply_text("🔍 Analyzing URL... Please wait.")
                result = await self.analyze_url(text, user_id)
                await update.message.reply_text(result, parse_mode='Markdown')
                context.user_data.pop('expecting', None)
            
            elif expecting == 'ip':
                await update.message.reply_text("🌐 Analyzing IP... Please wait.")
                result = await self.analyze_ip(text, user_id)
                await update.message.reply_text(result, parse_mode='Markdown')
                context.user_data.pop('expecting', None)
            
            elif expecting == 'hash':
                await update.message.reply_text("🔢 Analyzing hash... Please wait.")
                result = await self.analyze_hash(text, user_id)
                await update.message.reply_text(result, parse_mode='Markdown')
                context.user_data.pop('expecting', None)
            
            else:
                # Auto-detect type and analyze
                await self.auto_analyze(update, context, text)
    
    async def auto_analyze(self, update: Update, context: ContextTypes.DEFAULT_TYPE, text: str):
        """Auto-detect and analyze input"""
        user_id = update.effective_user.id
        
        # IP address pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        
        # Hash patterns
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        # URL pattern
        url_pattern = r'https?://[^\s]+'
        
        if re.match(url_pattern, text):
            await update.message.reply_text("🔗 URL detected. Analyzing...")
            result = await self.analyze_url(text, user_id)
            await update.message.reply_text(result, parse_mode='Markdown')
        
        elif re.match(ip_pattern, text):
            await update.message.reply_text("🌐 IP address detected. Analyzing...")
            result = await self.analyze_ip(text, user_id)
            await update.message.reply_text(result, parse_mode='Markdown')
        
        elif re.match(sha256_pattern, text) or re.match(sha1_pattern, text) or re.match(md5_pattern, text):
            await update.message.reply_text("🔢 Hash detected. Analyzing...")
            result = await self.analyze_hash(text, user_id)
            await update.message.reply_text(result, parse_mode='Markdown')
        
        else:
            keyboard = [
                [InlineKeyboardButton("🔗 Analyze as URL", callback_data='analyze_url')],
                [InlineKeyboardButton("🌐 Analyze as IP", callback_data='analyze_ip')],
                [InlineKeyboardButton("🔢 Analyze as Hash", callback_data='analyze_hash')]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text(
                "🤔 I couldn't auto-detect the type. Please choose:",
                reply_markup=reply_markup
            )
    
    async def upload_iocs(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Upload IOCs from file (Admin only)"""
        user_id = update.effective_user.id
        
        if user_id != self.authorized_users[0]:  # Only first user is admin
            await update.message.reply_text("❌ Admin access required.")
            return
        
        await update.message.reply_text(
            "📤 **IOC Upload**\n\n"
            "Please send a JSON file with the following format:\n"
            "```json\n"
            "[\n"
            "  {\n"
            "    \"indicator\": \"example.com\",\n"
            "    \"type\": \"domain\",\n"
            "    \"threat_level\": \"high\",\n"
            "    \"description\": \"Malicious domain\",\n"
            "    \"source\": \"ThreatFeed\"\n"
            "  }\n"
            "]\n"
            "```",
            parse_mode='Markdown'
        )
        context.user_data['expecting'] = 'ioc_file'
    
    def process_ioc_file(self, file_path: str) -> str:
        """Process uploaded IOC file"""
        try:
            with open(file_path, 'r') as f:
                iocs = json.load(f)
            
            cursor = self.conn.cursor()
            added = 0
            updated = 0
            
            for ioc in iocs:
                indicator = ioc.get('indicator')
                ioc_type = ioc.get('type')
                threat_level = ioc.get('threat_level', 'medium')
                description = ioc.get('description', '')
                source = ioc.get('source', 'Manual Upload')
                
                # Check if IOC exists
                cursor.execute("SELECT id FROM iocs WHERE indicator = ?", (indicator,))
                if cursor.fetchone():
                    # Update existing
                    cursor.execute(
                        "UPDATE iocs SET threat_level = ?, description = ?, source = ?, last_updated = CURRENT_TIMESTAMP WHERE indicator = ?",
                        (threat_level, description, source, indicator)
                    )
                    updated += 1
                else:
                    # Add new
                    cursor.execute(
                        "INSERT INTO iocs (indicator, type, threat_level, description, source) VALUES (?, ?, ?, ?, ?)",
                        (indicator, ioc_type, threat_level, description, source)
                    )
                    added += 1
            
            self.conn.commit()
            return f"✅ IOCs processed successfully!\n\n• Added: {added}\n• Updated: {updated}"
            
        except Exception as e:
            logger.error(f"Error processing IOC file: {e}")
            return f"❌ Error processing IOC file: {str(e)}"
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Help command"""
        help_text = """
🛡️ **SOC AI Agent Help** 🛡️

**Commands:**
• `/start` - Main menu
• `/help` - This help message
• `/upload_iocs` - Upload IOC file (Admin only)

**Analysis Types:**
• **URL Analysis** - Check URLs for malicious content
• **IP Analysis** - Check IP reputation and abuse reports
• **Hash Analysis** - Verify file hashes against threat databases
• **File Analysis** - Scan uploaded files for malware

**Features:**
• VirusTotal integration
• AbuseDB integration
• IOC database matching
• AI-powered analysis
• Analysis history tracking

**Auto-Detection:**
Send any URL, IP, or hash and I'll automatically detect and analyze it!

**Supported Formats:**
• URLs: http://example.com
• IPs: 192.168.1.1
• Hashes: MD5, SHA1, SHA256
• Files: Any file type

**Data Sources:**
• VirusTotal API
• AbuseDB API
• Custom IOC Database
• Hugging Face AI Models
        """
        await update.message.reply_text(help_text, parse_mode='Markdown')

def main():
    """Main function to run the bot"""
    # Initialize SOC Agent
    soc_agent = SOCAgent()
    
    # Create application
    application = Application.builder().token(soc_agent.telegram_token).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", soc_agent.start))
    application.add_handler(CommandHandler("help", soc_agent.help_command))
    application.add_handler(CommandHandler("upload_iocs", soc_agent.upload_iocs))
    application.add_handler(CallbackQueryHandler(soc_agent.button_handler))
    application.add_handler(MessageHandler(filters.TEXT | filters.Document, soc_agent.message_handler))
    
    # Start the bot
    logger.info("Starting SOC AI Agent...")
    application.run_polling()

if __name__ == '__main__':
    main()
