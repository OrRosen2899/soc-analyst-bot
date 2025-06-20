#!/usr/bin/env python3
"""
Complete Secure SOC AI Agent with Full Threat Analysis & IOC Database
"""

import os
import re
import json
import sqlite3
import asyncio
import aiohttp
import ipaddress
import random
import string
import hashlib
from datetime import datetime, timedelta
from dotenv import load_dotenv
import logging
import secrets
import time

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
    level=logging.INFO
)
logger = logging.getLogger(__name__)

class SecureSOCAgent:
    def __init__(self):
        # Bot configuration
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.allowed_users = self._parse_allowed_users()
        
        # Verification settings
        self.verification_code = os.getenv('VERIFICATION_CODE', 'SOC2025!')
        self.admin_approval_required = os.getenv('ADMIN_APPROVAL', 'true').lower() == 'true'
        self.admin_user_ids = self._parse_admin_users()
        self.verification_timeout = int(os.getenv('VERIFICATION_TIMEOUT', '300'))  # 5 minutes
        
        # API configurations
        self.virustotal_api = os.getenv('VIRUSTOTAL_API_KEY')
        self.abusedb_api = os.getenv('ABUSEDB_API_KEY')
        self.ollama_url = os.getenv('OLLAMA_URL', 'http://localhost:11434')
        self.ollama_model = os.getenv('OLLAMA_MODEL', 'llama2')
        
        # Database
        self.db_path = os.getenv('DATABASE_PATH', 'soc_agent_secure.db')
        self.init_database()
        self.populate_sample_iocs()  # Add sample IOCs for testing
        
        # User sessions and verification tracking
        self.user_sessions = {}
        self.verification_attempts = {}
        
        # Analysis scoring thresholds
        self.malicious_threshold = 70  # 70+ = malicious (raised from 60)
        self.suspicious_threshold = 35  # 35-69 = suspicious (raised from 30)
        
    def _parse_allowed_users(self):
        """Parse allowed user IDs from environment"""
        allowed = os.getenv('ALLOWED_USER_IDS', '')
        if not allowed:
            return set()
        return set(int(uid.strip()) for uid in allowed.split(',') if uid.strip())
    
    def _parse_admin_users(self):
        """Parse admin user IDs from environment"""
        admins = os.getenv('ADMIN_USER_IDS', '')
        if not admins:
            return set()
        return set(int(uid.strip()) for uid in admins.split(',') if uid.strip())
    
    def is_admin(self, user_id: int) -> bool:
        """Check if user is an admin"""
        return user_id in self.admin_user_ids
    
    def init_database(self):
        """Initialize database with verification tables"""
        try:
            conn = sqlite3.connect(self.db_path)
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
            
            # Create analysis history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    indicator TEXT,
                    indicator_type TEXT,
                    verdict TEXT,
                    score INTEGER,
                    analysis_data TEXT,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def populate_sample_iocs(self):
        """Populate database with sample IOCs for testing"""
        sample_iocs = [
            # Malicious IPs
            ('1.2.3.4', 'ip', 'Known botnet C&C server', 'Botnet', 'Threat Intelligence Feed', 95),
            ('5.6.7.8', 'ip', 'Malware distribution server', 'Malware', 'Internal SOC', 90),
            ('9.10.11.12', 'ip', 'Phishing campaign infrastructure', 'Phishing', 'External Feed', 85),
            ('192.168.100.50', 'ip', 'Internal compromised host', 'Compromise', 'SOC Analysis', 80),
            
            # Malicious hashes
            ('d41d8cd98f00b204e9800998ecf8427e', 'md5', 'Known malware sample', 'Malware', 'VirusTotal', 98),
            ('adc83b19e793491b1c6ea0fd8b46cd9f32e592fc', 'sha1', 'Trojan dropper', 'Trojan', 'Sandbox Analysis', 95),
            ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256', 'Ransomware payload', 'Ransomware', 'Internal Analysis', 99),
            
            # Malicious domains
            ('malicious-site.com', 'domain', 'Phishing domain', 'Phishing', 'URL Analysis', 90),
            ('bad-domain.net', 'domain', 'Malware C&C domain', 'Malware', 'DNS Monitoring', 85),
            ('evil-site.org', 'domain', 'Scam website', 'Scam', 'Brand Protection', 75),
            
            # Suspicious but not definitively malicious
            ('suspicious-ip.example', 'ip', 'Unusual network activity', 'Suspicious', 'Network Monitoring', 45),
            ('questionable.site', 'domain', 'Recently registered domain', 'Suspicious', 'Domain Analysis', 40),
        ]
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for indicator, ioc_type, description, threat_type, source, confidence in sample_iocs:
                cursor.execute('''
                    INSERT OR IGNORE INTO iocs 
                    (indicator, type, description, threat_type, source, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (indicator, ioc_type, description, threat_type, source, confidence))
            
            conn.commit()
            conn.close()
            logger.info("Sample IOCs populated successfully")
            
        except Exception as e:
            logger.error(f"Error populating sample IOCs: {e}")
    
    def add_ioc_to_database(self, indicator: str, ioc_type: str, description: str, 
                           threat_type: str, source: str, confidence: int):
        """Add new IOC to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO iocs 
                (indicator, type, description, threat_type, source, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (indicator, ioc_type, description, threat_type, source, confidence))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Error adding IOC to database: {e}")
            return False
    
    def is_user_verified(self, user_id: int) -> tuple[bool, dict]:
        """Check if user is verified and return their info"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, username, access_level, status, verified_at, session_token
                FROM verified_users 
                WHERE user_id = ? AND status = 'active'
            ''', (user_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return True, {
                    'user_id': result[0],
                    'username': result[1],
                    'access_level': result[2],
                    'status': result[3],
                    'verified_at': result[4],
                    'session_token': result[5]
                }
            return False, {}
            
        except Exception as e:
            logger.error(f"Error checking user verification: {e}")
            return False, {}
    
    def log_verification_attempt(self, user_id: int, username: str, attempt_type: str, 
                               attempt_data: str, success: bool):
        """Log verification attempts for security monitoring"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO verification_attempts 
                (user_id, username, attempt_type, attempt_data, success)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, username, attempt_type, attempt_data, success))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging verification attempt: {e}")
    
    def add_verified_user(self, user_id: int, username: str, first_name: str, 
                         verification_method: str, verified_by: int = None):
        """Add user to verified users list"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            session_token = secrets.token_urlsafe(32)
            
            cursor.execute('''
                INSERT OR REPLACE INTO verified_users 
                (user_id, username, first_name, verification_method, verified_by, session_token)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, first_name, verification_method, verified_by, session_token))
            
            conn.commit()
            conn.close()
            
            return session_token
            
        except Exception as e:
            logger.error(f"Error adding verified user: {e}")
            return None
    
    def remove_verified_user(self, user_id: int) -> bool:
        """Remove user from verified users list"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM verified_users WHERE user_id = ?', (user_id,))
            
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()
            
            return affected_rows > 0
            
        except Exception as e:
            logger.error(f"Error removing verified user: {e}")
            return False
    
    def get_all_verified_users(self):
        """Get all verified users"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, username, first_name, verification_method, 
                       verified_at, verified_by, access_level, status, last_activity
                FROM verified_users 
                ORDER BY verified_at DESC
            ''')
            
            results = cursor.fetchall()
            conn.close()
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting verified users: {e}")
            return []
    
    def get_pending_approval(self, user_id: int):
        """Get pending approval request for user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, user_id, username, first_name, requested_at, verification_code
                FROM pending_approvals 
                WHERE user_id = ? AND status = 'pending'
            ''', (user_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting pending approval: {e}")
            return None
    
    def update_approval_status(self, user_id: int, status: str) -> bool:
        """Update approval request status"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE pending_approvals 
                SET status = ? 
                WHERE user_id = ? AND status = 'pending'
            ''', (status, user_id))
            
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()
            
            return affected_rows > 0
            
        except Exception as e:
            logger.error(f"Error updating approval status: {e}")
            return False
    
    def rate_limit_check(self, user_id: int) -> bool:
        """Check if user is rate limited for verification attempts"""
        current_time = time.time()
        
        if user_id not in self.verification_attempts:
            self.verification_attempts[user_id] = []
        
        # Remove attempts older than 1 hour
        self.verification_attempts[user_id] = [
            attempt for attempt in self.verification_attempts[user_id]
            if current_time - attempt < 3600
        ]
        
        # Allow max 5 attempts per hour
        if len(self.verification_attempts[user_id]) >= 5:
            return False
        
        self.verification_attempts[user_id].append(current_time)
        return True
    
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
    
    def check_local_iocs(self, indicator: str) -> dict:
        """Check indicator against local IOC database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT description, threat_type, source, confidence, created_at
                FROM iocs 
                WHERE indicator = ? COLLATE NOCASE
            ''', (indicator,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                desc, threat_type, source, confidence, created = result
                return {
                    'found': True,
                    'description': desc,
                    'threat_type': threat_type,
                    'source': source,
                    'confidence': confidence,
                    'created_at': created,
                    'score': confidence  # Use confidence as score
                }
            
            return {'found': False, 'score': 0}
            
        except Exception as e:
            logger.error(f"Error checking local IOCs: {e}")
            return {'found': False, 'error': str(e), 'score': 0}
    
    async def check_virustotal(self, indicator: str, indicator_type: str) -> dict:
        """Check indicator with VirusTotal API"""
        if not self.virustotal_api:
            return {'available': False, 'error': 'API key not configured', 'score': 0}
        
        try:
            headers = {
                'X-Apikey': self.virustotal_api,
                'User-Agent': 'SOC-Agent/1.0'
            }
            
            async with aiohttp.ClientSession() as session:
                if indicator_type in ['ip']:
                    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                    params = {'apikey': self.virustotal_api, 'ip': indicator}
                elif indicator_type in ['domain', 'url']:
                    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                    params = {'apikey': self.virustotal_api, 'domain': indicator.replace('http://', '').replace('https://', '').split('/')[0]}
                elif indicator_type in ['md5', 'sha1', 'sha256']:
                    url = f"https://www.virustotal.com/vtapi/v2/file/report"
                    params = {'apikey': self.virustotal_api, 'resource': indicator}
                else:
                    return {'available': False, 'error': 'Unsupported indicator type', 'score': 0}
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('response_code') == 1:
                            if indicator_type in ['md5', 'sha1', 'sha256']:
                                positives = data.get('positives', 0)
                                total = data.get('total', 0)
                                scan_date = data.get('scan_date', 'Unknown')
                                permalink = data.get('permalink', '')
                                
                                if total > 0:
                                    detection_ratio = (positives / total) * 100
                                    score = min(detection_ratio * 1.5, 100)  # Scale up detection ratio
                                else:
                                    score = 0
                                
                                return {
                                    'available': True,
                                    'found': positives > 0,
                                    'positives': positives,
                                    'total': total,
                                    'detection_ratio': detection_ratio if total > 0 else 0,
                                    'scan_date': scan_date,
                                    'permalink': permalink,
                                    'score': score
                                }
                            else:
                                # For IPs and domains
                                detected_urls = data.get('detected_urls', [])
                                detected_samples = data.get('detected_communicating_samples', [])
                                
                                threat_score = 0
                                if detected_urls:
                                    threat_score += min(len(detected_urls) * 10, 50)
                                if detected_samples:
                                    threat_score += min(len(detected_samples) * 5, 30)
                                
                                return {
                                    'available': True,
                                    'found': len(detected_urls) > 0 or len(detected_samples) > 0,
                                    'detected_urls': len(detected_urls),
                                    'detected_samples': len(detected_samples),
                                    'score': min(threat_score, 80)
                                }
                        else:
                            return {'available': True, 'found': False, 'score': 0}
                    else:
                        return {'available': False, 'error': f'API error: {response.status}', 'score': 0}
                        
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
            return {'available': False, 'error': str(e), 'score': 0}
    
    async def check_abuseipdb(self, indicator: str, indicator_type: str) -> dict:
        """Check IP with AbuseIPDB API"""
        if indicator_type != 'ip' or not self.abusedb_api:
            return {'available': False, 'error': 'Not applicable or API key not configured', 'score': 0}
        
        try:
            headers = {
                'Key': self.abusedb_api,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': indicator,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with aiohttp.ClientSession() as session:
                url = "https://api.abuseipdb.com/api/v2/check"
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'data' in data:
                            abuse_data = data['data']
                            confidence = abuse_data.get('abuseConfidencePercentage', 0)
                            is_public = abuse_data.get('isPublic', True)
                            usage_type = abuse_data.get('usageType', 'Unknown')
                            country = abuse_data.get('countryCode', 'Unknown')
                            total_reports = abuse_data.get('totalReports', 0)
                            
                            # Calculate score based on abuse confidence
                            score = confidence * 0.8  # Scale abuse confidence to our scoring system
                            
                            return {
                                'available': True,
                                'found': confidence > 0,
                                'abuse_confidence': confidence,
                                'is_public': is_public,
                                'usage_type': usage_type,
                                'country': country,
                                'total_reports': total_reports,
                                'score': score
                            }
                    else:
                        return {'available': False, 'error': f'API error: {response.status}', 'score': 0}
                        
        except Exception as e:
            logger.error(f"AbuseIPDB API error: {e}")
            return {'available': False, 'error': str(e), 'score': 0}
    
    async def ai_analysis(self, indicator: str, indicator_type: str, context_data: dict) -> dict:
        """Perform AI analysis of the indicator"""
        try:
            # Get context from other sources
            ioc_found = context_data.get('ioc', {}).get('found', False)
            vt_found = context_data.get('virustotal', {}).get('found', False)
            abuse_found = context_data.get('abuseipdb', {}).get('found', False)
            
            # Prepare context for AI
            analysis_prompt = f"""
            You are a cybersecurity analyst. Analyze this {indicator_type} indicator for security threats: {indicator}
            
            Context from threat intelligence sources:
            - Local IOC Database: {'FOUND' if ioc_found else 'NOT FOUND'}
            - VirusTotal: {'THREATS DETECTED' if vt_found else 'CLEAN'}
            - AbuseIPDB: {'ABUSE REPORTED' if abuse_found else 'NO ABUSE'}
            
            Instructions:
            1. Consider the indicator type and context
            2. If it's a well-known legitimate service (google.com, 8.8.8.8, etc.), score it very low (0-10)
            3. Only assign high risk scores (60+) for clear threat indicators
            4. Be conservative with scoring - don't overestimate threats
            
            Provide a brief security analysis (max 200 words) covering:
            - Threat assessment and risk level
            - Potential attack vectors if malicious
            - Recommended security actions
            - Your confidence score (0-100)
            
            Format your response as:
            Risk Assessment: [assessment]
            Confidence: [0-100]
            """
            
            if self.ollama_url and self.ollama_model:
                # Use Ollama for AI analysis
                async with aiohttp.ClientSession() as session:
                    ollama_payload = {
                        "model": self.ollama_model,
                        "prompt": analysis_prompt,
                        "stream": False
                    }
                    
                    async with session.post(f"{self.ollama_url}/api/generate", 
                                          json=ollama_payload) as response:
                        if response.status == 200:
                            data = await response.json()
                            ai_response = data.get('response', 'No analysis available')
                            
                            # Extract confidence score from response
                            confidence_match = re.search(r'confidence[:\s]*(\d+)', ai_response.lower())
                            ai_confidence = int(confidence_match.group(1)) if confidence_match else 50
                            
                            # Calculate AI risk score based on response content and context
                            ai_score = self.calculate_ai_risk_score(ai_response, indicator, indicator_type, context_data)
                            
                            return {
                                'available': True,
                                'analysis': ai_response,
                                'confidence': ai_confidence,
                                'score': ai_score
                            }
            
            # Fallback: Rule-based analysis
            return self.rule_based_analysis(indicator, indicator_type, context_data)
            
        except Exception as e:
            logger.error(f"AI analysis error: {e}")
            return self.rule_based_analysis(indicator, indicator_type, context_data)
    
    def calculate_ai_risk_score(self, ai_response: str, indicator: str, indicator_type: str, context_data: dict) -> float:
        """Calculate risk score based on AI response and context"""
        ai_response_lower = ai_response.lower()
        
        # Known legitimate indicators should get very low scores
        legitimate_domains = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com']
        clean_ips = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        
        if indicator.lower() in legitimate_domains or indicator in clean_ips:
            return 0  # Force legitimate services to 0 risk
        
        # Base score from other sources
        base_score = 0
        if context_data.get('ioc', {}).get('found'):
            base_score += 40
        if context_data.get('virustotal', {}).get('found'):
            base_score += 30
        if context_data.get('abuseipdb', {}).get('found'):
            base_score += 20
        
        # AI sentiment analysis
        threat_keywords = ['malicious', 'dangerous', 'threat', 'attack', 'suspicious', 'phishing', 'malware']
        safe_keywords = ['legitimate', 'safe', 'clean', 'benign', 'trusted', 'official']
        
        threat_count = sum(1 for keyword in threat_keywords if keyword in ai_response_lower)
        safe_count = sum(1 for keyword in safe_keywords if keyword in ai_response_lower)
        
        # Calculate AI contribution
        if safe_count > threat_count:
            ai_contribution = max(0, 10 - (safe_count * 5))  # Reduce score for safe keywords
        else:
            ai_contribution = min(40, threat_count * 10)  # Increase score for threat keywords
        
        # Combine scores but cap at reasonable levels
        final_score = min(base_score + ai_contribution, 85)
        
        return final_score
    
    def rule_based_analysis(self, indicator: str, indicator_type: str, context_data: dict) -> dict:
        """Fallback rule-based analysis"""
        analysis_text = ""
        risk_score = 0
        
        # Known legitimate domains (should be very low risk)
        legitimate_domains = {
            'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'twitter.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'wikipedia.org', 'reddit.com', 'instagram.com', 'whatsapp.com', 'zoom.us',
            'dropbox.com', 'netflix.com', 'paypal.com', 'ebay.com', 'adobe.com',
            'salesforce.com', 'oracle.com', 'ibm.com', 'cloudflare.com', 'mozilla.org'
        }
        
        # Known clean IPs (public DNS, etc.)
        clean_ips = {
            '8.8.8.8', '8.8.4.4',  # Google DNS
            '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
            '208.67.222.222', '208.67.220.220',  # OpenDNS
            '9.9.9.9', '149.112.112.112'  # Quad9 DNS
        }
        
        if indicator_type == 'ip':
            # Check if it's a known clean IP
            if indicator in clean_ips:
                analysis_text = "Known legitimate public service (DNS resolver, CDN, etc.)"
                risk_score = 0
            else:
                try:
                    ip_obj = ipaddress.ip_address(indicator)
                    if ip_obj.is_private:
                        analysis_text = "Private IP address - internal network range. Monitor for unusual activity if flagged."
                        risk_score = 5  # Very low risk for private IPs
                    elif ip_obj.is_loopback:
                        analysis_text = "Loopback address - localhost reference, typically benign."
                        risk_score = 0
                    elif ip_obj.is_multicast:
                        analysis_text = "Multicast address - used for group communication, typically legitimate."
                        risk_score = 2
                    else:
                        analysis_text = "Public IP address - requires reputation checking to assess threat level."
                        risk_score = 10  # Neutral score for unknown public IPs
                except:
                    analysis_text = "Invalid IP format detected."
                    risk_score = 5
                    
        elif indicator_type in ['domain', 'url']:
            # Extract domain from URL if needed
            domain = indicator.lower()
            if domain.startswith(('http://', 'https://')):
                domain = domain.split('/')[2]
            
            # Check against known legitimate domains
            if domain in legitimate_domains:
                analysis_text = f"Well-known legitimate domain ({domain}) - established service provider."
                risk_score = 0
            elif domain.endswith(('.gov', '.edu', '.mil')):
                analysis_text = "Government, educational, or military domain - typically legitimate."
                risk_score = 2
            elif len(domain) < 4:
                analysis_text = "Very short domain name - potentially suspicious or typosquatting attempt."
                risk_score = 45
            elif any(suspicious in domain for suspicious in ['xn--', 'bit.ly', 'tinyurl', 't.co']) and domain not in ['bit.ly', 'tinyurl.com', 't.co']:
                analysis_text = "Domain contains suspicious patterns - possible IDN homograph attack or suspicious shortener."
                risk_score = 50
            elif domain.count('-') > 3:
                analysis_text = "Domain contains many hyphens - possible suspicious or automatically generated domain."
                risk_score = 35
            elif any(keyword in domain for keyword in ['login', 'secure', 'bank', 'paypal', 'amazon', 'microsoft'] if domain not in legitimate_domains):
                analysis_text = "Domain contains brand/security keywords - possible phishing attempt."
                risk_score = 60
            elif domain.endswith('.tk') or domain.endswith('.ml') or domain.endswith('.cf'):
                analysis_text = "Domain uses free TLD often associated with malicious activity."
                risk_score = 40
            else:
                analysis_text = "Standard domain format - appears normal, reputation check recommended."
                risk_score = 5  # Very low risk for normal-looking domains
                
        elif indicator_type in ['md5', 'sha1', 'sha256']:
            analysis_text = f"File hash ({indicator_type.upper()}) - requires reputation database lookup for threat assessment."
            risk_score = 15  # Neutral score for unknown hashes
        
        return {
            'available': True,
            'analysis': analysis_text,
            'confidence': 80,
            'score': risk_score
        }
    
    def calculate_overall_verdict(self, scores: dict) -> tuple[str, int, str]:
        """Calculate overall verdict based on all analysis scores"""
        total_score = 0
        weight_sum = 0
        
        # Weight different sources
        weights = {
            'ioc': 1.0,      # Local IOC database has highest weight
            'virustotal': 0.9,
            'abuseipdb': 0.8,
            'ai': 0.7        # Reduced AI weight to prevent overestimation
        }
        
        for source, weight in weights.items():
            if source in scores and scores[source].get('score', 0) > 0:
                total_score += scores[source]['score'] * weight
                weight_sum += weight
        
        # Calculate weighted average
        if weight_sum > 0:
            final_score = min(total_score / weight_sum, 100)
        else:
            final_score = 0
        
        # Special handling for very low scores - if all sources agree it's clean, ensure clean verdict
        all_scores = [scores.get(source, {}).get('score', 0) for source in weights.keys()]
        max_individual_score = max(all_scores) if all_scores else 0
        
        # If no source gives a score above 10, force clean verdict
        if max_individual_score <= 10:
            final_score = min(final_score, 10)
        
        # Determine verdict with updated thresholds
        if final_score >= self.malicious_threshold:
            verdict = "🔴 **MALICIOUS**"
            verdict_emoji = "🚨"
        elif final_score >= self.suspicious_threshold:
            verdict = "🟡 **SUSPICIOUS**"
            verdict_emoji = "⚠️"
        else:
            verdict = "🟢 **CLEAN**"
            verdict_emoji = "✅"
        
        return verdict, int(final_score), verdict_emoji
    
    def save_analysis_history(self, user_id: int, indicator: str, indicator_type: str, 
                            verdict: str, score: int, analysis_data: dict):
        """Save analysis to history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_history 
                (user_id, indicator, indicator_type, verdict, score, analysis_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, indicator, indicator_type, verdict, score, json.dumps(analysis_data)))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error saving analysis history: {e}")
    
    async def comprehensive_analysis(self, indicator: str, user_id: int) -> str:
        """Perform comprehensive analysis and return formatted result"""
        indicator = indicator.strip()
        indicator_type = self.detect_indicator_type(indicator)
        
        if indicator_type == 'unknown':
            return "❌ **Analysis Failed**\n\nUnable to detect indicator type. Please provide a valid IP, hash, or domain."
        
        # Start analysis message
        analysis_start_time = datetime.now()
        
        # Perform all checks concurrently
        analysis_tasks = {
            'ioc': asyncio.create_task(asyncio.to_thread(self.check_local_iocs, indicator)),
            'virustotal': asyncio.create_task(self.check_virustotal(indicator, indicator_type)),
            'abuseipdb': asyncio.create_task(self.check_abuseipdb(indicator, indicator_type))
        }
        
        # Wait for all checks to complete
        results = {}
        for source, task in analysis_tasks.items():
            try:
                results[source] = await task
            except Exception as e:
                logger.error(f"Error in {source} analysis: {e}")
                results[source] = {'available': False, 'error': str(e), 'score': 0}
        
        # Perform AI analysis with context
        results['ai'] = await self.ai_analysis(indicator, indicator_type, results)
        
        # Calculate overall verdict
        verdict, final_score, verdict_emoji = self.calculate_overall_verdict(results)
        
        # Save to history
        self.save_analysis_history(user_id, indicator, indicator_type, verdict, final_score, results)
        
        analysis_time = (datetime.now() - analysis_start_time).total_seconds()
        
        # Format comprehensive result
        result_message = f"""🛡️ **SOC THREAT ANALYSIS**

{verdict_emoji} **VERDICT**: {verdict}
📊 **Risk Score**: {final_score}/100
🔍 **Indicator**: `{indicator}`
📋 **Type**: {indicator_type.upper()}
⏱️ **Analysis Time**: {analysis_time:.2f}s

━━━━━━━━━━━━━━━━━━━━━━━━━

🏢 **IOC DATABASE**"""
        
        ioc_result = results.get('ioc', {})
        if ioc_result.get('found'):
            result_message += f"""
✅ **Found in Database**
🎯 **Threat Type**: {ioc_result.get('threat_type', 'Unknown')}
📝 **Description**: {ioc_result.get('description', 'No description')}
🔗 **Source**: {ioc_result.get('source', 'Unknown')}
📊 **Confidence**: {ioc_result.get('confidence', 0)}%"""
        else:
            result_message += "\n❌ **Not Found** - No matches in local IOC database"
        
        # VirusTotal Results
        result_message += "\n\n🦠 **VIRUSTOTAL**"
        vt_result = results.get('virustotal', {})
        if vt_result.get('available'):
            if vt_result.get('found'):
                if indicator_type in ['md5', 'sha1', 'sha256']:
                    result_message += f"""
🚨 **Threat Detected**
🎯 **Detections**: {vt_result.get('positives', 0)}/{vt_result.get('total', 0)}
📊 **Detection Ratio**: {vt_result.get('detection_ratio', 0):.1f}%
📅 **Scan Date**: {vt_result.get('scan_date', 'Unknown')}"""
                else:
                    result_message += f"""
🚨 **Threat Activity Detected**
🌐 **Malicious URLs**: {vt_result.get('detected_urls', 0)}
📁 **Malware Samples**: {vt_result.get('detected_samples', 0)}"""
            else:
                result_message += "\n✅ **Clean** - No threats detected"
        else:
            error_msg = vt_result.get('error', 'API not available')
            result_message += f"\n⚠️ **Unavailable** - {error_msg}"
        
        # AbuseIPDB Results (IP only)
        if indicator_type == 'ip':
            result_message += "\n\n🚫 **ABUSEIPDB**"
            abuse_result = results.get('abuseipdb', {})
            if abuse_result.get('available'):
                if abuse_result.get('found'):
                    result_message += f"""
🚨 **Abuse Reports Found**
📊 **Abuse Confidence**: {abuse_result.get('abuse_confidence', 0)}%
📝 **Total Reports**: {abuse_result.get('total_reports', 0)}
🌍 **Country**: {abuse_result.get('country', 'Unknown')}
🏢 **Usage Type**: {abuse_result.get('usage_type', 'Unknown')}"""
                else:
                    result_message += "\n✅ **Clean** - No abuse reports"
            else:
                error_msg = abuse_result.get('error', 'API not available')
                result_message += f"\n⚠️ **Unavailable** - {error_msg}"
        
        # AI Analysis
        result_message += "\n\n🤖 **AI ANALYSIS**"
        ai_result = results.get('ai', {})
        if ai_result.get('available'):
            ai_analysis = ai_result.get('analysis', 'No analysis available')
            result_message += f"""
📊 **AI Confidence**: {ai_result.get('confidence', 0)}%
📝 **Analysis**: {ai_analysis}"""
        else:
            result_message += "\n⚠️ **Unavailable** - AI analysis not accessible"
        
        # Recommendations
        result_message += "\n\n💡 **RECOMMENDATIONS**"
        if final_score >= self.malicious_threshold:
            result_message += """
🚨 **IMMEDIATE ACTION REQUIRED**
• Block this indicator immediately
• Check for related IOCs
• Investigate affected systems
• Update security controls"""
        elif final_score >= self.suspicious_threshold:
            result_message += """
⚠️ **ENHANCED MONITORING**
• Monitor closely for suspicious activity
• Consider temporary restrictions
• Gather additional intelligence
• Review associated indicators"""
        else:
            result_message += """
✅ **CONTINUE MONITORING**
• Appears clean based on current intel
• Maintain standard monitoring
• Report if behavior changes
• Regular reputation checks"""
        
        result_message += f"\n\n📅 **Analysis completed at**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return result_message
    
    def generate_challenge(self) -> tuple[str, str]:
        """Generate a simple anti-bot challenge"""
        challenge_types = ["math", "word", "pattern"]
        challenge_type = random.choice(challenge_types)
        
        if challenge_type == "math":
            # Simple math problem
            a = random.randint(1, 20)
            b = random.randint(1, 20)
            operation = random.choice(['+', '-'])
            
            if operation == '+':
                question = f"What is {a} + {b}?"
                answer = str(a + b)
            else:
                if a < b:  # Ensure positive result
                    a, b = b, a
                question = f"What is {a} - {b}?"
                answer = str(a - b)
                
        elif challenge_type == "word":
            # Word reversal
            words = ["SECURITY", "ANALYST", "THREAT", "NETWORK", "MALWARE", "FIREWALL"]
            word = random.choice(words)
            question = f"Type this word backwards: {word}"
            answer = word[::-1].lower()
            
        else:  # pattern
            # Complete the pattern
            patterns = [
                ("1, 2, 3, ?, 5", "4"),
                ("A, B, C, ?, E", "D"),
                ("2, 4, 6, ?, 10", "8"),
                ("MON, TUE, ?, THU", "WED")
            ]
            pattern, answer = random.choice(patterns)
            question = f"Complete the pattern: {pattern}"
        
        return question, answer.lower()
    
    def has_pending_approval(self, user_id: int) -> bool:
        """Check if user has pending approval request"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id FROM pending_approvals 
                WHERE user_id = ? AND status = 'pending'
            ''', (user_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
            
        except Exception as e:
            logger.error(f"Error checking pending approval: {e}")
            return False
    
    def create_approval_request(self, user_id: int, username: str, first_name: str) -> bool:
        """Create approval request"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO pending_approvals 
                (user_id, username, first_name, verification_code)
                VALUES (?, ?, ?, ?)
            ''', (user_id, username, first_name, secrets.token_hex(8)))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error creating approval request: {e}")
            return False
    
    def get_verified_keyboard(self):
        """Get keyboard for verified users"""
        keyboard = [
            [KeyboardButton("📊 IOC Stats"), KeyboardButton("🔍 Quick Scan")],
            [KeyboardButton("ℹ️ Help"), KeyboardButton("🔐 My Account")]
        ]
        return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    def get_admin_keyboard(self):
        """Get keyboard for admin users"""
        keyboard = [
            [KeyboardButton("📊 IOC Stats"), KeyboardButton("🔍 Quick Scan")],
            [KeyboardButton("👥 Manage Users"), KeyboardButton("📋 Pending Approvals")],
            [KeyboardButton("ℹ️ Help"), KeyboardButton("🔐 My Account")]
        ]
        return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    def update_user_activity(self, user_id: int):
        """Update user's last activity timestamp"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE verified_users 
                SET last_activity = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error updating user activity: {e}")
    
    # Command handlers
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command with verification check"""
        user = update.effective_user
        user_id = user.id
        
        # Check if user is already verified
        is_verified, user_info = self.is_user_verified(user_id)
        
        if is_verified:
            # Update last activity
            self.update_user_activity(user_id)
            
            # Determine keyboard based on admin status
            keyboard = self.get_admin_keyboard() if self.is_admin(user_id) else self.get_verified_keyboard()
            
            admin_status = " (Admin)" if self.is_admin(user_id) else ""
            
            await update.message.reply_text(
                f"🛡️ **SOC AI Agent - Secure Access**\n\n"
                f"Welcome back, {user.first_name}!{admin_status}\n"
                f"🔐 Verification Status: ✅ Verified\n"
                f"🎯 Access Level: {user_info.get('access_level', 'user').title()}\n"
                f"📅 Verified: {user_info.get('verified_at', 'Unknown')}\n\n"
                f"🚨 **Send any IOC for instant comprehensive analysis:**\n"
                f"• IP addresses (192.168.1.1)\n"
                f"• File hashes (MD5/SHA1/SHA256)\n"
                f"• Domain names (example.com)\n"
                f"• URLs (https://example.com)",
                parse_mode='Markdown',
                reply_markup=keyboard
            )
        else:
            # Show verification options
            await self.show_verification_options(update, context)
    
    async def admin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /admin command for admin users"""
        user = update.effective_user
        
        if not self.is_admin(user.id):
            await update.message.reply_text(
                "🚫 **Access Denied**\n\nYou don't have admin privileges.",
                parse_mode='Markdown'
            )
            return
        
        # Check if user is verified
        is_verified, _ = self.is_user_verified(user.id)
        if not is_verified:
            await update.message.reply_text(
                "🔒 **Access Denied**\n\nYou must verify your identity first.",
                parse_mode='Markdown'
            )
            return
        
        keyboard = [
            [InlineKeyboardButton("👥 View All Users", callback_data="admin_view_users")],
            [InlineKeyboardButton("📋 Pending Approvals", callback_data="admin_pending")],
            [InlineKeyboardButton("🗑️ Delete User", callback_data="admin_delete_user")],
            [InlineKeyboardButton("📊 System Stats", callback_data="admin_stats")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "👑 **Admin Control Panel**\n\n"
            "Select an admin function:",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
    
    async def show_verification_options(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show verification options to unverified users"""
        user = update.effective_user
        
        keyboard = [
            [InlineKeyboardButton("🔑 Enter Verification Code", callback_data="verify_code")],
            [InlineKeyboardButton("📝 Request Admin Approval", callback_data="request_approval")],
            [InlineKeyboardButton("ℹ️ About Verification", callback_data="about_verification")]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "🔒 **SOC AI Agent - Secure Access Required**\n\n"
            "⚠️ This is a restricted security tool that requires verification.\n\n"
            "**Verification Options:**\n"
            "🔑 **Code Verification**: Enter the SOC access code\n"
            "📝 **Admin Approval**: Request access from administrators\n\n"
            "**Security Features:**\n"
            "• All access attempts are logged\n"
            "• Rate limiting prevents abuse\n"
            "• Session-based access control\n\n"
            "Please choose your verification method:",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )

    # [Continue with verification and admin methods - same as before but updated for new analysis system]
    
    async def handle_verification_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle verification callback buttons"""
        query = update.callback_query
        await query.answer()
        
        user = query.from_user
        data = query.data
        
        if data == "verify_code":
            await self.start_code_verification(query, context)
        elif data == "request_approval":
            await self.start_approval_request(query, context)
        elif data == "about_verification":
            await self.show_verification_info(query, context)
        elif data.startswith("approve_"):
            await self.handle_admin_approval(query, context)
        elif data.startswith("deny_"):
            await self.handle_admin_denial(query, context)
        elif data == "scan_ip":
            await self.start_indicator_scan(query, context, "IP Address", "ip")
        elif data == "scan_hash":
            await self.start_indicator_scan(query, context, "File Hash", "hash")
        elif data == "scan_domain":
            await self.start_indicator_scan(query, context, "Domain", "domain")
        elif data == "scan_file":
            await self.start_file_upload_scan(query, context)
        elif data == "scan_script":
            await self.start_script_analysis(query, context)
        elif data.startswith("admin_"):
            await self.handle_admin_callback(query, context)
        elif data.startswith("delete_user_"):
            await self.handle_delete_user_callback(query, context)
        elif data.startswith("confirm_delete_"):
            await self.confirm_delete_user(query, context)
    
    async def start_code_verification(self, query, context):
        """Start code verification process"""
        user = query.from_user
        
        if not self.rate_limit_check(user.id):
            await query.edit_message_text(
                "🚫 **Rate Limit Exceeded**\n\n"
                "Too many verification attempts. Please wait 1 hour before trying again.\n"
                "For immediate access, contact an administrator.",
                parse_mode='Markdown'
            )
            return
        
        # Set user state for code verification
        context.user_data['verification_state'] = 'awaiting_code'
        context.user_data['verification_start'] = time.time()
        
        await query.edit_message_text(
            "🔑 **Code Verification**\n\n"
            "Please enter the SOC access verification code.\n\n"
            "⏱️ You have 5 minutes to enter the code.\n"
            "🔒 Code attempts are logged for security.\n\n"
            "Type the verification code:",
            parse_mode='Markdown'
        )
    
    async def start_approval_request(self, query, context):
        """Start admin approval request process with anti-bot challenge"""
        user = query.from_user
        
        # Check if user already has pending request
        if self.has_pending_approval(user.id):
            await query.edit_message_text(
                "📝 **Approval Request Status**\n\n"
                "You already have a pending approval request.\n"
                "Please wait for an administrator to review your request.\n\n"
                "⏱️ Typical response time: 24-48 hours",
                parse_mode='Markdown'
            )
            return
        
        # Start anti-bot challenge
        await self.start_anti_bot_challenge(query, context)
    
    async def start_anti_bot_challenge(self, query, context):
        """Start anti-bot verification challenge"""
        user = query.from_user
        
        # Generate challenge
        question, correct_answer = self.generate_challenge()
        
        # Store challenge data
        context.user_data['challenge_question'] = question
        context.user_data['challenge_answer'] = correct_answer
        context.user_data['challenge_start'] = time.time()
        context.user_data['challenge_attempts'] = 0
        context.user_data['verification_state'] = 'challenge'
        
        await query.edit_message_text(
            "🤖 **Anti-Bot Verification**\n\n"
            "To prove you're human and not a bot, please solve this challenge:\n\n"
            f"❓ **Challenge**: {question}\n\n"
            "💡 Type your answer below (not case-sensitive)\n"
            "⏱️ You have 3 minutes to complete this challenge.\n\n"
            "🔒 This helps prevent automated access attempts.",
            parse_mode='Markdown'
        )
    
    async def show_verification_info(self, query, context):
        """Show information about verification"""
        await query.edit_message_text(
            "ℹ️ **About Verification**\n\n"
            "**Why Verification is Required:**\n"
            "• This SOC tool provides access to sensitive security data\n"
            "• Verification prevents unauthorized access\n"
            "• All activities are logged for security auditing\n\n"
            "**Verification Methods:**\n\n"
            "🔑 **Code Verification**\n"
            "• Requires the SOC access code\n"
            "• Instant access upon successful verification\n"
            "• Contact your SOC administrator for the code\n\n"
            "📝 **Admin Approval**\n"
            "• Request approval from SOC administrators\n"
            "• Requires manual review (24-48 hours)\n"
            "• Includes identity verification process\n\n"
            "**Security Features:**\n"
            "• Rate limiting (5 attempts per hour)\n"
            "• Session timeout protection\n"
            "• Audit logging of all attempts\n"
            "• Multi-level access control",
            parse_mode='Markdown'
        )
    
    async def handle_admin_approval(self, query, context):
        """Handle admin approval of user requests - FIXED"""
        admin_user = query.from_user
        
        # Verify admin privileges
        if not self.is_admin(admin_user.id):
            await query.edit_message_text(
                "🚫 **Access Denied**\n\nYou don't have admin privileges.",
                parse_mode='Markdown'
            )
            return
        
        # Extract user ID from callback data
        try:
            user_id_to_approve = int(query.data.split("_")[1])
        except (IndexError, ValueError):
            await query.edit_message_text(
                "❌ **Error**\n\nInvalid approval request.",
                parse_mode='Markdown'
            )
            return
        
        # Get pending approval info
        approval_info = self.get_pending_approval(user_id_to_approve)
        if not approval_info:
            await query.edit_message_text(
                "❌ **Error**\n\nApproval request not found or already processed.",
                parse_mode='Markdown'
            )
            return
        
        approval_id, user_id, username, first_name, requested_at, verification_code = approval_info
        
        # Add user to verified users
        session_token = self.add_verified_user(
            user_id, username, first_name, 'admin_approval', admin_user.id
        )
        
        if session_token:
            # Update approval status
            self.update_approval_status(user_id, 'approved')
            
            # Log the approval
            self.log_verification_attempt(
                admin_user.id, 
                admin_user.username, 
                'admin_approval', 
                f"Approved user {user_id} ({first_name})", 
                True
            )
            
            # Notify the approved user
            try:
                keyboard = self.get_verified_keyboard()
                await context.bot.send_message(
                    chat_id=user_id,
                    text="✅ **Access Approved!**\n\n"
                         "🎉 Your SOC AI Agent access has been approved by an administrator!\n"
                         "🔐 You now have full access to all security analysis features.\n\n"
                         "Welcome to the SOC team! 🛡️",
                    parse_mode='Markdown',
                    reply_markup=keyboard
                )
            except Exception as e:
                logger.error(f"Could not notify approved user {user_id}: {e}")
            
            # Update the admin message
            await query.edit_message_text(
                f"✅ **User Approved Successfully**\n\n"
                f"👤 **Approved User**: {first_name}\n"
                f"📧 **Username**: @{username or 'N/A'}\n"
                f"🆔 **User ID**: `{user_id}`\n"
                f"👑 **Approved by**: {admin_user.first_name}\n"
                f"📅 **Approval Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"🔔 User has been notified and can now access the system.",
                parse_mode='Markdown'
            )
        else:
            await query.edit_message_text(
                "❌ **Approval Failed**\n\n"
                "Failed to add user to verified list. Please try again.",
                parse_mode='Markdown'
            )
    
    async def handle_admin_denial(self, query, context):
        """Handle admin denial of user requests - FIXED"""
        admin_user = query.from_user
        
        # Verify admin privileges
        if not self.is_admin(admin_user.id):
            await query.edit_message_text(
                "🚫 **Access Denied**\n\nYou don't have admin privileges.",
                parse_mode='Markdown'
            )
            return
        
        # Extract user ID from callback data
        try:
            user_id_to_deny = int(query.data.split("_")[1])
        except (IndexError, ValueError):
            await query.edit_message_text(
                "❌ **Error**\n\nInvalid denial request.",
                parse_mode='Markdown'
            )
            return
        
        # Get pending approval info
        approval_info = self.get_pending_approval(user_id_to_deny)
        if not approval_info:
            await query.edit_message_text(
                "❌ **Error**\n\nApproval request not found or already processed.",
                parse_mode='Markdown'
            )
            return
        
        approval_id, user_id, username, first_name, requested_at, verification_code = approval_info
        
        # Update approval status to denied
        if self.update_approval_status(user_id, 'denied'):
            # Log the denial
            self.log_verification_attempt(
                admin_user.id, 
                admin_user.username, 
                'admin_denial', 
                f"Denied user {user_id} ({first_name})", 
                True
            )
            
            # Notify the denied user
            try:
                await context.bot.send_message(
                    chat_id=user_id,
                    text="❌ **Access Request Denied**\n\n"
                         "Your SOC AI Agent access request has been reviewed and denied.\n"
                         "Please contact your SOC administrator if you believe this is an error.\n\n"
                         "You may submit a new request after addressing any issues.",
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Could not notify denied user {user_id}: {e}")
            
            # Update the admin message
            await query.edit_message_text(
                f"❌ **User Request Denied**\n\n"
                f"👤 **Denied User**: {first_name}\n"
                f"📧 **Username**: @{username or 'N/A'}\n"
                f"🆔 **User ID**: `{user_id}`\n"
                f"👑 **Denied by**: {admin_user.first_name}\n"
                f"📅 **Denial Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"🔔 User has been notified of the denial.",
                parse_mode='Markdown'
            )
        else:
            await query.edit_message_text(
                "❌ **Denial Failed**\n\n"
                "Failed to update approval status. Please try again.",
                parse_mode='Markdown'
            )
    
    async def handle_admin_callback(self, query, context):
        """Handle admin-specific callbacks"""
        user = query.from_user
        data = query.data
        
        # Verify admin privileges
        if not self.is_admin(user.id):
            await query.edit_message_text(
                "🚫 **Access Denied**\n\nYou don't have admin privileges.",
                parse_mode='Markdown'
            )
            return
        
        if data == "admin_view_users":
            await self.show_all_users(query, context)
        elif data == "admin_pending":
            await self.show_pending_approvals(query, context)
        elif data == "admin_delete_user":
            await self.show_users_for_deletion(query, context)
        elif data == "admin_stats":
            await self.show_admin_stats(query, context)
    
    async def show_all_users(self, query, context):
        """Show all verified users"""
        users = self.get_all_verified_users()
        
        if not users:
            await query.edit_message_text(
                "👥 **All Users**\n\n"
                "No verified users found.",
                parse_mode='Markdown'
            )
            return
        
        user_text = "👥 **All Verified Users**\n\n"
        
        for user_data in users[:10]:  # Limit to 10 users to avoid message length issues
            user_id, username, first_name, method, verified_at, verified_by, access_level, status, last_activity = user_data
            
            admin_badge = " 👑" if self.is_admin(user_id) else ""
            username_display = f"@{username}" if username else "No username"
            
            user_text += f"👤 **{first_name}**{admin_badge}\n"
            user_text += f"   📧 {username_display}\n"
            user_text += f"   🆔 `{user_id}`\n"
            user_text += f"   🔐 {method.title()} verification\n"
            user_text += f"   📅 {verified_at}\n\n"
        
        if len(users) > 10:
            user_text += f"... and {len(users) - 10} more users\n"
        
        user_text += f"\n📊 **Total**: {len(users)} verified users"
        
        await query.edit_message_text(user_text, parse_mode='Markdown')
    
    async def show_users_for_deletion(self, query, context):
        """Show users that can be deleted"""
        users = self.get_all_verified_users()
        admin_user_id = query.from_user.id
        
        # Filter out admins and self
        deletable_users = [
            user for user in users 
            if user[0] != admin_user_id and not self.is_admin(user[0])
        ]
        
        if not deletable_users:
            await query.edit_message_text(
                "🗑️ **Delete User**\n\n"
                "No users available for deletion.\n"
                "(Admins cannot be deleted via this interface)",
                parse_mode='Markdown'
            )
            return
        
        keyboard = []
        for user_data in deletable_users[:10]:  # Limit to 10 users
            user_id, username, first_name, _, _, _, _, _, _ = user_data
            display_name = f"{first_name} (@{username})" if username else first_name
            keyboard.append([
                InlineKeyboardButton(
                    f"🗑️ {display_name}", 
                    callback_data=f"delete_user_{user_id}"
                )
            ])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "🗑️ **Delete User**\n\n"
            "⚠️ **Warning**: This will permanently remove user access.\n\n"
            "Select a user to delete:",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
    
    async def handle_delete_user_callback(self, query, context):
        """Handle delete user confirmation"""
        user_id_to_delete = int(query.data.split("_")[2])
        
        # Get user info
        users = self.get_all_verified_users()
        user_info = next((u for u in users if u[0] == user_id_to_delete), None)
        
        if not user_info:
            await query.edit_message_text(
                "❌ **Error**\n\nUser not found.",
                parse_mode='Markdown'
            )
            return
        
        user_id, username, first_name, method, verified_at, verified_by, access_level, status, last_activity = user_info
        
        keyboard = [
            [
                InlineKeyboardButton("✅ Confirm Delete", callback_data=f"confirm_delete_{user_id}"),
                InlineKeyboardButton("❌ Cancel", callback_data="admin_delete_user")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        username_display = f"@{username}" if username else "No username"
        
        await query.edit_message_text(
            f"🗑️ **Confirm User Deletion**\n\n"
            f"⚠️ **WARNING**: This action cannot be undone!\n\n"
            f"**User Details:**\n"
            f"👤 Name: {first_name}\n"
            f"📧 Username: {username_display}\n"
            f"🆔 User ID: `{user_id}`\n"
            f"🔐 Verified: {verified_at}\n"
            f"📊 Access Level: {access_level}\n\n"
            f"Are you sure you want to delete this user?",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
    
    async def confirm_delete_user(self, query, context):
        """Confirm and execute user deletion"""
        user_id_to_delete = int(query.data.split("_")[2])
        admin_user = query.from_user
        
        # Double-check admin privileges
        if not self.is_admin(admin_user.id):
            await query.edit_message_text(
                "🚫 **Access Denied**\n\nYou don't have admin privileges.",
                parse_mode='Markdown'
            )
            return
        
        # Prevent deletion of admins
        if self.is_admin(user_id_to_delete):
            await query.edit_message_text(
                "🚫 **Cannot Delete Admin**\n\n"
                "Admin users cannot be deleted via this interface.",
                parse_mode='Markdown'
            )
            return
        
        # Get user info before deletion
        users = self.get_all_verified_users()
        user_info = next((u for u in users if u[0] == user_id_to_delete), None)
        
        if not user_info:
            await query.edit_message_text(
                "❌ **Error**\n\nUser not found.",
                parse_mode='Markdown'
            )
            return
        
        username = user_info[1]
        first_name = user_info[2]
        
        # Delete the user
        if self.remove_verified_user(user_id_to_delete):
            # Log the deletion
            self.log_verification_attempt(
                admin_user.id, 
                admin_user.username, 
                'admin_delete', 
                f"Deleted user {user_id_to_delete} ({first_name})", 
                True
            )
            
            # Notify the deleted user (if possible)
            try:
                await context.bot.send_message(
                    chat_id=user_id_to_delete,
                    text="🚫 **Access Revoked**\n\n"
                         "Your access to the SOC AI Agent has been revoked by an administrator.\n"
                         "If you believe this is an error, please contact your SOC administrator.",
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.info(f"Could not notify deleted user {user_id_to_delete}: {e}")
            
            await query.edit_message_text(
                f"✅ **User Deleted Successfully**\n\n"
                f"👤 **Deleted User**: {first_name}\n"
                f"📧 **Username**: @{username or 'N/A'}\n"
                f"🆔 **User ID**: `{user_id_to_delete}`\n"
                f"👑 **Deleted by**: {admin_user.first_name}\n"
                f"📅 **Deletion Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"🔒 User access has been revoked and logged.",
                parse_mode='Markdown'
            )
        else:
            await query.edit_message_text(
                "❌ **Deletion Failed**\n\n"
                "Failed to delete user from database. Please try again.",
                parse_mode='Markdown'
            )
    
    async def show_pending_approvals(self, query, context):
        """Show pending approval requests"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, username, first_name, requested_at 
                FROM pending_approvals 
                WHERE status = 'pending'
                ORDER BY requested_at ASC
            ''')
            
            pending = cursor.fetchall()
            conn.close()
            
            if not pending:
                await query.edit_message_text(
                    "📋 **Pending Approvals**\n\n"
                    "No pending approval requests.",
                    parse_mode='Markdown'
                )
                return
            
            approval_text = "📋 **Pending Approval Requests**\n\n"
            
            for user_id, username, first_name, requested_at in pending:
                username_display = f"@{username}" if username else "No username"
                approval_text += f"👤 **{first_name}**\n"
                approval_text += f"   📧 {username_display}\n"
                approval_text += f"   🆔 `{user_id}`\n"
                approval_text += f"   📅 {requested_at}\n\n"
            
            approval_text += f"📊 **Total Pending**: {len(pending)} requests"
            
            await query.edit_message_text(approval_text, parse_mode='Markdown')
            
        except Exception as e:
            await query.edit_message_text(f"❌ Error getting pending approvals: {str(e)}")
    
    async def show_admin_stats(self, query, context):
        """Show system statistics for admin"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get various stats
            cursor.execute('SELECT COUNT(*) FROM verified_users WHERE status = "active"')
            active_users = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM pending_approvals WHERE status = "pending"')
            pending_approvals = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM verification_attempts WHERE timestamp > datetime("now", "-24 hours")')
            recent_attempts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM verification_attempts WHERE success = 1')
            successful_attempts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM verification_attempts WHERE success = 0')
            failed_attempts = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM iocs')
            total_iocs = cursor.fetchone()[0]
            
            conn.close()
            
            stats_text = f"📊 **System Statistics**\n\n"
            stats_text += f"👥 **Active Users**: {active_users}\n"
            stats_text += f"👑 **Admin Users**: {len(self.admin_user_ids)}\n"
            stats_text += f"📋 **Pending Approvals**: {pending_approvals}\n\n"
            stats_text += f"🔐 **Verification Attempts (24h)**: {recent_attempts}\n"
            stats_text += f"✅ **Successful Verifications**: {successful_attempts}\n"
            stats_text += f"❌ **Failed Attempts**: {failed_attempts}\n\n"
            stats_text += f"🎯 **IOC Database**: {total_iocs:,} indicators\n\n"
            stats_text += f"⏰ **System Uptime**: Online\n"
            stats_text += f"🔒 **Security**: All systems operational"
            
            await query.edit_message_text(stats_text, parse_mode='Markdown')
            
        except Exception as e:
            await query.edit_message_text(f"❌ Error getting statistics: {str(e)}")
    
    async def handle_keyboard_commands(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle keyboard button commands"""
        user = update.effective_user
        text = update.message.text
        
        # Check if user is verified
        is_verified, user_info = self.is_user_verified(user.id)
        if not is_verified:
            await update.message.reply_text(
                "🔒 **Access Denied**\n\nYou must verify your identity first.",
                parse_mode='Markdown'
            )
            return
        
        self.update_user_activity(user.id)
        
        if text == "📊 IOC Stats":
            await self.show_ioc_stats(update, context)
        elif text == "🔍 Quick Scan":
            await self.show_quick_scan_options(update, context)
        elif text == "👥 Manage Users" and self.is_admin(user.id):
            await self.show_manage_users_menu(update, context)
        elif text == "📋 Pending Approvals" and self.is_admin(user.id):
            await self.show_pending_approvals_keyboard(update, context)
        elif text == "ℹ️ Help":
            await self.show_help(update, context)
        elif text == "🔐 My Account":
            await self.show_account_info(update, context, user_info)
    
    async def show_manage_users_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show user management menu for admins"""
        keyboard = [
            [InlineKeyboardButton("👥 View All Users", callback_data="admin_view_users")],
            [InlineKeyboardButton("🗑️ Delete User", callback_data="admin_delete_user")],
            [InlineKeyboardButton("📊 System Stats", callback_data="admin_stats")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "👥 **User Management**\n\n"
            "Select a user management function:",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
    
    async def show_pending_approvals_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show pending approvals from keyboard"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT user_id, username, first_name, requested_at 
                FROM pending_approvals 
                WHERE status = 'pending'
                ORDER BY requested_at ASC
            ''')
            
            pending = cursor.fetchall()
            conn.close()
            
            if not pending:
                await update.message.reply_text(
                    "📋 **Pending Approvals**\n\n"
                    "No pending approval requests.",
                    parse_mode='Markdown'
                )
                return
            
            approval_text = "📋 **Pending Approval Requests**\n\n"
            keyboard = []
            
            for user_id, username, first_name, requested_at in pending[:5]:  # Limit to 5 for buttons
                username_display = f"@{username}" if username else "No username"
                approval_text += f"👤 **{first_name}**\n"
                approval_text += f"   📧 {username_display}\n"
                approval_text += f"   🆔 `{user_id}`\n"
                approval_text += f"   📅 {requested_at}\n\n"
                
                # Add approval buttons for each request
                keyboard.append([
                    InlineKeyboardButton(f"✅ Approve {first_name}", callback_data=f"approve_{user_id}"),
                    InlineKeyboardButton(f"❌ Deny {first_name}", callback_data=f"deny_{user_id}")
                ])
            
            if len(pending) > 5:
                approval_text += f"... and {len(pending) - 5} more requests\n"
            
            approval_text += f"\n📊 **Total Pending**: {len(pending)} requests"
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(
                approval_text, 
                parse_mode='Markdown',
                reply_markup=reply_markup
            )
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error getting pending approvals: {str(e)}")
    
    async def show_quick_scan_options(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show quick scan options - all 5 types"""
        keyboard = [
            [InlineKeyboardButton("🔍 Check File Hash", callback_data="scan_hash")],
            [InlineKeyboardButton("🌐 Check IP Address", callback_data="scan_ip")],
            [InlineKeyboardButton("🌍 Check Domain", callback_data="scan_domain")],
            [InlineKeyboardButton("📁 Upload File Analysis", callback_data="scan_file")],
            [InlineKeyboardButton("📜 Script Analysis", callback_data="scan_script")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "🔍 **Quick Scan Options**\n\n"
            "Choose the type of analysis you want to perform:\n\n"
            "🔍 **File Hash** - MD5, SHA1, SHA256 hashes\n"
            "🌐 **IP Address** - IPv4 or IPv6 addresses\n"
            "🌍 **Domain** - Domain names and URLs\n"
            "📁 **Upload File** - Analyze uploaded files\n"
            "📜 **Script Analysis** - Analyze scripts and code\n\n"
            "Select an option below:",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )
    
    async def handle_code_verification(self, update: Update, context: ContextTypes.DEFAULT_TYPE, code: str):
        """Handle code verification attempt"""
        user = update.effective_user
        
        # Check timeout
        start_time = context.user_data.get('verification_start', 0)
        if time.time() - start_time > self.verification_timeout:
            context.user_data.clear()
            await update.message.reply_text(
                "⏰ **Verification Timeout**\n\n"
                "Verification session expired. Use /start to try again.",
                parse_mode='Markdown'
            )
            return
        
        # Log attempt
        self.log_verification_attempt(user.id, user.username, 'code', code[:10] + '...', False)
        
        # Check code
        if code.strip() == self.verification_code:
            # Successful verification
            session_token = self.add_verified_user(
                user.id, user.username, user.first_name, 'code'
            )
            
            if session_token:
                self.log_verification_attempt(user.id, user.username, 'code', 'SUCCESS', True)
                context.user_data.clear()
                
                # Determine keyboard based on admin status
                keyboard = self.get_admin_keyboard() if self.is_admin(user.id) else self.get_verified_keyboard()
                admin_status = " (Admin)" if self.is_admin(user.id) else ""
                
                await update.message.reply_text(
                    f"✅ **Verification Successful!**\n\n"
                    f"🎉 Welcome to the SOC AI Agent{admin_status}!\n"
                    f"🔐 You now have full access to all security analysis features.\n\n"
                    f"**Available Features:**\n"
                    f"🔍 Indicator Analysis (IP, Hash, Domain)\n"
                    f"🛡️ Threat Intelligence Lookup\n"
                    f"🤖 AI-Powered Security Analysis\n"
                    f"📊 IOC Statistics\n"
                    f"{('👑 Admin Management Tools\\n' if self.is_admin(user.id) else '')}"
                    f"\nSend any indicator to begin analysis!",
                    parse_mode='Markdown',
                    reply_markup=keyboard
                )
            else:
                await update.message.reply_text(
                    "❌ **Verification Error**\n\n"
                    "Code correct but failed to activate access. Contact administrator.",
                    parse_mode='Markdown'
                )
        else:
            # Failed verification
            remaining_attempts = 5 - len(self.verification_attempts.get(user.id, []))
            
            await update.message.reply_text(
                "❌ **Invalid Verification Code**\n\n"
                f"⚠️ Remaining attempts: {remaining_attempts}\n"
                "🔒 This attempt has been logged.\n\n"
                "Please try again or use /start for other verification options.",
                parse_mode='Markdown'
            )
    
    async def handle_challenge_text_response(self, update: Update, context: ContextTypes.DEFAULT_TYPE, response: str):
        """Handle text-based challenge responses"""
        user = update.effective_user
        
        # Check timeout
        start_time = context.user_data.get('challenge_start', 0)
        if time.time() - start_time > 180:  # 3 minutes
            context.user_data.clear()
            await update.message.reply_text(
                "⏰ **Challenge Timeout**\n\n"
                "The anti-bot challenge expired. Use /start to try again.",
                parse_mode='Markdown'
            )
            return
        
        # Check answer
        correct_answer = context.user_data.get('challenge_answer', '')
        user_answer = response.strip().lower()
        
        if user_answer == correct_answer:
            await self.complete_challenge_success_text(update, context)
        else:
            await self.handle_challenge_failure_text(update, context)
    
    async def complete_challenge_success_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle successful challenge completion (text response)"""
        user = update.effective_user
        
        # Create approval request
        if self.create_approval_request(user.id, user.username, user.first_name):
            # Clear challenge data
            context.user_data.clear()
            
            # Notify admins with challenge completion info
            await self.notify_admins_of_verified_request(context, user)
            
            await update.message.reply_text(
                "✅ **Challenge Completed Successfully!**\n\n"
                "🎉 You've proven you're human!\n"
                "📝 Your access request has been submitted to administrators.\n\n"
                "**Request Details:**\n"
                f"👤 Name: {user.first_name}\n"
                f"📧 Username: @{user.username or 'N/A'}\n"
                f"🆔 User ID: {user.id}\n"
                f"📅 Requested: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"✅ Anti-Bot Challenge: Passed\n\n"
                "⏱️ You'll be notified when your request is reviewed.\n"
                "📧 Admins have been notified of your verified request.",
                parse_mode='Markdown'
            )
        else:
            await update.message.reply_text(
                "❌ **Request Failed**\n\n"
                "Failed to submit approval request. Please try again later.",
                parse_mode='Markdown'
            )
    
    async def handle_challenge_failure_text(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle failed challenge attempt (text response)"""
        user = update.effective_user
        
        attempts = context.user_data.get('challenge_attempts', 0) + 1
        context.user_data['challenge_attempts'] = attempts
        
        if attempts >= 3:
            context.user_data.clear()
            await update.message.reply_text(
                "❌ **Challenge Failed**\n\n"
                "Too many incorrect attempts. Please wait 10 minutes before trying again.\n"
                "Use /start to restart the verification process.",
                parse_mode='Markdown'
            )
        else:
            remaining = 3 - attempts
            question = context.user_data.get('challenge_question', '')
            
            await update.message.reply_text(
                "❌ **Incorrect Answer**\n\n"
                f"⚠️ Remaining attempts: {remaining}\n\n"
                f"❓ **Challenge**: {question}\n\n"
                "💡 Please try again. Type your answer below.",
                parse_mode='Markdown'
            )
    
    async def notify_admins_of_verified_request(self, context, user):
        """Notify admin users of new approval request (challenge passed)"""
        keyboard = [
            [
                InlineKeyboardButton("✅ Approve", callback_data=f"approve_{user.id}"),
                InlineKeyboardButton("❌ Deny", callback_data=f"deny_{user.id}")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        message = (
            "🔔 **New Verified Access Request**\n\n"
            f"👤 **User**: {user.first_name}\n"
            f"📧 **Username**: @{user.username or 'N/A'}\n"
            f"🆔 **User ID**: {user.id}\n"
            f"📅 **Requested**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"✅ **Anti-Bot Challenge**: **PASSED** ✅\n\n"
            "🤖 This user has successfully completed the anti-bot verification.\n"
            "Please review and approve/deny this request."
        )
        
        for admin_id in self.admin_user_ids:
            try:
                await context.bot.send_message(
                    chat_id=admin_id,
                    text=message,
                    parse_mode='Markdown',
                    reply_markup=reply_markup
                )
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")
    
    async def start_indicator_scan(self, query, context, scan_type: str, indicator_type: str):
        """Start scanning for specific indicator type"""
        user = query.from_user
        
        # Check if user is verified
        is_verified, user_info = self.is_user_verified(user.id)
        if not is_verified:
            await query.edit_message_text(
                "🔒 **Access Denied**\n\nYou must verify your identity first.",
                parse_mode='Markdown'
            )
            return
        
        # Set user state for indicator input
        context.user_data['scan_state'] = f'awaiting_{indicator_type}'
        context.user_data['scan_start'] = time.time()
        
        examples = {
            'ip': "Example: 8.8.8.8 or 192.168.1.1",
            'hash': "Example: MD5, SHA1, or SHA256 hash",
            'domain': "Example: google.com or malicious-site.com"
        }
        
        await query.edit_message_text(
            f"🔍 **{scan_type} Scanner**\n\n"
            f"Please enter the {scan_type.lower()} you want to analyze:\n\n"
            f"💡 {examples.get(indicator_type, '')}\n\n"
            f"⏱️ Session expires in 5 minutes.\n"
            f"Type the {scan_type.lower()} below:",
            parse_mode='Markdown'
        )
    
    async def start_file_upload_scan(self, query, context):
        """Start file upload analysis"""
        user = query.from_user
        
        # Check if user is verified
        is_verified, user_info = self.is_user_verified(user.id)
        if not is_verified:
            await query.edit_message_text(
                "🔒 **Access Denied**\n\nYou must verify your identity first.",
                parse_mode='Markdown'
            )
            return
        
        # Set user state for file upload
        context.user_data['scan_state'] = 'awaiting_file'
        context.user_data['scan_start'] = time.time()
        
        await query.edit_message_text(
            "📁 **File Upload Analysis**\n\n"
            "Please upload a file for security analysis.\n\n"
            "**Supported File Types:**\n"
            "• Executable files (.exe, .dll, .so)\n"
            "• Archive files (.zip, .rar, .tar)\n"
            "• Document files (.pdf, .doc, .xls)\n"
            "• Script files (.ps1, .bat, .sh)\n"
            "• Any suspicious files\n\n"
            "**File Size Limit:** 20MB\n"
            "⏱️ Session expires in 10 minutes.\n\n"
            "📎 Use the attachment button to upload your file.",
            parse_mode='Markdown'
        )
    
    async def start_script_analysis(self, query, context):
        """Start script analysis"""
        user = query.from_user
        
        # Check if user is verified
        is_verified, user_info = self.is_user_verified(user.id)
        if not is_verified:
            await query.edit_message_text(
                "🔒 **Access Denied**\n\nYou must verify your identity first.",
                parse_mode='Markdown'
            )
            return
        
        # Set user state for script input
        context.user_data['scan_state'] = 'awaiting_script'
        context.user_data['scan_start'] = time.time()
        
        await query.edit_message_text(
            "📜 **Script Analysis**\n\n"
            "Please paste the script or code you want to analyze.\n\n"
            "**Supported Script Types:**\n"
            "• PowerShell (.ps1)\n"
            "• Batch files (.bat, .cmd)\n"
            "• Shell scripts (.sh, .bash)\n"
            "• Python scripts (.py)\n"
            "• JavaScript (.js)\n"
            "• VBScript (.vbs)\n"
            "• Any suspicious code\n\n"
            "**Analysis Features:**\n"
            "• Malicious command detection\n"
            "• Obfuscation analysis\n"
            "• Suspicious pattern matching\n"
            "• AI-powered code analysis\n\n"
            "⏱️ Session expires in 10 minutes.\n\n"
            "📝 Paste your script below:",
            parse_mode='Markdown'
        )
    
    async def handle_scan_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE, indicator: str):
        """Handle indicator input from quick scan"""
        user = update.effective_user
        
        # Check timeout
        start_time = context.user_data.get('scan_start', 0)
        if time.time() - start_time > 300:  # 5 minutes
            context.user_data.clear()
            await update.message.reply_text(
                "⏰ **Scan Session Timeout**\n\n"
                "Your scan session expired. Use the Quick Scan button to try again.",
                parse_mode='Markdown'
            )
            return
        
        scan_state = context.user_data.get('scan_state', '')
        expected_type = scan_state.replace('awaiting_', '')
        
        # Validate indicator type
        detected_type = self.detect_indicator_type(indicator.strip())
        
        # Check if the detected type matches what was requested
        if expected_type == 'hash' and detected_type not in ['md5', 'sha1', 'sha256']:
            await update.message.reply_text(
                "❌ **Invalid Hash Format**\n\n"
                "Please enter a valid hash (MD5, SHA1, or SHA256).\n"
                "Example: `a1b2c3d4e5f6...`\n\n"
                "Try again or use /start to cancel.",
                parse_mode='Markdown'
            )
            return
        elif expected_type == 'ip' and detected_type != 'ip':
            await update.message.reply_text(
                "❌ **Invalid IP Address**\n\n"
                "Please enter a valid IP address.\n"
                "Example: `192.168.1.1` or `8.8.8.8`\n\n"
                "Try again or use /start to cancel.",
                parse_mode='Markdown'
            )
            return
        elif expected_type == 'domain' and detected_type not in ['domain', 'url']:
            await update.message.reply_text(
                "❌ **Invalid Domain**\n\n"
                "Please enter a valid domain name.\n"
                "Example: `google.com` or `example.org`\n\n"
                "Try again or use /start to cancel.",
                parse_mode='Markdown'
            )
            return
        
        # Clear scan state
        context.user_data.clear()
        
        # Proceed with analysis
        await update.message.reply_text(
            f"✅ **Valid {expected_type.title()} Detected**\n\n"
            f"Starting analysis of: `{indicator}`",
            parse_mode='Markdown'
        )
        
        # Analyze the indicator using comprehensive analysis
        analyzing_msg = await update.message.reply_text(
            "🔍 **Analyzing Indicator...**\n\n"
            "⏳ Performing comprehensive threat analysis...\n"
            "🔄 Checking multiple intelligence sources...",
            parse_mode='Markdown'
        )
        
        try:
            # Perform comprehensive analysis
            result = await self.comprehensive_analysis(indicator.strip(), user.id)
            
            # Update with results
            await analyzing_msg.edit_text(result, parse_mode='Markdown')
            
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            await analyzing_msg.edit_text(
                f"❌ **Analysis Error**\n\n"
                f"Failed to complete analysis: {str(e)}\n"
                f"Please try again or contact support.",
                parse_mode='Markdown'
            )
    
    async def show_ioc_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show IOC database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs')
            total_iocs = cursor.fetchone()[0]
            
            # IOCs by type
            cursor.execute('SELECT type, COUNT(*) FROM iocs GROUP BY type ORDER BY COUNT(*) DESC')
            types = cursor.fetchall()
            
            # Recent IOCs
            cursor.execute('SELECT COUNT(*) FROM iocs WHERE created_at > datetime("now", "-7 days")')
            recent_iocs = cursor.fetchone()[0]
            
            # Top sources
            cursor.execute('SELECT source, COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC LIMIT 5')
            sources = cursor.fetchall()
            
            conn.close()
            
            stats_text = f"📊 **IOC Database Statistics**\n\n"
            stats_text += f"🎯 **Total IOCs**: {total_iocs:,}\n"
            stats_text += f"📅 **Added this week**: {recent_iocs:,}\n\n"
            
            if types:
                stats_text += "**📋 By Type:**\n"
                for ioc_type, count in types[:5]:
                    stats_text += f"• {ioc_type.upper()}: {count:,}\n"
                if len(types) > 5:
                    stats_text += f"• ... and {len(types) - 5} more types\n"
                stats_text += "\n"
            
            if sources:
                stats_text += "**🔗 Top Sources:**\n"
                for source, count in sources:
                    stats_text += f"• {source}: {count:,}\n"
            
            await update.message.reply_text(stats_text, parse_mode='Markdown')
            
        except Exception as e:
            await update.message.reply_text(f"❌ Error getting statistics: {str(e)}")
    
    async def show_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show help information"""
        user = update.effective_user
        is_admin = self.is_admin(user.id)
        
        help_text = """🛡️ **SOC AI Agent - Help**

**🔍 Indicator Analysis:**
Send any of these indicators for analysis:
• IP addresses (e.g., 192.168.1.1)
• File hashes (MD5, SHA1, SHA256)
• Domain names (e.g., example.com)
• URLs (e.g., https://example.com)

**📊 Features:**
• Real-time threat intelligence
• VirusTotal integration
• AbuseIPDB reputation checks
• Local IOC database
• AI-powered analysis
• Secure access control

**🎛️ Commands:**
• Send any indicator for analysis
• Use keyboard buttons for quick access
• /start - Main menu"""

        if is_admin:
            help_text += """
• /admin - Admin control panel

**👑 Admin Features:**
• User management
• Approval/denial of requests
• System statistics
• User deletion capabilities"""

        help_text += """

**🔐 Security:**
• All activities are logged
• Session-based access
• Multi-level verification
• Rate limiting protection

**📞 Support:**
Contact your SOC administrator for:
• Access issues
• Technical problems
• Feature requests
"""
        
        await update.message.reply_text(help_text, parse_mode='Markdown')
    
    async def show_account_info(self, update: Update, context: ContextTypes.DEFAULT_TYPE, user_info: dict):
        """Show user account information"""
        user = update.effective_user
        is_admin = self.is_admin(user.id)
        
        account_text = f"""🔐 **Account Information**

👤 **Profile:**
• Name: {user.first_name}
• Username: @{user.username or 'N/A'}
• User ID: {user.id}

🎯 **Access Details:**
• Status: ✅ Verified
• Access Level: {user_info.get('access_level', 'user').title()}{' (Admin)' if is_admin else ''}
• Verified: {user_info.get('verified_at', 'Unknown')}

🔒 **Security:**
• Session Active: ✅ Yes
• Last Activity: Just now
• Two-Factor: Telegram Account

⚙️ **Permissions:**
• Indicator Analysis: ✅ Enabled
• IOC Database: ✅ Read Access
• AI Analysis: ✅ Enabled"""

        if is_admin:
            account_text += """
• User Management: ✅ Admin Access
• System Administration: ✅ Full Access"""
        
        await update.message.reply_text(account_text, parse_mode='Markdown')
    
    # Simple placeholder methods for file/script analysis
    async def handle_file_upload(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle file upload for analysis"""
        await update.message.reply_text("📁 File upload analysis coming soon!")
        context.user_data.clear()
    
    async def handle_script_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE, script_content: str):
        """Handle script content for analysis"""
        await update.message.reply_text("📜 Script analysis coming soon!")
        context.user_data.clear()
    
    async def analyze_uploaded_file(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Analyze an uploaded file"""
        await update.message.reply_text("📁 File analysis feature coming soon!")
    
    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle all text messages and file uploads"""
        user = update.effective_user
        message = update.message
        
        # Check if user is in verification state
        if context.user_data.get('verification_state') == 'awaiting_code':
            await self.handle_code_verification(update, context, message.text)
            return
        elif context.user_data.get('verification_state') == 'challenge':
            await self.handle_challenge_text_response(update, context, message.text)
            return
        
        # Check if user is in scan state
        scan_state = context.user_data.get('scan_state')
        if scan_state:
            if scan_state == 'awaiting_file' and message.document:
                await self.handle_file_upload(update, context)
                return
            elif scan_state == 'awaiting_script' and message.text:
                await self.handle_script_input(update, context, message.text)
                return
            elif scan_state.startswith('awaiting_') and message.text:
                await self.handle_scan_input(update, context, message.text)
                return
        
        # Check if user is verified
        is_verified, user_info = self.is_user_verified(user.id)
        
        if not is_verified:
            await update.message.reply_text(
                "🔒 **Access Denied**\n\n"
                "You must verify your identity before using this bot.\n"
                "Use /start to begin verification.",
                parse_mode='Markdown'
            )
            return
        
        # Update user activity
        self.update_user_activity(user.id)
        
        # Handle file uploads for verified users
        if message.document:
            await self.analyze_uploaded_file(update, context)
            return
        
        # Process as SOC indicator for comprehensive analysis
        if message.text:
            # Send "analyzing" message
            analyzing_msg = await update.message.reply_text(
                "🔍 **Analyzing Indicator...**\n\n"
                "⏳ Performing comprehensive threat analysis...\n"
                "🔄 Checking multiple intelligence sources...",
                parse_mode='Markdown'
            )
            
            try:
                # Perform comprehensive analysis
                result = await self.comprehensive_analysis(message.text.strip(), user.id)
                
                # Update with results
                await analyzing_msg.edit_text(result, parse_mode='Markdown')
                
            except Exception as e:
                logger.error(f"Analysis error: {e}")
                await analyzing_msg.edit_text(
                    f"❌ **Analysis Error**\n\n"
                    f"Failed to complete analysis: {str(e)}\n"
                    f"Please try again or contact support.",
                    parse_mode='Markdown'
                )
    
    # [Include all the remaining methods from before with keyboard handlers, admin functions, etc.]
    # [But now with updated calls to comprehensive_analysis instead of placeholder methods]

def main():
    """Main function to run the secure bot"""
    agent = SecureSOCAgent()
    
    if not agent.bot_token:
        logger.error("TELEGRAM_BOT_TOKEN not found in environment variables")
        return
    
    # Create application
    application = Application.builder().token(agent.bot_token).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", agent.start_command))
    application.add_handler(CommandHandler("admin", agent.admin_command))
    application.add_handler(CallbackQueryHandler(agent.handle_verification_callback))
    
    # Message handlers - order matters!
    application.add_handler(MessageHandler(
        filters.TEXT & filters.Regex("^(📊 IOC Stats|🔍 Quick Scan|👥 Manage Users|📋 Pending Approvals|ℹ️ Help|🔐 My Account)$"), 
        agent.handle_keyboard_commands
    ))
    application.add_handler(MessageHandler(
        filters.Document.ALL, 
        agent.handle_message
    ))
    application.add_handler(MessageHandler(
        filters.TEXT & ~filters.COMMAND, 
        agent.handle_message
    ))
    
    logger.info("🛡️ Secure SOC AI Agent starting...")
    logger.info(f"🔐 Admin approval required: {agent.admin_approval_required}")
    logger.info(f"👥 Number of admin users: {len(agent.admin_user_ids)}")
    logger.info(f"🔑 Verification code configured: {'Yes' if agent.verification_code else 'No'}")
    logger.info(f"🦠 VirusTotal API: {'Configured' if agent.virustotal_api else 'Not configured'}")
    logger.info(f"🚫 AbuseIPDB API: {'Configured' if agent.abusedb_api else 'Not configured'}")
    
    print("\n🛡️ SOC AI Agent - Secure Mode")
    print("=" * 40)
    print(f"🔐 Verification Code: {agent.verification_code}")
    print(f"👑 Admin IDs: {', '.join(map(str, agent.admin_user_ids))}")
    print(f"📝 Admin Approval: {'Required' if agent.admin_approval_required else 'Optional'}")
    print(f"⏱️ Verification Timeout: {agent.verification_timeout}s")
    print(f"🦠 VirusTotal API: {'✅ Configured' if agent.virustotal_api else '❌ Not configured'}")
    print(f"🚫 AbuseIPDB API: {'✅ Configured' if agent.abusedb_api else '❌ Not configured'}")
    print(f"🤖 AI Analysis: {'✅ Ollama configured' if agent.ollama_url else '❌ Using fallback'}")
    print("=" * 40)
    print("✅ Bot is running securely...")
    
    # Run the bot
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    main()
