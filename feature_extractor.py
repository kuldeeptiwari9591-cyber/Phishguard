import socket
import ssl
import datetime
import requests
import tldextract
import logging
import re
import os
import whois
import threading
import hashlib
import json
import base64
from typing import Dict, Optional, List
from urllib.parse import urlparse
import sqlite3
from pathlib import Path

# --- CONFIG ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

WHOIS_TIMEOUT = 5
SCREENSHOT_DIR = "screenshots"
DATABASE_PATH = "phishing_detector.db"

class AdvancedPhishingDetector:
    def __init__(self, whois_api_key: Optional[str] = None):
        self.whois_api_key = whois_api_key
        # Load keys securely
        self.google_key = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
        self.vt_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        # Initialize database
        self._init_database()
        
        # Create screenshot directory
        Path(SCREENSHOT_DIR).mkdir(exist_ok=True)

    # ------------------ DATABASE SETUP ------------------

    def _init_database(self):
        """Initialize SQLite database with required tables."""
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT,
                risk_score INTEGER,
                screenshot_path TEXT,
                thumbnail_path TEXT,
                full_analysis_json TEXT
            )
        ''')
        
        # Domain reputation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domain_reputation (
                domain TEXT PRIMARY KEY,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_scans INTEGER DEFAULT 1,
                high_risk_count INTEGER DEFAULT 0,
                average_risk_score REAL DEFAULT 0,
                blacklist_count INTEGER DEFAULT 0
            )
        ''')
        
        # User reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                domain TEXT NOT NULL,
                report_type TEXT NOT NULL,
                user_comment TEXT,
                reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_ip_hash TEXT
            )
        ''')
        
        # Screenshot cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS screenshot_cache (
                domain TEXT PRIMARY KEY,
                screenshot_path TEXT,
                thumbnail_path TEXT,
                captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                file_size INTEGER
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_url ON scan_history(url)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_domain ON scan_history(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_domain ON user_reports(domain)')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")

    # ------------------ UTILITIES ------------------

    def _clean_date(self, dt):
        """Helper: Standardize date objects to datetime."""
        if isinstance(dt, list): 
            dt = dt[0]
        if isinstance(dt, str):
            try: 
                return datetime.datetime.strptime(dt[:10], "%Y-%m-%d")
            except: 
                return None
        if isinstance(dt, datetime.datetime): 
            return dt.replace(tzinfo=None)
        return None

    def _parse_ssl_date(self, date_str):
        """Helper: Make SSL dates human-readable (YYYY-MM-DD)."""
        if not date_str: 
            return "Unknown"
        try:
            fmt = "%b %d %H:%M:%S %Y %Z"
            dt_obj = datetime.datetime.strptime(date_str, fmt)
            return dt_obj.strftime("%Y-%m-%d")
        except: 
            return date_str

    def _clean_str(self, val):
        """Helper: Clean strings from lists/None types."""
        if not val: 
            return None
        if isinstance(val, list): 
            return str(val[0]).strip()
        return str(val).strip()

    def _clean_category_name(self, name):
        """Helper: Detect if owner is hidden via Privacy Proxy."""
        name = str(name)
        lower = name.lower()
        if any(x in lower for x in ["privacy", "redacted", "contact", "protection", "proxy"]):
            return "Hidden (Privacy Protected)"
        return name.title()

    def _whois_with_timeout(self, domain: str):
        """Helper: Threaded WHOIS lookup to prevent freezing."""
        result = {}
        def task():
            try: 
                result["data"] = whois.whois(domain)
            except: 
                result["data"] = None
        t = threading.Thread(target=task)
        t.start()
        t.join(WHOIS_TIMEOUT)
        return result.get("data")

    def _generate_url_hash(self, url: str) -> str:
        """Generate unique hash for URL (for filenames)."""
        return hashlib.md5(url.encode()).hexdigest()

    # ------------------ CONTEXT AWARENESS ------------------

    def _determine_context(self, url: str, domain: str) -> tuple:
        """
        Detects both context and category of the website.
        Returns: (context, category_name)
        """
        url_lower = url.lower()
        
        # Banking / Finance
        if any(k in url_lower for k in ['bank', 'wallet', 'paypal', 'stripe', 'payment', 'credit', 'debit']):
            return ("BANKING/FINANCE", "Financial Services")
        
        # Login/Authentication
        if any(k in url_lower for k in ['login', 'signin', 'auth', 'account', 'password']):
            return ("AUTHENTICATION", "User Authentication")
        
        # E-commerce/Shopping
        if any(k in url_lower for k in ['shop', 'store', 'buy', 'checkout', 'cart', 'product', 'order']):
            return ("SHOPPING", "E-Commerce")
        
        # Government / Education
        if domain.endswith(('.gov', '.edu', '.ac.in', '.gov.in', '.ac.uk', '.edu.au')):
            return ("GOVERNMENT/EDUCATION", "Government/Education")
        
        # Social Media
        if any(k in domain for k in ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'snapchat']):
            return ("SOCIAL_MEDIA", "Social Media")
            
        # Entertainment / Streaming
        if any(k in url_lower for k in ['movie', 'stream', 'watch', 'video', 'film', 'series', 'episode', 'download', 'hd', 'flix', 'hub']):
            return ("ENTERTAINMENT", "Streaming/Entertainment")
        
        # News / Media
        if any(k in url_lower for k in ['news', 'blog', 'article', 'post', 'media']):
            return ("NEWS/MEDIA", "News & Media")
        
        # Gaming
        if any(k in url_lower for k in ['game', 'play', 'gaming', 'gamer', 'esports']):
            return ("GAMING", "Gaming")
        
        # Technology / Software
        if any(k in url_lower for k in ['software', 'download', 'app', 'tech', 'developer', 'api', 'docs']):
            return ("TECHNOLOGY", "Technology")
        
        # Adult Content
        if any(k in url_lower for k in ['adult', 'xxx', 'porn', '18+', 'nsfw']):
            return ("ADULT_CONTENT", "Adult Content")
        
        # File Sharing / Cloud
        if any(k in url_lower for k in ['drive', 'dropbox', 'upload', 'file', 'cloud', 'storage']):
            return ("FILE_SHARING", "File Sharing")

        return ("GENERAL", "General Website")

    # ------------------ DATA GATHERING ------------------

    def verify_url_exists(self, url: str) -> Optional[str]:
        """Check if URL is reachable."""
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        try:
            r = requests.head(url, timeout=4, headers=headers, allow_redirects=True)
            if r.status_code < 400: 
                return r.url
        except: 
            pass
        try:
            r = requests.get(url, timeout=4, headers=headers, allow_redirects=True)
            if r.status_code < 400: 
                return r.url
        except: 
            return None

    def get_server_ip(self, domain: str) -> str:
        """Get IP address of domain."""
        try: 
            return socket.gethostbyname(domain)
        except: 
            return "Unknown"

    def _fetch_whois_data(self, domain: str, features: Dict):
        """Fetch WHOIS data with graceful degradation."""
        # Try API first (if key available)
        if self.whois_api_key:
            if self._try_whois_api(domain, features):
                logger.info(f"WHOIS data retrieved via API for {domain}")
                return
            else:
                logger.warning(f"WHOIS API failed for {domain}, trying local fallback")
        
        # Try local WHOIS as fallback
        if self._try_whois_local(domain, features):
            logger.info(f"WHOIS data retrieved locally for {domain}")
            return
        
        # If both fail, continue with defaults
        logger.warning(f"WHOIS lookup failed for {domain}, using defaults")
        features["technical_summary"]["registrar"] = "Unknown"
        features["technical_summary"]["category"] = "Unknown"
        features["technical_summary"]["domain_age_days"] = "Unknown"

    def _try_whois_api(self, domain: str, features: Dict) -> bool:
        """Try WHOIS API lookup with timeout and retry."""
        if not self.whois_api_key:
            return False
            
        try:
            endpoint = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
            params = {
                "apiKey": self.whois_api_key, 
                "domainName": domain, 
                "outputFormat": "JSON"
            }
            
            # Single attempt with shorter timeout
            try:
                r = requests.get(endpoint, params=params, timeout=5)  # Reduced to 5 seconds
                
                if r.status_code != 200: 
                    return False
                    
                data = r.json().get("WhoisRecord", {})
                if not data: 
                    return False
                
                # Extract data
                features["technical_summary"]["registrar"] = data.get("registrarName", "Unknown")
                raw_org = data.get("registrant", {}).get("organization", "Unknown")
                features["technical_summary"]["category"] = self._clean_category_name(raw_org)
                
                if data.get("createdDate"):
                    c = self._clean_date(data["createdDate"])
                    if c: 
                        features["technical_summary"]["domain_age_days"] = (datetime.datetime.now() - c).days
                return True
                
            except (requests.Timeout, requests.ConnectionError) as e:
                logger.warning(f"WHOIS API timeout/connection error: {e}")
                return False
                    
        except Exception as e:
            logger.error(f"WHOIS API error: {e}")
            return False

    def _try_whois_local(self, domain: str, features: Dict) -> bool:
        """Try local WHOIS lookup."""
        try:
            w = self._whois_with_timeout(domain)
            if not w: 
                return False

            # Smart Org Finder
            raw_org = (self._clean_str(w.org) or self._clean_str(w.get('organization')) or 
                       self._clean_str(w.name))
            if raw_org: 
                features["technical_summary"]["category"] = self._clean_category_name(raw_org)
            
            # Dates
            creation = w.creation_date or w.updated_date
            c = self._clean_date(creation)
            if c: 
                features["technical_summary"]["domain_age_days"] = (datetime.datetime.now() - c).days
            
            # Registrar
            reg = self._clean_str(w.registrar)
            if reg: 
                features["technical_summary"]["registrar"] = reg
            
            return True
        except Exception as e:
            logger.error(f"Local WHOIS error: {e}")
            return False

    def _fetch_ssl_data_advanced(self, domain: str, features: Dict):
        """Enhanced SSL certificate analysis."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    features["detected_signals"]["https"] = True
                    features["technical_summary"]["ssl_valid"] = True
                    
                    # Issuer
                    issuer = dict(x[0] for x in cert["issuer"])
                    features["technical_summary"]["ssl_issuer"] = issuer.get("organizationName", "Unknown")
                    
                    # Certificate dates
                    not_before = self._parse_ssl_date(cert.get("notBefore"))
                    not_after = self._parse_ssl_date(cert.get("notAfter"))
                    features["technical_summary"]["ssl_issued_date"] = not_before
                    features["technical_summary"]["ssl_expiry_date"] = not_after
                    
                    # Calculate certificate age
                    try:
                        issued_dt = datetime.datetime.strptime(not_before, "%Y-%m-%d")
                        cert_age = (datetime.datetime.now() - issued_dt).days
                        features["technical_summary"]["ssl_cert_age_days"] = cert_age
                    except:
                        features["technical_summary"]["ssl_cert_age_days"] = "Unknown"
                    
                    # Check if expired
                    try:
                        expiry_dt = datetime.datetime.strptime(not_after, "%Y-%m-%d")
                        features["technical_summary"]["ssl_expired"] = datetime.datetime.now() > expiry_dt
                    except:
                        features["technical_summary"]["ssl_expired"] = False
                    
                    # Subject Alternative Names
                    san = []
                    for ext in cert.get('subjectAltName', []):
                        if ext[0] == 'DNS':
                            san.append(ext[1])
                    features["technical_summary"]["ssl_san"] = san
                    
        except Exception as e:
            logger.info(f"SSL check failed for {domain}: {e}")
            features["detected_signals"]["https"] = False
            features["technical_summary"]["ssl_valid"] = False
            features["technical_summary"]["ssl_issuer"] = "None"
            features["technical_summary"]["ssl_issued_date"] = "Unknown"
            features["technical_summary"]["ssl_expiry_date"] = "Unknown"
            features["technical_summary"]["ssl_cert_age_days"] = "Unknown"
            features["technical_summary"]["ssl_expired"] = False

    # ------------------ SCREENSHOT CAPTURE ------------------

    def _check_screenshot_cache(self, domain: str) -> Optional[Dict]:
        """Check if screenshot exists in cache (< 24 hours old)."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT screenshot_path, thumbnail_path, captured_at 
                FROM screenshot_cache 
                WHERE domain = ? 
                AND datetime(captured_at) > datetime('now', '-24 hours')
            ''', (domain,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    "screenshot_path": result[0],
                    "thumbnail_path": result[1],
                    "captured_at": result[2],
                    "status": "cached"
                }
            return None
        except Exception as e:
            logger.error(f"Screenshot cache check error: {e}")
            return None

    def _capture_screenshot(self, url: str, domain: str) -> Dict:
        """
        Capture website screenshot using external API with retry logic.
        """
        # Check cache first
        cached = self._check_screenshot_cache(domain)
        if cached:
            return cached
        
        screenshot_api_key = os.getenv('SCREENSHOT_API_KEY')
        
        if not screenshot_api_key:
            logger.warning("SCREENSHOT_API_KEY not found. Screenshots disabled.")
            return {"status": "disabled", "error": "Screenshot API key not configured"}
        
        try:
            url_hash = self._generate_url_hash(url)
            screenshot_path = f"{SCREENSHOT_DIR}/{url_hash}.png"
            thumbnail_path = f"{SCREENSHOT_DIR}/{url_hash}_thumb.png"
            
            # ScreenshotAPI.net
            api_url = f"https://shot.screenshotapi.net/screenshot"
            params = {
                'token': screenshot_api_key,
                'url': url,
                'width': 1920,
                'height': 1080,
                'output': 'image',
                'file_type': 'png',
                'wait_for_event': 'load'
            }
            
            # Retry logic with increased timeout
            max_retries = 2
            for attempt in range(max_retries):
                try:
                    logger.info(f"Screenshot attempt {attempt + 1} for {domain}")
                    response = requests.get(api_url, params=params, timeout=20)  # Increased to 20s
                    
                    if response.status_code == 200:
                        # Save screenshot
                        with open(screenshot_path, 'wb') as f:
                            f.write(response.content)
                        
                        # Create thumbnail
                        try:
                            from PIL import Image
                            img = Image.open(screenshot_path)
                            img.thumbnail((400, 300))
                            img.save(thumbnail_path)
                        except ImportError:
                            import shutil
                            shutil.copy(screenshot_path, thumbnail_path)
                        
                        # Save to cache
                        self._save_screenshot_metadata(domain, {
                            "screenshot_path": screenshot_path,
                            "thumbnail_path": thumbnail_path,
                            "captured_at": datetime.datetime.now().isoformat()
                        })
                        
                        logger.info(f"Screenshot captured successfully for {domain}")
                        return {
                            "screenshot_path": screenshot_path,
                            "thumbnail_path": thumbnail_path,
                            "captured_at": datetime.datetime.now().isoformat(),
                            "status": "success"
                        }
                    elif attempt < max_retries - 1:
                        logger.warning(f"Screenshot API returned {response.status_code}, retrying...")
                        import time
                        time.sleep(2)
                        continue
                    else:
                        logger.error(f"Screenshot API error: {response.status_code}")
                        return {"status": "failed", "error": f"API returned {response.status_code}"}
                        
                except requests.Timeout:
                    logger.warning(f"Screenshot timeout on attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(2)
                        continue
                    return {"status": "failed", "error": "Screenshot API timeout"}
                    
                except requests.ConnectionError as e:
                    logger.warning(f"Screenshot connection error: {e}")
                    if attempt < max_retries - 1:
                        import time
                        time.sleep(2)
                        continue
                    return {"status": "failed", "error": "Connection error"}
            
        except Exception as e:
            logger.error(f"Screenshot capture error: {e}")
            return {"status": "failed", "error": str(e)}

    def _save_screenshot_metadata(self, domain: str, screenshot_data: Dict):
        """Save screenshot metadata to database."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO screenshot_cache 
                (domain, screenshot_path, thumbnail_path, captured_at, file_size)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                domain,
                screenshot_data["screenshot_path"],
                screenshot_data["thumbnail_path"],
                screenshot_data["captured_at"],
                0  # file_size placeholder
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error saving screenshot metadata: {e}")

    # ------------------ API CHECKS ------------------

    def _check_apis(self, url: str, features: Dict):
        """Check URL against Google Safe Browsing and VirusTotal."""
        
        # Initialize API results
        features["api_results"] = {}
        
        # 1. Google Safe Browsing
        if self.google_key:
            try:
                api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_key}"
                payload = {
                    "client": {"clientId": "phishguard", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}]
                    }
                }
                r = requests.post(api, json=payload, timeout=4)
                if r.status_code == 200 and "matches" in r.json():
                    features["detected_signals"]["blacklist_hit"] = True
                    threat_type = r.json()["matches"][0].get("threatType", "UNKNOWN")
                    features["api_results"]["google_safe_browsing"] = f"⚠️ Threat detected: {threat_type}"
                    features["why_dangerous"].insert(0, f"🚨 CRITICAL: Google Safe Browsing flagged as {threat_type}")
                else:
                    features["api_results"]["google_safe_browsing"] = "✓ Clean"
            except Exception as e:
                logger.error(f"Google Safe Browsing error: {e}")
                features["api_results"]["google_safe_browsing"] = "Error checking"

        # 2. VirusTotal
        if self.vt_key:
            try:
                # URL ID for VirusTotal
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
                headers = {"x-apikey": self.vt_key}
                
                r = requests.get(api_url, headers=headers, timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values())
                    
                    if malicious > 0:
                        features["detected_signals"]["blacklist_hit"] = True
                        features["api_results"]["virustotal"] = f"⚠️ {malicious}/{total} engines flagged as malicious"
                        features["why_dangerous"].insert(0, f"🚨 CRITICAL: {malicious} security engines detected this as malicious")
                    elif suspicious > 0:
                        features["api_results"]["virustotal"] = f"⚠️ {suspicious}/{total} engines flagged as suspicious"
                        features["why_dangerous"].append(f"⚠️ {suspicious} security engines found suspicious patterns")
                    else:
                        features["api_results"]["virustotal"] = f"✓ Clean (0/{total} detections)"
                else:
                    features["api_results"]["virustotal"] = "Not in database"
            except Exception as e:
                logger.error(f"VirusTotal error: {e}")
                features["api_results"]["virustotal"] = "Error checking"

    # ------------------ HEURISTICS ------------------

    def _detect_homograph_attack(self, domain: str) -> bool:
        """Detect use of look-alike characters (Cyrillic, Greek)."""
        # Cyrillic characters that look like Latin
        cyrillic_lookalikes = set('аеорсухіјАВЕКМНОРСТХІЈ')
        suspicious_chars = set(domain) & cyrillic_lookalikes
        return len(suspicious_chars) > 0

    def _perform_heuristics(self, url: str, extracted, features: Dict):
        """Perform rule-based heuristic analysis."""
        signals = features["detected_signals"]
        why_dangerous = features["why_dangerous"]
        domain = extracted.domain + "." + extracted.suffix
        
        # A. Typosquatting (Brand Imitation)
        top_brands = ["google", "facebook", "amazon", "apple", "paypal", "microsoft", 
                      "netflix", "instagram", "twitter", "linkedin", "ebay", "walmart",
                      "youtube", "reddit", "github", "dropbox"]
        
        for brand in top_brands:
            if brand in extracted.domain and extracted.domain != brand:
                signals["typosquatting"] = True
                why_dangerous.append(f"⚠️ Domain name '{extracted.domain}' imitates popular brand '{brand}'")
                break
        
        # B. New Domain Check
        age = features["technical_summary"].get("domain_age_days")
        if isinstance(age, int):
            if age < 30:
                signals["new_domain"] = True
                why_dangerous.append(f"⚠️ Domain is extremely new ({age} days old)")
            elif age < 90:
                why_dangerous.append(f"⚠️ Domain is relatively new ({age} days old)")
        
        # C. IP Address Usage
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", extracted.domain):
            signals["ip_usage"] = True
            why_dangerous.append("⚠️ Website uses a raw IP address instead of a domain name")
            
        # D. Suspicious Keywords
        risky_words = ["verify", "account", "suspended", "secure", "update", "confirm", 
                       "banking", "login", "signin", "password", "urgent"]
        found_keywords = [w for w in risky_words if w in url.lower()]
        if len(found_keywords) >= 2:
            signals["suspicious_keywords"] = True
            why_dangerous.append(f"⚠️ URL contains suspicious keywords: {', '.join(found_keywords)}")
        
        # E. URL Shortener Detection
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'cutt.ly', 
                      'rb.gy', 'is.gd', 'cli.gs', 'short.io']
        if any(s in domain for s in shorteners):
            signals["url_shortener"] = True
            why_dangerous.append("⚠️ Uses URL shortener (hides real destination)")
        
        # F. Homograph Attack Detection
        if self._detect_homograph_attack(domain):
            signals["homograph_attack"] = True
            why_dangerous.append("⚠️ Uses look-alike characters to mimic legitimate sites")
        
        # G. Path Depth Analysis
        parsed = urlparse(url)
        path_depth = parsed.path.count('/') - 1
        if path_depth > 5:
            signals["deep_path"] = True
            why_dangerous.append(f"⚠️ Unusually deep URL path ({path_depth} levels)")
        
        # H. Subdomain Excess
        subdomain_count = extracted.subdomain.count('.') + (1 if extracted.subdomain else 0)
        if subdomain_count > 3:
            signals["excessive_subdomains"] = True
            why_dangerous.append(f"⚠️ Too many subdomains ({subdomain_count})")
        
        # I. Non-Standard Port
        if parsed.port and parsed.port not in [80, 443]:
            signals["non_standard_port"] = True
            why_dangerous.append(f"⚠️ Uses unusual port {parsed.port}")
        
        # J. SSL Certificate Checks
        tech = features["technical_summary"]
        
        # Self-Signed Certificate
        if tech.get("ssl_issuer") and "self" in tech["ssl_issuer"].lower():
            signals["self_signed_cert"] = True
            why_dangerous.append("⚠️ Uses self-signed SSL certificate (not verified by authority)")
        
        # Expired Certificate
        if tech.get("ssl_expired"):
            signals["expired_cert"] = True
            why_dangerous.append("⚠️ SSL certificate has expired")
        
        # New Certificate
        cert_age = tech.get("ssl_cert_age_days")
        if isinstance(cert_age, int) and cert_age < 7:
            signals["new_certificate"] = True
            why_dangerous.append(f"⚠️ SSL certificate is very new ({cert_age} days)")
        
        # Free SSL on Banking Site
        context = features.get("context", "")
        if context in ["BANKING/FINANCE", "AUTHENTICATION"] and tech.get("ssl_issuer"):
            if "let's encrypt" in tech["ssl_issuer"].lower():
                why_dangerous.append("⚠️ Uses free SSL certificate (unusual for financial institutions)")
        
        # K. TLD Analysis
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
        if any(extracted.suffix.endswith(tld.strip('.')) for tld in suspicious_tlds):
            signals["suspicious_tld"] = True
            why_dangerous.append(f"⚠️ Uses suspicious top-level domain (.{extracted.suffix})")
        
        # L. Special Characters in Domain
        special_char_count = sum(domain.count(c) for c in ['-', '_', '@'])
        if special_char_count > 2:
            signals["excessive_special_chars"] = True
            why_dangerous.append(f"⚠️ Domain contains excessive special characters ({special_char_count})")

    # ------------------ DATABASE OPERATIONS ------------------

    def _check_scan_history(self, url: str, domain: str) -> Optional[Dict]:
        """Check if URL was recently scanned (< 6 hours)."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT full_analysis_json, scanned_at 
                FROM scan_history 
                WHERE url = ? 
                AND datetime(scanned_at) > datetime('now', '-6 hours')
                ORDER BY scanned_at DESC 
                LIMIT 1
            ''', (url,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                cached_data = json.loads(result[0])
                scanned_at = datetime.datetime.fromisoformat(result[1])
                age_minutes = int((datetime.datetime.now() - scanned_at).total_seconds() / 60)
                
                cached_data["from_cache"] = True
                cached_data["cache_age_minutes"] = age_minutes
                return cached_data
            
            return None
        except Exception as e:
            logger.error(f"Scan history check error: {e}")
            return None

    def _save_scan_to_history(self, features: Dict):
        """Save scan results to database."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Extract domain
            extracted = tldextract.extract(features["url"])
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Save scan history
            cursor.execute('''
                INSERT INTO scan_history 
                (url, domain, risk_level, risk_score, screenshot_path, thumbnail_path, full_analysis_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                features["url"],
                domain,
                features["risk_level"],
                features["risk_score"],
                features.get("screenshot_path"),
                features.get("thumbnail_path"),
                json.dumps(features)
            ))
            
            # Update domain reputation
            cursor.execute('''
                INSERT INTO domain_reputation (domain, total_scans, high_risk_count, average_risk_score, blacklist_count)
                VALUES (?, 1, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    last_scanned = CURRENT_TIMESTAMP,
                    total_scans = total_scans + 1,
                    high_risk_count = high_risk_count + ?,
                    average_risk_score = ((average_risk_score * total_scans) + ?) / (total_scans + 1),
                    blacklist_count = blacklist_count + ?
            ''', (
                domain,
                1 if features["risk_level"] == "HIGH" else 0,
                features["risk_score"],
                1 if features["detected_signals"].get("blacklist_hit") else 0,
                1 if features["risk_level"] == "HIGH" else 0,
                features["risk_score"],
                1 if features["detected_signals"].get("blacklist_hit") else 0
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error saving scan to history: {e}")

    def _get_domain_reputation(self, domain: str) -> Dict:
        """Get historical reputation data for domain."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT first_seen, last_scanned, total_scans, high_risk_count, 
                       average_risk_score, blacklist_count
                FROM domain_reputation 
                WHERE domain = ?
            ''', (domain,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    "first_seen": result[0],
                    "last_scanned": result[1],
                    "total_scans": result[2],
                    "times_flagged": result[3],
                    "average_risk_score": round(result[4], 2),
                    "blacklist_count": result[5]
                }
            
            return {
                "first_seen": "Never scanned",
                "total_scans": 0,
                "times_flagged": 0,
                "average_risk_score": 0
            }
        except Exception as e:
            logger.error(f"Domain reputation error: {e}")
            return {}

    def get_community_reports(self, domain: str) -> Dict:
        """Get aggregated community reports for domain."""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT report_type, COUNT(*) 
                FROM user_reports 
                WHERE domain = ? 
                GROUP BY report_type
            ''', (domain,))
            
            results = cursor.fetchall()
            
            cursor.execute('''
                SELECT MAX(reported_at) 
                FROM user_reports 
                WHERE domain = ?
            ''', (domain,))
            
            latest = cursor.fetchone()
            conn.close()
            
            report_counts = {row[0]: row[1] for row in results}
            
            return {
                "total_reports": sum(report_counts.values()),
                "phishing_reports": report_counts.get("phishing", 0),
                "safe_reports": report_counts.get("safe", 0),
                "false_positive_reports": report_counts.get("false_positive", 0),
                "latest_report": latest[0] if latest and latest[0] else "Never reported"
            }
        except Exception as e:
            logger.error(f"Community reports error: {e}")
            return {"total_reports": 0, "phishing_reports": 0, "safe_reports": 0}

    def submit_user_report(self, url: str, report_type: str, user_comment: str = "", user_ip: str = "") -> bool:
        """Allow users to report phishing sites."""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Hash IP for privacy
            ip_hash = hashlib.sha256(user_ip.encode()).hexdigest() if user_ip else ""
            
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO user_reports (url, domain, report_type, user_comment, user_ip_hash)
                VALUES (?, ?, ?, ?, ?)
            ''', (url, domain, report_type, user_comment, ip_hash))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"User report submission error: {e}")
            return False

    # ------------------ DECISION ENGINE ------------------

    def _generate_verdict(self, features: Dict):
        """Generate risk verdict based on all signals."""
        signals = features["detected_signals"]
        why_safe = features["why_safe"]
        why_dangerous = features["why_dangerous"]
        tech = features["technical_summary"]
        context = features["context"]
        
        # 1. Calculate Risk Score
        risk_score = 0
        
        # CRITICAL SIGNALS (Automatic HIGH RISK)
        critical_hit = False
        
        if signals.get("blacklist_hit"): 
            risk_score = 100  # Immediate 100
            critical_hit = True
            if "CRITICAL" not in str(why_dangerous[0]) if why_dangerous else "":
                why_dangerous.insert(0, "🚨 CRITICAL: Found in security blacklists (Google Safe Browsing or VirusTotal)")
        
        # Don't add more points if already critical
        if not critical_hit:
            # High severity signals
            if signals.get("typosquatting"): 
                risk_score += 60
            if signals.get("homograph_attack"): 
                risk_score += 50
            if signals.get("ip_usage"): 
                risk_score += 30
            if signals.get("new_domain"): 
                risk_score += 40
            if signals.get("expired_cert"): 
                risk_score += 35
            if signals.get("self_signed_cert"): 
                risk_score += 30
            if signals.get("url_shortener"): 
                risk_score += 25
            
            # Medium severity signals
            if not signals.get("https"): 
                risk_score += 20
            if signals.get("new_certificate"): 
                risk_score += 15
            if signals.get("excessive_subdomains"): 
                risk_score += 15
            if signals.get("suspicious_keywords"): 
                risk_score += 15
            if signals.get("suspicious_tld"): 
                risk_score += 15
            
            # Low severity signals
            if signals.get("deep_path"): 
                risk_score += 10
            if signals.get("non_standard_port"): 
                risk_score += 10
            if signals.get("excessive_special_chars"): 
                risk_score += 10
            
            # Context Weighting
            if context in ["BANKING/FINANCE", "AUTHENTICATION"]:
                if signals.get("new_domain") or not signals.get("https"):
                    risk_score += 30
                    why_dangerous.append("⚠️ Banking/login site with trust issues is extremely dangerous")
            
            # Community reports boost
            community = features.get("community_reports", {})
            if community.get("phishing_reports", 0) > 3:
                risk_score += 25
                why_dangerous.append(f"⚠️ {community['phishing_reports']} users reported this as phishing")
            
            # Domain reputation boost
            reputation = features.get("domain_reputation", {})
            if reputation.get("times_flagged", 0) > 2:
                risk_score += 20
                why_dangerous.append(f"⚠️ Previously flagged as suspicious {reputation['times_flagged']} times")
            
            # Trust Bonus
            age = tech.get("domain_age_days")
            if isinstance(age, int):
                if age > 365:
                    risk_score -= 20
                    why_safe.append(f"✓ Domain has a long history ({age} days old)")
                elif age > 180:
                    risk_score -= 10
                    why_safe.append(f"✓ Domain has been active for {age} days")
            
            if tech.get("ssl_valid"):
                why_safe.append("✓ Connection is encrypted (HTTPS)")
                if tech.get("ssl_issuer") and tech["ssl_issuer"] not in ["Unknown", "None"]:
                    if "DigiCert" in tech["ssl_issuer"] or "GlobalSign" in tech["ssl_issuer"]:
                        risk_score -= 10
                        why_safe.append(f"✓ Certificate issued by trusted authority ({tech['ssl_issuer']})")
            
            # Registrar trust
            if tech.get("registrar") and tech["registrar"] != "Unknown":
                trusted_registrars = ["GoDaddy", "Namecheap", "Google", "Amazon"]
                if any(tr in tech["registrar"] for tr in trusted_registrars):
                    why_safe.append(f"✓ Registered with reputable registrar ({tech['registrar']})")
        
        # 2. Final Risk Level Determination
        if critical_hit or risk_score >= 80:
            features["risk_level"] = "HIGH"
            features["verdict_summary"] = "⛔ CRITICAL THREAT - Confirmed phishing/malicious site"
        elif risk_score >= 50:
            features["risk_level"] = "HIGH"
            features["verdict_summary"] = "⛔ DANGEROUS - Multiple phishing indicators detected"
        elif risk_score >= 25:
            features["risk_level"] = "SUSPICIOUS"
            features["verdict_summary"] = "⚠️ SUSPICIOUS - Lacks sufficient trust signals"
        else:
            features["risk_level"] = "LOW"
            features["verdict_summary"] = "✅ SAFE - No immediate threats detected"

        features["risk_score"] = max(0, min(100, risk_score))

    def _generate_guidance(self, features: Dict):
        """Generate actionable guidance for users."""
        level = features["risk_level"]
        context = features["context"]
        
        if level == "HIGH":
            features["action_guidance"] = [
                "⛔ DO NOT enter passwords, credit cards, or personal information",
                "⛔ DO NOT download any files from this site",
                "⛔ Close this tab immediately",
                "Report this site to your IT department or authorities",
                "Run antivirus scan if you interacted with this site"
            ]
        elif level == "SUSPICIOUS":
            features["action_guidance"] = [
                "⚠️ Avoid entering sensitive information",
                "⚠️ Verify the URL spelling very carefully",
                "⚠️ Check if you can access this service from an official app instead",
                "⚠️ Look for contact information to verify legitimacy",
                "Proceed with extreme caution"
            ]
        else:
            features["action_guidance"] = [
                "✅ Site appears safe to browse",
                "Still avoid sharing sensitive data on public Wi-Fi",
                "Verify the URL matches what you expected",
                "Keep your browser and antivirus updated"
            ]

    def _calculate_confidence(self, features: Dict):
        """Calculate confidence level in the analysis."""
        tech = features["technical_summary"]
        signals = features["detected_signals"]
        
        confidence_points = 0
        max_points = 8
        
        # Data availability checks
        if tech.get("domain_age_days") != "Unknown": confidence_points += 1
        if tech.get("registrar") != "Unknown": confidence_points += 1
        if tech.get("ssl_valid") is not None: confidence_points += 1
        if tech.get("category") != "Unknown": confidence_points += 1
        
        # API verification
        if features.get("api_results", {}).get("google_safe_browsing"): confidence_points += 1
        if features.get("api_results", {}).get("virustotal"): confidence_points += 1
        
        # Screenshot available
        if features.get("screenshot_path"): confidence_points += 1
        
        # Historical data available
        reputation = features.get("domain_reputation", {})
        if reputation.get("total_scans", 0) > 0: confidence_points += 1
        
        # Calculate percentage
        confidence_pct = (confidence_points / max_points) * 100
        
        if confidence_pct >= 70:
            features["confidence"] = "HIGH"
            features["confidence_score"] = round(confidence_pct, 1)
        elif confidence_pct >= 40:
            features["confidence"] = "MODERATE"
            features["confidence_score"] = round(confidence_pct, 1)
        else:
            features["confidence"] = "LOW"
            features["confidence_score"] = round(confidence_pct, 1)
            features["verdict_summary"] += " (Limited data available - confidence is low)"

    # ------------------ MAIN ANALYSIS ------------------

    def analyze_url_comprehensive(self, url: str) -> Dict:
        """
        Comprehensive URL analysis with all features.
        Returns complete feature dictionary.
        """
        # 1. Normalize URL
        if not url.startswith(("http://", "https://")): 
            url = "http://" + url
        
        # 2. Initialize The Contract Structure
        features = {
            "url": url,
            "context": "GENERAL",
            "category": "General Website",
            "risk_level": "UNKNOWN",
            "confidence": "LOW",
            "confidence_score": 0,
            "risk_score": 0,
            "verdict_summary": "Analysis pending...",
            "why_dangerous": [],
            "why_safe": [],
            "detected_signals": {
                "new_domain": False,
                "typosquatting": False,
                "blacklist_hit": False,
                "https": False,
                "ip_usage": False,
                "url_shortener": False,
                "self_signed_cert": False,
                "expired_cert": False,
                "new_certificate": False,
                "homograph_attack": False,
                "excessive_subdomains": False,
                "non_standard_port": False,
                "suspicious_keywords": False,
                "deep_path": False,
                "suspicious_tld": False,
                "excessive_special_chars": False
            },
            "action_guidance": [],
            "technical_summary": {
                "domain_age_days": "Unknown",
                "ssl_valid": False,
                "ssl_issuer": "Unknown",
                "ssl_issued_date": "Unknown",
                "ssl_expiry_date": "Unknown",
                "ssl_cert_age_days": "Unknown",
                "ssl_expired": False,
                "registrar": "Unknown",
                "category": "Unknown",
                "server_ip": "Unknown"
            },
            "api_results": {},
            "from_cache": False
        }

        # 3. Extract domain info
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # 4. Check scan history cache
        cached_scan = self._check_scan_history(url, domain)
        if cached_scan:
            logger.info(f"Returning cached scan for {url}")
            return cached_scan
        
        # 5. Check if URL is reachable
        final_url = self.verify_url_exists(url)
        if not final_url:
            features["risk_level"] = "UNKNOWN"
            features["verdict_summary"] = "⚠️ Website is unreachable or offline"
            features["action_guidance"] = ["Site might be temporarily down", "Verify the URL is correct"]
            features["confidence"] = "LOW"
            return features

        try:
            # 6. Determine context and category
            context, category = self._determine_context(final_url, domain)
            features["context"] = context
            features["category"] = category
            
            logger.info(f"Analyzing {url} - Context: {context}, Category: {category}")
            
            # 7. Gather technical data
            features["technical_summary"]["server_ip"] = self.get_server_ip(domain)
            
            # Parallel data gathering
            self._fetch_whois_data(domain, features)
            self._fetch_ssl_data_advanced(domain, features)
            
            # 8. API checks
            self._check_apis(final_url, features)
            
            # 9. Screenshot capture
            screenshot_data = self._capture_screenshot(final_url, domain)
            if screenshot_data.get("status") == "success" or screenshot_data.get("status") == "cached":
                features["screenshot_path"] = screenshot_data.get("screenshot_path")
                features["thumbnail_path"] = screenshot_data.get("thumbnail_path")
                features["screenshot_captured_at"] = screenshot_data.get("captured_at")
            else:
                features["screenshot_path"] = None
                features["thumbnail_path"] = None
                features["screenshot_status"] = screenshot_data.get("status", "unavailable")
            
            # 10. Get community reports
            community = self.get_community_reports(domain)
            features["community_reports"] = community
            
            # 11. Get domain reputation
            reputation = self._get_domain_reputation(domain)
            features["domain_reputation"] = reputation
            
            # 12. Heuristic analysis
            self._perform_heuristics(final_url, extracted, features)
            
            # 13. Generate verdict and guidance
            self._generate_verdict(features)
            self._generate_guidance(features)
            self._calculate_confidence(features)
            
            # 14. Save to database
            self._save_scan_to_history(features)
            
            logger.info(f"✅ Analysis complete for {url} - Risk: {features['risk_level']} ({features['risk_score']}/100)")

        except Exception as e:
            logger.error(f"Analysis Error for {url}: {e}")
            features["verdict_summary"] = f"Analysis Error: {str(e)}"
            features["risk_level"] = "UNKNOWN"
            features["action_guidance"] = ["Unable to complete analysis", "Try again later"]

        return features


# ------------------ UTILITY FUNCTIONS ------------------

def analyze_url(url: str, whois_api_key: Optional[str] = None) -> Dict:
    """
    Convenience function to analyze a single URL.
    Usage: result = analyze_url("https://example.com")
    """
    detector = AdvancedPhishingDetector(whois_api_key=whois_api_key)
    return detector.analyze_url_comprehensive(url)


if __name__ == "__main__":
    # Example usage
    test_url = input("Enter URL to analyze: ")
    
    detector = AdvancedPhishingDetector()
    result = detector.analyze_url_comprehensive(test_url)
    
    print("\n" + "="*60)
    print(f"URL: {result['url']}")
    print(f"Category: {result['category']}")
    print(f"Context: {result['context']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Risk Score: {result['risk_score']}/100")
    print(f"Confidence: {result['confidence']} ({result['confidence_score']}%)")
    print(f"Verdict: {result['verdict_summary']}")
    print("="*60)
    
    if result['why_dangerous']:
        print("\n❌ Warning Signs:")
        for reason in result['why_dangerous']:
            print(f"  • {reason}")
    
    if result['why_safe']:
        print("\n✅ Trust Signals:")
        for reason in result['why_safe']:
            print(f"  • {reason}")
    
    print("\n📋 Action Guidance:")
    for action in result['action_guidance']:
        print(f"  • {action}")
    
    if result.get('screenshot_path'):
        print(f"\n📸 Screenshot: {result['screenshot_path']}")
    
    print("\n" + "="*60)
