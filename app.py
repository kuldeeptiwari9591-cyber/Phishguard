import os
import logging
import uuid
import datetime
from datetime import timezone
from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from pymongo import MongoClient
import certifi
from dotenv import load_dotenv
from pathlib import Path
import json

# IMPORT YOUR CUSTOM FEATURE EXTRACTOR
from feature_extractor import AdvancedPhishingDetector

# --- 1. TERMUX DNS FIX (CRITICAL FOR ANDROID) ---
try:
    import dns.resolver
    dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
    dns.resolver.default_resolver.nameservers = ['8.8.8.8']
    print("[*] DNS Resolver configured for Termux.")
except ImportError:
    pass
except Exception as e:
    print(f"[!] DNS Fix Warning: {e}")


# Get port from environment (for Cloud Run)
PORT = int(os.getenv('PORT', 5000))


# --- CONFIGURATION ---
app = Flask(__name__)
CORS(app)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load .env file
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, 'apikey.env'))

# Screenshot directory
SCREENSHOT_DIR = "screenshots"
Path(SCREENSHOT_DIR).mkdir(exist_ok=True)

# --- DATABASE CONNECTION ---
MONGO_URI = os.getenv('MONGO_URI')
mongo_db = None

def get_db():
    """
    Robust MongoDB connection with certifi for SSL.
    Connects to Atlas and returns database object.
    """
    global mongo_db
    if mongo_db is not None:
        return mongo_db
    
    if not MONGO_URI:
        logger.error("[!] MONGO_URI is missing from apikey.env")
        return None

    try:
        # Connect to Atlas using certifi for SSL
        client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
        mongo_db = client.get_database("phishguard")
        # Test connection
        mongo_db.command('ping')
        logger.info("[*] MongoDB Connected Successfully!")
        return mongo_db
    except Exception as e:
        logger.error(f"[!] DB Connection Error: {e}")
        return None

# --- STATIC FILE ROUTES ---

@app.route('/')
def home():
    """Serve main index page."""
    try:
        return open('index.html', encoding='utf-8').read()
    except Exception as e:
        logger.error(f"Error loading index.html: {e}")
        return f"Error loading index.html: {e}", 500

@app.route('/awareness')
def awareness():
    """Serve awareness page."""
    try:
        return open('awareness.html', encoding='utf-8').read()
    except Exception as e:
        logger.error(f"Error loading awareness.html: {e}")
        return f"Error loading awareness.html: {e}", 500

@app.route('/about')
def about():
    """Serve about page."""
    try:
        return open('about.html', encoding='utf-8').read()
    except Exception as e:
        logger.error(f"Error loading about.html: {e}")
        return f"Error loading about.html: {e}", 500

@app.route('/style.css')
def css():
    """Serve CSS file."""
    try:
        return open('style.css', encoding='utf-8').read(), 200, {'Content-Type': 'text/css'}
    except Exception as e:
        logger.error(f"Error loading style.css: {e}")
        return f"Error loading style.css: {e}", 500

@app.route('/script.js')
def js():
    """Serve JavaScript file."""
    try:
        return open('script.js', encoding='utf-8').read(), 200, {'Content-Type': 'application/javascript'}
    except Exception as e:
        logger.error(f"Error loading script.js: {e}")
        return f"Error loading script.js: {e}", 500

# --- SCREENSHOT SERVING ---

@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    """
    Serve screenshot images.
    Allows frontend to display captured screenshots.
    """
    try:
        return send_from_directory(SCREENSHOT_DIR, filename)
    except Exception as e:
        logger.error(f"Screenshot not found: {filename} - {e}")
        return jsonify({'error': 'Screenshot not found'}), 404

@app.route('/api/screenshot/<path:filename>')
def get_screenshot(filename):
    """
    Alternative endpoint for screenshot access.
    Returns image file directly.
    """
    try:
        screenshot_path = os.path.join(SCREENSHOT_DIR, filename)
        if os.path.exists(screenshot_path):
            return send_file(screenshot_path, mimetype='image/png')
        else:
            return jsonify({'error': 'Screenshot not found'}), 404
    except Exception as e:
        logger.error(f"Error serving screenshot: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: ANALYZE URL (ENHANCED) ---

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """
    Enhanced URL analysis endpoint with all Phase 2 features:
    - Screenshot capture
    - Enhanced SSL analysis
    - Historical data
    - Community reports
    - Comprehensive heuristics
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400

        logger.info(f"[*] Analyzing: {url}")
        
        # Initialize Detector with API keys
        whois_key = os.environ.get('WHOISXML_API_KEY')
        detector = AdvancedPhishingDetector(whois_api_key=whois_key)
        
        # Run comprehensive scan
        result = detector.analyze_url_comprehensive(url)
        
        # Add server timestamp
        result['analyzed_at'] = datetime.datetime.now(timezone.utc).isoformat()
        
        # SAVE TO MONGODB
        db = get_db()
        if db is not None:
            try:
                # Prepare document for storage
                analysis_doc = {
                    'history_id': str(uuid.uuid4()),
                    'url': url,
                    'domain': result.get('url', url).split('/')[2] if '/' in result.get('url', url) else url,
                    'risk_level': result.get('risk_level', 'UNKNOWN'),
                    'risk_score': result.get('risk_score', 0),
                    'confidence': result.get('confidence', 'LOW'),
                    'confidence_score': result.get('confidence_score', 0),
                    'context': result.get('context', 'GENERAL'),
                    'verdict_summary': result.get('verdict_summary', ''),
                    'timestamp': datetime.datetime.now(timezone.utc),
                    
                    # Detailed results
                    'detected_signals': result.get('detected_signals', {}),
                    'why_dangerous': result.get('why_dangerous', []),
                    'why_safe': result.get('why_safe', []),
                    'action_guidance': result.get('action_guidance', []),
                    
                    # Technical data
                    'technical_summary': result.get('technical_summary', {}),
                    'api_results': result.get('api_results', {}),
                    
                    # Screenshot info
                    'screenshot_path': result.get('screenshot_path'),
                    'thumbnail_path': result.get('thumbnail_path'),
                    
                    # Metadata
                    'from_cache': result.get('from_cache', False),
                    'cache_age_minutes': result.get('cache_age_minutes', 0)
                }
                
                # Insert into analyses collection
                db.analyses.insert_one(analysis_doc)
                logger.info(f"[+] Saved analysis for: {url}")
                
            except Exception as e:
                logger.error(f"[!] Database save failed: {e}")
        
        # Convert screenshot paths to URLs for frontend
        if result.get('screenshot_path'):
            result['screenshot_url'] = f"/screenshots/{os.path.basename(result['screenshot_path'])}"
        if result.get('thumbnail_path'):
            result['thumbnail_url'] = f"/screenshots/{os.path.basename(result['thumbnail_path'])}"
        
        return jsonify(result)

    except Exception as e:
        logger.error(f"[!] Analysis error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: SCAN HISTORY (ENHANCED) ---

@app.route('/api/history', methods=['GET'])
def get_history():
    """
    Get scan history with pagination and filtering.
    Query params:
    - limit: Number of results (default: 10, max: 100)
    - offset: Skip N results (for pagination)
    - risk_level: Filter by HIGH/SUSPICIOUS/LOW
    - days: Get scans from last N days
    """
    db = get_db()
    if db is None:
        return jsonify([])

    try:
        # Parse query parameters
        limit = min(int(request.args.get('limit', 10)), 100)
        offset = int(request.args.get('offset', 0))
        risk_filter = request.args.get('risk_level')
        days = request.args.get('days')
        
        # Build query
        query = {}
        
        # Risk level filter
        if risk_filter and risk_filter in ['HIGH', 'SUSPICIOUS', 'LOW']:
            query['risk_level'] = risk_filter
        
        # Date filter
        if days:
            try:
                cutoff_date = datetime.datetime.now(timezone.utc) - datetime.timedelta(days=int(days))
                query['timestamp'] = {'$gte': cutoff_date}
            except ValueError:
                pass
        
        # Query database
        cursor = db.analyses.find(query).sort("timestamp", -1).skip(offset).limit(limit)
        
        output = []
        for doc in cursor:
            # Format timestamp
            date_str = "Unknown"
            if 'timestamp' in doc and doc['timestamp']:
                try:
                    date_str = doc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                except:
                    date_str = str(doc['timestamp'])
            
            # Build history item
            history_item = {
                'id': str(doc.get('_id', '')),
                'history_id': doc.get('history_id', ''),
                'date': date_str,
                'url': doc.get('url', 'Unknown'),
                'domain': doc.get('domain', 'Unknown'),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'risk_score': doc.get('risk_score', 0),
                'confidence': doc.get('confidence', 'LOW'),
                'verdict_summary': doc.get('verdict_summary', ''),
                'context': doc.get('context', 'GENERAL'),
                'from_cache': doc.get('from_cache', False)
            }
            
            # Add screenshot if available
            if doc.get('thumbnail_path'):
                history_item['thumbnail_url'] = f"/screenshots/{os.path.basename(doc['thumbnail_path'])}"
            
            output.append(history_item)
        
        return jsonify(output)

    except Exception as e:
        logger.error(f"[!] History fetch error: {e}")
        return jsonify([])

# --- API: GET DETAILED SCAN RESULT ---

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """
    Get detailed information about a specific scan.
    Returns full analysis with all signals and technical details.
    """
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database unavailable'}), 503

    try:
        from bson import ObjectId
        
        # Try to find by _id or history_id
        try:
            scan = db.analyses.find_one({'_id': ObjectId(scan_id)})
        except:
            scan = db.analyses.find_one({'history_id': scan_id})
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Convert ObjectId to string
        scan['_id'] = str(scan['_id'])
        
        # Format timestamp
        if scan.get('timestamp'):
            scan['timestamp'] = scan['timestamp'].isoformat()
        
        # Add screenshot URLs
        if scan.get('screenshot_path'):
            scan['screenshot_url'] = f"/screenshots/{os.path.basename(scan['screenshot_path'])}"
        if scan.get('thumbnail_path'):
            scan['thumbnail_url'] = f"/screenshots/{os.path.basename(scan['thumbnail_path'])}"
        
        return jsonify(scan)

    except Exception as e:
        logger.error(f"[!] Scan details error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: STATISTICS DASHBOARD ---
'''
@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """
    Get aggregate statistics for dashboard:
    - Total scans
    - Scans by risk level
    - Most scanned domains
    - Recent trends
    """
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database unavailable'}), 503

    try:
        stats = {}
        
        # Total scans
        stats['total_scans'] = db.analyses.count_documents({})
        
        # Scans by risk level
        risk_breakdown = list(db.analyses.aggregate([
            {'$group': {'_id': '$risk_level', 'count': {'$sum': 1}}}
        ]))
        stats['by_risk_level'] = {item['_id']: item['count'] for item in risk_breakdown}
        
        # Today's scans
        today_start = datetime.datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        stats['today_scans'] = db.analyses.count_documents({
            'timestamp': {'$gte': today_start}
        })
        
        # This week's scans
        week_start = datetime.datetime.now(timezone.utc) - datetime.timedelta(days=7)
        stats['week_scans'] = db.analyses.count_documents({
            'timestamp': {'$gte': week_start}
        })
        
        # Most scanned domains (top 5)
        top_domains = list(db.analyses.aggregate([
            {'$group': {'_id': '$domain', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 5}
        ]))
        stats['top_domains'] = [{'domain': item['_id'], 'count': item['count']} for item in top_domains]
        
        # Average risk score
        avg_risk = list(db.analyses.aggregate([
            {'$group': {'_id': None, 'avg_score': {'$avg': '$risk_score'}}}
        ]))
        stats['average_risk_score'] = round(avg_risk[0]['avg_score'], 2) if avg_risk else 0
        
        # High risk percentage
        high_risk_count = db.analyses.count_documents({'risk_level': 'HIGH'})
        stats['high_risk_percentage'] = round((high_risk_count / stats['total_scans'] * 100), 2) if stats['total_scans'] > 0 else 0
        
        return jsonify(stats)

    except Exception as e:
        logger.error(f"[!] Statistics error: {e}")
        return jsonify({'error': str(e)}), 500
'''

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """
    Get aggregate statistics for dashboard:
    - Total scans
    - Scans by risk level
    - Most scanned domains
    - Recent trends
    """
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database unavailable'}), 503

    try:
        stats = {}
        
        # Total scans
        stats['total_scans'] = db.analyses.count_documents({})
        
        # Scans by risk level
        risk_breakdown = list(db.analyses.aggregate([
            {'$group': {'_id': '$risk_level', 'count': {'$sum': 1}}}
        ]))
        stats['by_risk_level'] = {item['_id']: item['count'] for item in risk_breakdown if item['_id']}
        
        # Today's scans
        today_start = datetime.datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        stats['today_scans'] = db.analyses.count_documents({
            'timestamp': {'$gte': today_start}
        })
        
        # This week's scans
        week_start = datetime.datetime.now(timezone.utc) - datetime.timedelta(days=7)
        stats['week_scans'] = db.analyses.count_documents({
            'timestamp': {'$gte': week_start}
        })
        
        # Most scanned domains (top 5)
        top_domains = list(db.analyses.aggregate([
            {'$match': {'domain': {'$ne': None, '$exists': True}}},  # ← FIX: Filter out None values
            {'$group': {'_id': '$domain', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 5}
        ]))
        stats['top_domains'] = [{'domain': item['_id'], 'count': item['count']} for item in top_domains if item['_id']]
        
        # Average risk score (FIX: Handle None and string values)
        avg_risk_pipeline = [
            {'$match': {'risk_score': {'$ne': None, '$exists': True, '$type': 'number'}}},  # ← FIX: Only numbers
            {'$group': {'_id': None, 'avg_score': {'$avg': '$risk_score'}}}
        ]
        avg_risk = list(db.analyses.aggregate(avg_risk_pipeline))
        stats['average_risk_score'] = round(avg_risk[0]['avg_score'], 2) if avg_risk and avg_risk[0].get('avg_score') else 0
        
        # High risk percentage (FIX: Handle division by zero)
        high_risk_count = db.analyses.count_documents({'risk_level': 'HIGH'})
        if stats['total_scans'] > 0:
            stats['high_risk_percentage'] = round((high_risk_count / stats['total_scans'] * 100), 2)
        else:
            stats['high_risk_percentage'] = 0
        
        return jsonify(stats)

    except Exception as e:
        logger.error(f"[!] Statistics error: {e}")
        # Return default values if error
        return jsonify({
            'total_scans': 0,
            'by_risk_level': {},
            'today_scans': 0,
            'week_scans': 0,
            'top_domains': [],
            'average_risk_score': 0,
            'high_risk_percentage': 0
        })


# --- API: COMMUNITY REPORTS ---

@app.route('/api/report', methods=['POST'])
def submit_report():
    """
    Allow users to report phishing sites or false positives.
    Body: {
        "url": "https://example.com",
        "report_type": "phishing" | "safe" | "false_positive",
        "comment": "Optional user comment"
    }
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        report_type = data.get('report_type', '').strip()
        comment = data.get('comment', '').strip()
        
        if not url or not report_type:
            return jsonify({'error': 'URL and report_type required'}), 400
        
        if report_type not in ['phishing', 'safe', 'false_positive']:
            return jsonify({'error': 'Invalid report_type'}), 400
        
        # Get user IP (hashed for privacy)
        user_ip = request.remote_addr
        
        # Initialize detector and submit report
        detector = AdvancedPhishingDetector()
        success = detector.submit_user_report(url, report_type, comment, user_ip)
        
        if success:
            logger.info(f"[+] User report submitted: {url} - {report_type}")
            return jsonify({'success': True, 'message': 'Report submitted successfully'})
        else:
            return jsonify({'error': 'Failed to submit report'}), 500

    except Exception as e:
        logger.error(f"[!] Report submission error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<domain>', methods=['GET'])
def get_domain_reports(domain):
    """
    Get community reports for a specific domain.
    Returns aggregated report statistics.
    """
    try:
        detector = AdvancedPhishingDetector()
        reports = detector.get_community_reports(domain)
        return jsonify(reports)
    except Exception as e:
        logger.error(f"[!] Get reports error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: DOMAIN REPUTATION ---

@app.route('/api/reputation/<domain>', methods=['GET'])
def get_domain_reputation(domain):
    """
    Get historical reputation data for a domain.
    Returns scan history and risk trends.
    """
    try:
        detector = AdvancedPhishingDetector()
        reputation = detector._get_domain_reputation(domain)
        return jsonify(reputation)
    except Exception as e:
        logger.error(f"[!] Reputation lookup error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: BATCH ANALYSIS ---

@app.route('/api/analyze-batch', methods=['POST'])
def analyze_batch():
    """
    Analyze multiple URLs at once.
    Body: {
        "urls": ["url1", "url2", "url3", ...]
    }
    Max 10 URLs per request.
    """
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({'error': 'urls array required'}), 400
        
        if len(urls) > 10:
            return jsonify({'error': 'Maximum 10 URLs per batch'}), 400
        
        # Initialize detector
        whois_key = os.environ.get('WHOISXML_API_KEY')
        detector = AdvancedPhishingDetector(whois_api_key=whois_key)
        
        results = []
        for url in urls:
            try:
                result = detector.analyze_url_comprehensive(url.strip())
                
                # Add screenshot URLs
                if result.get('screenshot_path'):
                    result['screenshot_url'] = f"/screenshots/{os.path.basename(result['screenshot_path'])}"
                if result.get('thumbnail_path'):
                    result['thumbnail_url'] = f"/screenshots/{os.path.basename(result['thumbnail_path'])}"
                
                results.append(result)
                
                # Save to database
                db = get_db()
                if db is not None:
                    analysis_doc = {
                        'history_id': str(uuid.uuid4()),
                        'url': url,
                        'risk_level': result.get('risk_level', 'UNKNOWN'),
                        'risk_score': result.get('risk_score', 0),
                        'timestamp': datetime.datetime.now(timezone.utc),
                        'batch_analysis': True
                    }
                    db.analyses.insert_one(analysis_doc)
                
            except Exception as e:
                logger.error(f"Batch analysis error for {url}: {e}")
                results.append({
                    'url': url,
                    'error': str(e),
                    'risk_level': 'ERROR'
                })
        
        return jsonify({
            'total': len(urls),
            'results': results
        })

    except Exception as e:
        logger.error(f"[!] Batch analysis error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: SEARCH HISTORY ---

@app.route('/api/search', methods=['GET'])
def search_history():
    """
    Search scan history by URL or domain.
    Query params:
    - q: Search query
    - limit: Results limit
    """
    db = get_db()
    if db is None:
        return jsonify([])

    try:
        query_text = request.args.get('q', '').strip()
        limit = min(int(request.args.get('limit', 20)), 100)
        
        if not query_text:
            return jsonify([])
        
        # Search in URL and domain fields
        search_query = {
            '$or': [
                {'url': {'$regex': query_text, '$options': 'i'}},
                {'domain': {'$regex': query_text, '$options': 'i'}}
            ]
        }
        
        cursor = db.analyses.find(search_query).sort("timestamp", -1).limit(limit)
        
        results = []
        for doc in cursor:
            results.append({
                'id': str(doc.get('_id', '')),
                'url': doc.get('url', ''),
                'domain': doc.get('domain', ''),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'risk_score': doc.get('risk_score', 0),
                'timestamp': doc['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if doc.get('timestamp') else 'Unknown'
            })
        
        return jsonify(results)

    except Exception as e:
        logger.error(f"[!] Search error: {e}")
        return jsonify([])

# --- API: DELETE HISTORY ---

@app.route('/api/history/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """
    Delete a scan from history.
    Requires scan_id (MongoDB _id or history_id).
    """
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database unavailable'}), 503

    try:
        from bson import ObjectId
        
        # Try to delete by _id or history_id
        try:
            result = db.analyses.delete_one({'_id': ObjectId(scan_id)})
        except:
            result = db.analyses.delete_one({'history_id': scan_id})
        
        if result.deleted_count > 0:
            logger.info(f"[+] Deleted scan: {scan_id}")
            return jsonify({'success': True, 'message': 'Scan deleted'})
        else:
            return jsonify({'error': 'Scan not found'}), 404

    except Exception as e:
        logger.error(f"[!] Delete error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: EXPORT HISTORY ---

@app.route('/api/export', methods=['GET'])
def export_history():
    """
    Export scan history as JSON or CSV.
    Query params:
    - format: 'json' or 'csv' (default: json)
    - days: Export last N days (default: all)
    """
    db = get_db()
    if db is None:
        return jsonify({'error': 'Database unavailable'}), 503

    try:
        export_format = request.args.get('format', 'json').lower()
        days = request.args.get('days')
        
        # Build query
        query = {}
        if days:
            try:
                cutoff_date = datetime.datetime.now(timezone.utc) - datetime.timedelta(days=int(days))
                query['timestamp'] = {'$gte': cutoff_date}
            except ValueError:
                pass
        
        # Get all matching scans
        cursor = db.analyses.find(query).sort("timestamp", -1)
        
        scans = []
        for doc in cursor:
            scan_data = {
                'url': doc.get('url', ''),
                'domain': doc.get('domain', ''),
                'risk_level': doc.get('risk_level', ''),
                'risk_score': doc.get('risk_score', 0),
                'confidence': doc.get('confidence', ''),
                'timestamp': doc['timestamp'].isoformat() if doc.get('timestamp') else ''
            }
            scans.append(scan_data)
        
        if export_format == 'csv':
            # Convert to CSV
            import io
            import csv
            
            output = io.StringIO()
            if scans:
                writer = csv.DictWriter(output, fieldnames=scans[0].keys())
                writer.writeheader()
                writer.writerows(scans)
            
            response = app.response_class(
                response=output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment;filename=phishguard_export.csv'}
            )
            return response
        else:
            # Return as JSON
            return jsonify(scans)

    except Exception as e:
        logger.error(f"[!] Export error: {e}")
        return jsonify({'error': str(e)}), 500

# --- API: HEALTH CHECK ---

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    System health check endpoint.
    Returns status of all services.
    """
    health = {
        'status': 'healthy',
        'timestamp': datetime.datetime.now(timezone.utc).isoformat(),
        'services': {}
    }
    
    # Check database
    db = get_db()
    health['services']['database'] = 'connected' if db is not None else 'disconnected'
    
    # Check screenshot directory
    health['services']['screenshot_storage'] = 'available' if os.path.exists(SCREENSHOT_DIR) else 'unavailable'
    
    # Check API keys
    health['services']['google_safe_browsing'] = 'configured' if os.getenv('GOOGLE_SAFE_BROWSING_API_KEY') else 'missing'
    health['services']['virustotal'] = 'configured' if os.getenv('VIRUSTOTAL_API_KEY') else 'missing'
    health['services']['whoisxml'] = 'configured' if os.getenv('WHOISXML_API_KEY') else 'missing'
    
    return jsonify(health)

# --- ERROR HANDLERS ---

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

# --- MAIN ---

if __name__ == '__main__':
    logger.info("[*] PhishGuard Server Starting...")
    logger.info("[*] Features: Screenshot Capture, Enhanced SSL, Historical Data, Community Reports")
    logger.info(f"[*] Access at: http://0.0.0.0:{PORT}")
    
    # Verify screenshot directory exists
    if not os.path.exists(SCREENSHOT_DIR):
        logger.warning(f"[!] Screenshot directory '{SCREENSHOT_DIR}' not found, creating...")
        Path(SCREENSHOT_DIR).mkdir(exist_ok=True)
    
    # For Google Cloud, don't use debug mode
    debug_mode = os.getenv('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=PORT, debug=debug_mode)
