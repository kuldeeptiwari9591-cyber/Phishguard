"""
PhishGuard - Rule-Based Phishing Detection System
A college project by Kuldeep Tiwari & Aman Tiwari

This is an educational tool demonstrating heuristic phishing detection.
Not intended for commercial use.
"""

from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
from pymongo import MongoClient
import certifi
import os
import logging
from datetime import datetime, timezone
from pathlib import Path
import json
from dotenv import load_dotenv

# Import detection engine
from feature_extractor import AdvancedPhishingDetector

# Load environment variables
load_dotenv('apikey.env')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s:%(name)s:%(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCREENSHOT_DIR = os.path.join(BASE_DIR, "screenshots")
PORT = int(os.getenv('PORT', 5000))

# Ensure directories exist
Path(SCREENSHOT_DIR).mkdir(exist_ok=True)

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    logger.warning("MONGO_URI not found in environment variables. History features will be disabled.")
    db = None
else:
    try:
        client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
        db = client.get_database("phishguard")
        logger.info("[*] MongoDB Connected Successfully!")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        db = None

# Initialize detector
detector = AdvancedPhishingDetector(whois_api_key=os.getenv('WHOISXML_API_KEY'))

# ============================================================================
# STATIC FILE ROUTES
# ============================================================================

@app.route('/')
def home():
    """Serve main index page."""
    try:
        return send_from_directory(BASE_DIR, 'index.html')
    except Exception as e:
        logger.error(f"Error loading index.html: {e}")
        return f"Error loading index.html: {e}", 500

@app.route('/awareness')
def awareness():
    """Serve awareness page."""
    try:
        return send_from_directory(BASE_DIR, 'awareness.html')
    except Exception as e:
        logger.error(f"Error loading awareness.html: {e}")
        return f"Error loading awareness.html: {e}", 500

@app.route('/about')
def about():
    """Serve about page."""
    try:
        return send_from_directory(BASE_DIR, 'about.html')
    except Exception as e:
        logger.error(f"Error loading about.html: {e}")
        return f"Error loading about.html: {e}", 500

@app.route('/style.css')
def css():
    """Serve CSS file."""
    try:
        return send_from_directory(BASE_DIR, 'style.css', mimetype='text/css')
    except Exception as e:
        logger.error(f"Error loading style.css: {e}")
        return f"/* Error loading CSS: {e} */", 500

@app.route('/script.js')
def js():
    """Serve JavaScript file."""
    try:
        return send_from_directory(BASE_DIR, 'script.js', mimetype='application/javascript')
    except Exception as e:
        logger.error(f"Error loading script.js: {e}")
        return f"console.error('Error loading script.js: {e}');", 500

@app.route('/logo.png')
def logo():
    """Serve logo file from main directory."""
    try:
        logo_path = os.path.join(BASE_DIR, 'logo.png')
        if os.path.exists(logo_path):
            return send_from_directory(BASE_DIR, 'logo.png', mimetype='image/png')
        else:
            # Generate a simple placeholder logo if file doesn't exist
            return generate_placeholder_logo()
    except Exception as e:
        logger.error(f"Error serving logo: {e}")
        return '', 404

def generate_placeholder_logo():
    """Generate a simple placeholder logo using PIL."""
    try:
        from PIL import Image, ImageDraw
        from io import BytesIO
        
        # Create a 128x128 image with transparent background
        img = Image.new('RGBA', (128, 128), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Draw a shield shape (simplified polygon)
        shield_points = [
            (64, 10),   # Top center
            (110, 30),  # Top right
            (110, 70),  # Middle right
            (64, 120),  # Bottom center
            (18, 70),   # Middle left
            (18, 30)    # Top left
        ]
        
        # Draw filled shield (blue)
        draw.polygon(shield_points, fill=(37, 99, 235, 255), outline=(30, 64, 175, 255))
        
        # Draw checkmark inside shield
        check_points = [
            (40, 64),
            (56, 80),
            (88, 48)
        ]
        draw.line([(40, 64), (56, 80)], fill='white', width=6)
        draw.line([(56, 80), (88, 48)], fill='white', width=6)
        
        # Save to BytesIO
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        # Save to file for future use
        logo_path = os.path.join(BASE_DIR, 'logo.png')
        with open(logo_path, 'wb') as f:
            f.write(img_io.getvalue())
        
        img_io.seek(0)
        from flask import send_file
        return send_file(img_io, mimetype='image/png')
        
    except ImportError:
        logger.warning("PIL not installed, cannot generate placeholder logo")
        return '', 404
    except Exception as e:
        logger.error(f"Error generating placeholder logo: {e}")
        return '', 404

# ============================================================================
# SCREENSHOT SERVING
# ============================================================================

@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    """Serve screenshot files."""
    try:
        return send_from_directory(SCREENSHOT_DIR, filename)
    except Exception as e:
        logger.error(f"Error serving screenshot: {e}")
        return '', 404

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """
    Main URL analysis endpoint.
    Accepts: {"url": "https://example.com"}
    Returns: Complete analysis results
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        logger.info(f"[*] Analyzing: {url}")
        
        # Perform analysis
        result = detector.analyze_url_comprehensive(url)
        
        # Add screenshot URLs if screenshots exist
        if result.get('screenshot_path'):
            filename = os.path.basename(result['screenshot_path'])
            result['screenshot_url'] = f'/screenshots/{filename}'
        
        if result.get('thumbnail_path'):
            filename = os.path.basename(result['thumbnail_path'])
            result['thumbnail_url'] = f'/screenshots/{filename}'
        
        # Save to MongoDB if available
        if db is not None:
            try:
                history_doc = {
                    'url': result['url'],
                    'domain': result.get('domain', ''),
                    'risk_level': result['risk_level'],
                    'risk_score': result['risk_score'],
                    'context': result.get('context', 'GENERAL'),
                    'category': result.get('category', 'Unknown'),
                    'timestamp': datetime.now(timezone.utc),
                    'full_analysis': result
                }
                db.analyses.insert_one(history_doc)
            except Exception as e:
                logger.error(f"Failed to save to MongoDB: {e}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    """
    Get aggregate statistics for dashboard.
    Returns: Total scans, risk breakdown, top domains, etc.
    """
    if db is None:
        return jsonify({
            'total_scans': 0,
            'by_risk_level': {},
            'today_scans': 0,
            'week_scans': 0,
            'top_domains': [],
            'average_risk_score': 0,
            'high_risk_percentage': 0
        })
    
    try:
        # Total scans
        total_scans = db.analyses.count_documents({})
        
        # Scans by risk level
        risk_breakdown = list(db.analyses.aggregate([
            {'$group': {'_id': '$risk_level', 'count': {'$sum': 1}}}
        ]))
        by_risk_level = {item['_id']: item['count'] for item in risk_breakdown if item['_id']}
        
        # Today's scans
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_scans = db.analyses.count_documents({
            'timestamp': {'$gte': today_start}
        })
        
        # This week's scans
        from datetime import timedelta
        week_start = datetime.now(timezone.utc) - timedelta(days=7)
        week_scans = db.analyses.count_documents({
            'timestamp': {'$gte': week_start}
        })
        
        # Top domains
        top_domains = list(db.analyses.aggregate([
            {'$match': {'domain': {'$ne': None, '$exists': True}}},
            {'$group': {'_id': '$domain', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 5}
        ]))
        top_domains_list = [{'domain': item['_id'], 'count': item['count']} for item in top_domains if item['_id']]
        
        # Average risk score
        avg_risk_pipeline = [
            {'$match': {'risk_score': {'$ne': None, '$exists': True, '$type': 'number'}}},
            {'$group': {'_id': None, 'avg_score': {'$avg': '$risk_score'}}}
        ]
        avg_risk = list(db.analyses.aggregate(avg_risk_pipeline))
        average_risk_score = round(avg_risk[0]['avg_score'], 2) if avg_risk and avg_risk[0].get('avg_score') else 0
        
        # High risk percentage
        high_risk_count = db.analyses.count_documents({'risk_level': 'HIGH'})
        high_risk_percentage = round((high_risk_count / total_scans * 100), 2) if total_scans > 0 else 0
        
        return jsonify({
            'total_scans': total_scans,
            'by_risk_level': by_risk_level,
            'today_scans': today_scans,
            'week_scans': week_scans,
            'top_domains': top_domains_list,
            'average_risk_score': average_risk_score,
            'high_risk_percentage': high_risk_percentage
        })
        
    except Exception as e:
        logger.error(f"[!] Statistics error: {e}")
        return jsonify({
            'total_scans': 0,
            'by_risk_level': {},
            'today_scans': 0,
            'week_scans': 0,
            'top_domains': [],
            'average_risk_score': 0,
            'high_risk_percentage': 0
        })

@app.route('/api/history', methods=['GET'])
def get_history():
    """
    Get scan history with optional filters.
    Query params: limit, offset, risk_level, days
    """
    if db is None:
        return jsonify([])
    
    try:
        limit = int(request.args.get('limit', 20))
        limit = min(limit, 100)  # Max 100 results
        offset = int(request.args.get('offset', 0))
        risk_level = request.args.get('risk_level')
        days = request.args.get('days')
        
        # Build query
        query = {}
        if risk_level and risk_level != 'all':
            query['risk_level'] = risk_level
        
        if days:
            from datetime import timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(days=int(days))
            query['timestamp'] = {'$gte': cutoff}
        
        # Execute query
        results = list(db.analyses.find(query)
                      .sort('timestamp', -1)
                      .skip(offset)
                      .limit(limit))
        
        # Format response
        history = []
        for doc in results:
            history.append({
                'id': str(doc['_id']),
                'url': doc.get('url', ''),
                'domain': doc.get('domain', ''),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'risk_score': doc.get('risk_score', 0),
                'context': doc.get('context', 'GENERAL'),
                'category': doc.get('category', 'Unknown'),
                'date': doc.get('timestamp', datetime.now()).isoformat(),
                'timestamp': doc.get('timestamp', datetime.now()).isoformat()
            })
        
        return jsonify(history)
        
    except Exception as e:
        logger.error(f"History error: {e}")
        return jsonify([])

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """
    Get detailed results for a specific scan.
    """
    if db is None:
        return jsonify({'error': 'Database not available'}), 503
    
    try:
        from bson.objectid import ObjectId
        
        # Try to find by MongoDB _id
        try:
            result = db.analyses.find_one({'_id': ObjectId(scan_id)})
        except:
            # If not valid ObjectId, try finding by other fields
            result = None
        
        if not result:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Return full analysis
        analysis = result.get('full_analysis', {})
        
        # Add screenshot URLs if they exist
        if analysis.get('screenshot_path'):
            filename = os.path.basename(analysis['screenshot_path'])
            analysis['screenshot_url'] = f'/screenshots/{filename}'
        
        if analysis.get('thumbnail_path'):
            filename = os.path.basename(analysis['thumbnail_path'])
            analysis['thumbnail_url'] = f'/screenshots/{filename}'
        
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Scan details error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/search', methods=['GET'])
def search_history():
    """
    Search scan history by URL or domain.
    Query param: q (search query)
    """
    if db is None:
        return jsonify([])
    
    try:
        query_str = request.args.get('q', '').strip()
        if not query_str:
            return jsonify([])
        
        # Search in URL and domain fields
        results = list(db.analyses.find({
            '$or': [
                {'url': {'$regex': query_str, '$options': 'i'}},
                {'domain': {'$regex': query_str, '$options': 'i'}}
            ]
        }).sort('timestamp', -1).limit(20))
        
        # Format response
        history = []
        for doc in results:
            history.append({
                'id': str(doc['_id']),
                'url': doc.get('url', ''),
                'domain': doc.get('domain', ''),
                'risk_level': doc.get('risk_level', 'UNKNOWN'),
                'risk_score': doc.get('risk_score', 0),
                'context': doc.get('context', 'GENERAL'),
                'timestamp': doc.get('timestamp', datetime.now()).isoformat()
            })
        
        return jsonify(history)
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify([])

@app.route('/api/report', methods=['POST'])
def submit_report():
    """
    Submit community report for a URL.
    Body: {"url": str, "report_type": str, "comment": str}
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        report_type = data.get('report_type', 'phishing')
        comment = data.get('comment', '')
        
        if not url:
            return jsonify({'success': False, 'error': 'URL is required'}), 400
        
        # Get user IP (hashed for privacy)
        user_ip = request.remote_addr or ''
        
        # Submit report to detector
        success = detector.submit_user_report(url, report_type, comment, user_ip)
        
        if success:
            logger.info(f"Report submitted for {url}: {report_type}")
            return jsonify({'success': True, 'message': 'Report submitted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to submit report'}), 500
            
    except Exception as e:
        logger.error(f"Report submission error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    System health check endpoint.
    Returns status of various components.
    """
    health = {
        'status': 'healthy',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'components': {}
    }
    
    # Check MongoDB
    if db is not None:
        try:
            db.command('ping')
            health['components']['mongodb'] = 'connected'
        except:
            health['components']['mongodb'] = 'disconnected'
            health['status'] = 'degraded'
    else:
        health['components']['mongodb'] = 'not_configured'
    
    # Check screenshot directory
    health['components']['screenshots'] = 'available' if os.path.exists(SCREENSHOT_DIR) else 'unavailable'
    
    # Check API keys
    health['components']['api_keys'] = {
        'google_safe_browsing': 'configured' if os.getenv('GOOGLE_SAFE_BROWSING_API_KEY') else 'missing',
        'virustotal': 'configured' if os.getenv('VIRUSTOTAL_API_KEY') else 'missing',
        'whoisxml': 'configured' if os.getenv('WHOISXML_API_KEY') else 'missing',
        'screenshot': 'configured' if os.getenv('SCREENSHOT_API_KEY') else 'missing'
    }
    
    return jsonify(health)

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def page_not_found(e):
    """Redirect all 404s to home page."""
    logger.info(f"404 redirect: {request.path}")
    return redirect('/')

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors."""
    logger.error(f"Internal error: {e}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================================================
# CATCH-ALL ROUTE
# ============================================================================

@app.route('/<path:path>')
def catch_all(path):
    """
    Catch all undefined routes and redirect to home.
    Allows awareness and about pages to work.
    """
    # Allow known pages
    if path in ['awareness', 'about', 'awareness.html', 'about.html']:
        if path.endswith('.html'):
            path = path[:-5]  # Remove .html extension
        return globals()[path]()
    
    # Redirect everything else to home
    logger.info(f"Catch-all redirect: {path}")
    return redirect('/')

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("[*] PhishGuard - Rule-Based Phishing Detection System")
    logger.info("[*] College Project by Kuldeep Tiwari & Aman Tiwari")
    logger.info("=" * 60)
    logger.info(f"[*] Server Starting on Port {PORT}...")
    logger.info("[*] Features:")
    logger.info("    ✓ Rule-Based Heuristic Analysis (16+ Detection Rules)")
    logger.info("    ✓ Screenshot Capture & Analysis")
    logger.info("    ✓ SSL Certificate Deep Inspection")
    logger.info("    ✓ Domain Age & WHOIS Verification")
    logger.info("    ✓ Community Intelligence & Reporting")
    logger.info("    ✓ Historical Reputation Tracking")
    logger.info("    ✓ Google Safe Browsing & VirusTotal Integration")
    logger.info("=" * 60)
    logger.info(f"[*] MongoDB: {'Connected' if db else 'Not Available'}")
    logger.info(f"[*] Screenshot Directory: {SCREENSHOT_DIR}")
    logger.info(f"[*] API Keys Configured:")
    logger.info(f"    - Google Safe Browsing: {'Yes' if os.getenv('GOOGLE_SAFE_BROWSING_API_KEY') else 'No'}")
    logger.info(f"    - VirusTotal: {'Yes' if os.getenv('VIRUSTOTAL_API_KEY') else 'No'}")
    logger.info(f"    - WhoisXML: {'Yes' if os.getenv('WHOISXML_API_KEY') else 'No'}")
    logger.info(f"    - Screenshot API: {'Yes' if os.getenv('SCREENSHOT_API_KEY') else 'No'}")
    logger.info("=" * 60)
    logger.info(f"[*] Access at: http://0.0.0.0:{PORT}")
    logger.info("[*] Educational Use Only - Not for Commercial Deployment")
    logger.info("=" * 60)
    
    # Verify logo exists or create it
    logo_path = os.path.join(BASE_DIR, 'logo.png')
    if not os.path.exists(logo_path):
        logger.warning("[!] logo.png not found, will generate placeholder on first request")
    else:
        logger.info(f"[*] Logo: {logo_path}")
    
    # Run the application
    # For development
    debug_mode = os.getenv('FLASK_ENV') != 'production'
    
    # For production (Render), gunicorn will handle this
    # This is just for local development
    app.run(host='0.0.0.0', port=PORT, debug=debug_mode)
