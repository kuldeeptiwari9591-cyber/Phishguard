Complete script.js with All Fixes
/* PhishGuard - Ultimate Forensic Controller with Phase 2 Features */

// --- GLOBAL VARIABLES ---
let quizQuestions = [];
let currentQuestionIndex = 0;
let userAnswers = [];
let currentScore = 0;
window.lastResults = null; // Stores data for PDF generation
let statsChart = null; // For Chart.js instance

// --- 1. QUIZ DATA ---
const allQuizQuestions = [
    { 
        question: "What is the most common sign of a phishing email?", 
        options: ["Urgent action required", "Personalized greeting", "Official domain", "No links"], 
        answer: "Urgent action required" 
    },
    { 
        question: "Which of these URLs is suspicious?", 
        options: ["paypal.com", "paypal-secure-login.com", "paypal.co.uk", "help.paypal.com"], 
        answer: "paypal-secure-login.com" 
    },
    { 
        question: "What does HTTPS ensure on a website?", 
        options: ["The site is legitimate", "The connection is encrypted", "The site has no viruses", "Google Verified"], 
        answer: "The connection is encrypted" 
    },
    { 
        question: "How should you verify a suspicious link?", 
        options: ["Click it immediately", "Hover over it to see the URL", "Forward it to a friend", "Ignore it"], 
        answer: "Hover over it to see the URL" 
    },
    { 
        question: "What is Two-Factor Authentication (2FA)?", 
        options: ["Using two passwords", "A second security layer (like SMS code)", "Double encryption", "Two firewalls"], 
        answer: "A second security layer (like SMS code)" 
    },
    {
        question: "What is a homograph attack?",
        options: ["Using similar-looking characters to mimic domains", "Attacking home networks", "Grammar mistakes in emails", "Graph-based visualization"],
        answer: "Using similar-looking characters to mimic domains"
    },
    {
        question: "Why is a newly registered domain suspicious?",
        options: ["It's always malicious", "Attackers often use new domains to avoid detection", "New domains are slower", "They can't have SSL"],
        answer: "Attackers often use new domains to avoid detection"
    },
    {
        question: "What does a self-signed SSL certificate indicate?",
        options: ["Maximum security", "Not verified by a trusted authority", "Google approved", "Bank-grade encryption"],
        answer: "Not verified by a trusted authority"
    }
];

// --- 2. INITIALIZATION ---
document.addEventListener('DOMContentLoaded', function() {
    loadHistory();
    loadStatistics();
    if (document.getElementById('quizContainer')) loadQuizQuestions();
    
    // Enable "Enter" key for scanning
    const inputField = document.getElementById('urlInput');
    if (inputField) {
        inputField.addEventListener("keypress", function(event) {
            if (event.key === "Enter") {
                event.preventDefault(); 
                analyzeURL(); 
            }
        });
    }

    // Initialize batch analysis if on that page
    if (document.getElementById('batchUrlInput')) {
        initBatchAnalysis();
    }
});

// --- 3. UI HELPER FUNCTIONS ---
function clearInput() {
    const input = document.getElementById('urlInput');
    if (input) {
        input.value = '';
        input.focus();
        document.getElementById('urlResults').classList.add('hidden');
    }
}

async function pasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        document.getElementById('urlInput').value = text;
        showNotification('URL pasted from clipboard', 'success');
    } catch (err) {
        showNotification('Failed to read clipboard. Please paste manually.', 'error');
    }
}

function getTheme(level) {
    if (level === 'HIGH') return { 
        color: '#dc2626', 
        icon: 'fa-ban', 
        bg: '#fef2f2',
        gradient: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)'
    };
    if (level === 'SUSPICIOUS') return { 
        color: '#d97706', 
        icon: 'fa-exclamation-triangle', 
        bg: '#fffbeb',
        gradient: 'linear-gradient(135deg, #d97706 0%, #92400e 100%)'
    };
    return { 
        color: '#16a34a', 
        icon: 'fa-check-circle', 
        bg: '#f0fdf4',
        gradient: 'linear-gradient(135deg, #16a34a 0%, #15803d 100%)'
    };
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    const colors = {
        error: '#dc2626',
        success: '#16a34a',
        info: '#2563eb',
        warning: '#d97706'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${colors[type] || colors.info};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 350px;
        word-wrap: break-word;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

// --- 4. MAIN ANALYSIS LOGIC (ENHANCED) ---
async function analyzeURL() {
    const urlInput = document.getElementById('urlInput').value.trim();
    if (!urlInput) { 
        showNotification('Please enter a URL first.', 'error'); 
        return; 
    }
    
    // Show Spinner
    const spinner = document.getElementById('loadingOverlay');
    if(spinner) spinner.classList.remove('hidden');
    
    document.getElementById('urlResults').classList.add('hidden');
    
    try {
        const response = await fetch('/api/analyze-url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server Error (${response.status}): ${errorText}`);
        }
        
        const results = await response.json();
        
        if(results.error) {
            showNotification(`⚠️ Analysis Failed: ${results.error}`, 'error');
            if(spinner) spinner.classList.add('hidden');
            return;
        }

        // Check for warnings
        if (results.warnings && results.warnings.length > 0) {
            results.warnings.forEach(warning => {
                console.warn('Analysis warning:', warning);
            });
        }

        window.lastResults = results;
        renderReport(results);
        
        document.getElementById('urlResults').classList.remove('hidden');
        
        // Reload history and stats
        loadHistory(); 
        loadStatistics();
        
        // Show success with details
        const msg = results.from_cache ? 
            `Analysis complete! (Cached result from ${results.cache_age_minutes} min ago)` : 
            'Analysis complete!';
        showNotification(msg, 'success');
        
    } catch (error) {
        console.error('Analysis error:', error);
        
        // User-friendly error messages
        let errorMsg = 'Analysis failed. ';
        if (error.message.includes('Failed to fetch')) {
            errorMsg += 'Cannot connect to server. Please check if the server is running.';
        } else if (error.message.includes('timeout')) {
            errorMsg += 'Request timed out. The website may be slow or unreachable.';
        } else {
            errorMsg += error.message;
        }
        
        showNotification(errorMsg, 'error');
    } finally {
        if(spinner) spinner.classList.add('hidden');
    }
}

// --- 5. RENDER REPORT (ENHANCED WITH SCREENSHOT & NEW DATA) ---
function renderReport(data) {
    const container = document.getElementById('urlResults');
    const theme = getTheme(data.risk_level);
    const tech = data.technical_summary;
    const signals = data.detected_signals;
    const community = data.community_reports || {};
    const reputation = data.domain_reputation || {};
    const api_results = data.api_results || {};

    // Category Icons Mapping
    const categoryIcons = {
        'BANKING/FINANCE': 'fa-university',
        'AUTHENTICATION': 'fa-key',
        'SHOPPING': 'fa-shopping-cart',
        'GOVERNMENT/EDUCATION': 'fa-landmark',
        'SOCIAL_MEDIA': 'fa-users',
        'ENTERTAINMENT': 'fa-film',
        'NEWS/MEDIA': 'fa-newspaper',
        'GAMING': 'fa-gamepad',
        'TECHNOLOGY': 'fa-code',
        'ADULT_CONTENT': 'fa-exclamation-triangle',
        'FILE_SHARING': 'fa-cloud',
        'GENERAL': 'fa-globe'
    };
    
    const categoryIcon = categoryIcons[data.context] || 'fa-globe';

    // A. Screenshot Section (with error handling)
    const screenshotHtml = data.screenshot_path && data.screenshot_url ? `
        <div style="margin-bottom: 2rem;">
            <h3 style="color: #1e293b; margin-bottom: 1rem; font-size: 1.1rem;">
                <i class="fas fa-camera"></i> Website Preview
            </h3>
            <div style="border: 2px solid #e2e8f0; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
                <img src="${data.screenshot_url}" alt="Website Screenshot" style="width: 100%; height: auto; display: block; cursor: pointer;" onclick="openScreenshotModal('${data.screenshot_url}')" onerror="this.parentElement.innerHTML='<div style=\\'padding:2rem;text-align:center;color:#94a3b8\\'><i class=\\'fas fa-image-slash\\' style=\\'font-size:3rem;margin-bottom:1rem\\'></i><p>Screenshot unavailable</p></div>'">
            </div>
            ${data.from_cache ? `<p style="color: #64748b; font-size: 0.85rem; margin-top: 0.5rem; text-align: center;"><i class="fas fa-clock"></i> Cached ${data.cache_age_minutes} minutes ago</p>` : ''}
        </div>
    ` : data.screenshot_status ? `
        <div style="background: #fef3c7; border: 1px solid #fbbf24; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; text-align: center;">
            <i class="fas fa-info-circle" style="color: #d97706; font-size: 2rem; margin-bottom: 0.5rem;"></i>
            <p style="color: #92400e; margin: 0;"><strong>Screenshot feature is ${data.screenshot_status}</strong></p>
            <p style="color: #78350f; font-size: 0.9rem; margin: 0.5rem 0 0 0;">Configure SCREENSHOT_API_KEY to enable this feature</p>
        </div>
    ` : '';

    // B. Action Guidance List
    const guidanceHtml = data.action_guidance.map(item => 
        `<li style="margin-bottom:8px; display:flex; align-items:start; gap:8px;">
            <i class="fas fa-chevron-right" style="color:${theme.color}; margin-top:4px;"></i>
            <span>${item}</span>
        </li>`
    ).join('');

    // C. Reasoning List (Why Safe / Dangerous)
    const reasons = [...data.why_dangerous, ...data.why_safe];
    const reasoningHtml = reasons.length > 0 
        ? reasons.map(r => {
            const isDanger = data.why_dangerous.includes(r);
            const icon = isDanger ? 'fa-exclamation-circle' : 'fa-check-circle';
            const color = isDanger ? '#dc2626' : '#16a34a';
            return `<div style="padding:12px; background:white; border-left:4px solid ${color}; margin-bottom:10px; font-size:0.95rem; border-radius:6px; box-shadow:0 1px 3px rgba(0,0,0,0.08); display:flex; gap:10px;">
                <i class="fas ${icon}" style="color:${color}; margin-top:2px;"></i>
                <span>${r}</span>
            </div>`;
        }).join('')
        : `<div style="color:#64748b; font-style:italic; padding:1rem; text-align:center;">No specific anomalies detected.</div>`;

    // D. Technical Grid Creator
    const createItem = (label, val, isBad) => `
        <div style="display:flex; justify-content:space-between; padding:12px 0; border-bottom:1px solid #f1f5f9;">
            <span style="color:#64748b; font-size:0.9rem;">${label}</span>
            <span style="font-weight:600; color:${isBad ? '#dc2626' : '#1e293b'}; font-size:0.95rem;">${val}</span>
        </div>`;

    // E. Community Reports Section
    const communityHtml = community.total_reports > 0 ? `
        <div style="background:#f8fafc; padding:1rem; border-radius:8px; margin-top:1rem; border:1px solid #e2e8f0;">
            <h4 style="margin:0 0 0.5rem 0; color:#1e293b; font-size:0.9rem;">
                <i class="fas fa-users"></i> Community Reports
            </h4>
            <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:0.5rem; font-size:0.85rem;">
                <div><strong>${community.phishing_reports || 0}</strong> Phishing</div>
                <div><strong>${community.safe_reports || 0}</strong> Safe</div>
                <div><strong>${community.total_reports || 0}</strong> Total</div>
            </div>
        </div>
    ` : '';

    // F. Domain Reputation Section
    const reputationHtml = reputation.total_scans > 0 ? `
        <div style="background:#f8fafc; padding:1rem; border-radius:8px; margin-top:1rem; border:1px solid #e2e8f0;">
            <h4 style="margin:0 0 0.5rem 0; color:#1e293b; font-size:0.9rem;">
                <i class="fas fa-history"></i> Historical Data
            </h4>
            <div style="font-size:0.85rem; line-height:1.6;">
                <div>First Seen: <strong>${reputation.first_seen || 'Unknown'}</strong></div>
                <div>Total Scans: <strong>${reputation.total_scans || 0}</strong></div>
                <div>Times Flagged: <strong>${reputation.times_flagged || 0}</strong></div>
                <div>Avg Risk: <strong>${reputation.average_risk_score || 0}</strong></div>
            </div>
        </div>
    ` : '';

    // G. API Results Section
    const apiHtml = Object.keys(api_results).length > 0 ? `
        <div style="background:#f8fafc; padding:1rem; border-radius:8px; margin-top:1rem; border:1px solid #e2e8f0;">
            <h4 style="margin:0 0 0.5rem 0; color:#1e293b; font-size:0.9rem;">
                <i class="fas fa-shield-alt"></i> Security Engines
            </h4>
            <div style="font-size:0.85rem; line-height:1.6;">
                ${api_results.google_safe_browsing ? `<div>Google Safe Browsing: <strong>${api_results.google_safe_browsing}</strong></div>` : ''}
                ${api_results.virustotal ? `<div>VirusTotal: <strong>${api_results.virustotal}</strong></div>` : ''}
            </div>
        </div>
    ` : '';

    // H. Build Complete HTML
    container.innerHTML = `
        <!-- Hero Banner -->
        <div style="background:${theme.gradient}; color:white; padding:2.5rem; border-radius:12px; margin-bottom:2rem; box-shadow:0 8px 20px rgba(0,0,0,0.15);">
            <div style="display:flex; align-items:center; gap:20px; flex-wrap:wrap;">
                <i class="fas ${theme.icon}" style="font-size:4rem; text-shadow:0 2px 4px rgba(0,0,0,0.2);"></i>
                <div style="flex:1;">
                    <div style="display: flex; align-items: center; gap: 10px; font-size:0.85rem; opacity:0.9; text-transform:uppercase; letter-spacing:1px; margin-bottom:5px;">
                        <i class="fas ${categoryIcon}"></i>
                        <span>${data.context} CONTEXT</span>
                    </div>
                    <h1 style="margin:0; font-size:2.5rem; font-weight:800; line-height:1.2; text-shadow:0 2px 4px rgba(0,0,0,0.1);">
                        ${data.risk_level} RISK
                    </h1>
                    <p style="margin:10px 0 0 0; font-size:1.15rem; opacity:0.95; max-width:600px;">
                        ${data.verdict_summary}
                    </p>
                </div>
            </div>
            
            <div style="margin-top:1.5rem; display:flex; gap:10px; flex-wrap:wrap;">
                <div style="background:rgba(255,255,255,0.25); backdrop-filter:blur(10px); padding:8px 18px; border-radius:25px; font-size:0.9rem; font-weight:600;">
                    <i class="fas fa-tachometer-alt"></i> Confidence: ${data.confidence} (${data.confidence_score}%)
                </div>
                <div style="background:rgba(255,255,255,0.25); backdrop-filter:blur(10px); padding:8px 18px; border-radius:25px; font-size:0.9rem; font-weight:600;">
                    <i class="fas fa-chart-line"></i> Risk Score: ${data.risk_score}/100
                </div>
            </div>
        </div>

        ${screenshotHtml}

        <!-- Main Content Grid -->
        <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap:2rem; margin-bottom:2rem;">
            
            <!-- Left Column: Analysis & Guidance -->
            <div>
                <div style="background:#f8fafc; padding:1.5rem; border-radius:12px; border:1px solid #e2e8f0; margin-bottom:1.5rem; box-shadow:0 2px 4px rgba(0,0,0,0.03);">
                    <h3 style="color:#1e293b; margin-bottom:1rem; font-size:1.15rem; display:flex; align-items:center; gap:8px;">
                        <i class="fas fa-microscope" style="color:${theme.color};"></i> Detection Logic
                    </h3>
                    ${reasoningHtml}
                </div>

                <div style="background:${theme.bg}; padding:1.5rem; border-radius:12px; border:2px solid ${theme.color}40; box-shadow:0 2px 4px rgba(0,0,0,0.03);">
                    <h3 style="color:${theme.color}; margin-bottom:1rem; font-size:1.15rem; display:flex; align-items:center; gap:8px;">
                        <i class="fas fa-user-shield"></i> Recommended Actions
                    </h3>
                    <ul style="list-style:none; padding:0; color:#334155; margin:0; line-height:1.8;">
                        ${guidanceHtml}
                    </ul>
                </div>
            </div>

            <!-- Right Column: Technical Details -->
            <div>
                <div style="background:white; padding:1.5rem; border-radius:12px; border:1px solid #e2e8f0; box-shadow:0 2px 6px rgba(0,0,0,0.04);">
                    
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.5rem; padding-bottom:1rem; border-bottom:2px solid #f1f5f9;">
                        <h3 style="color:#1e293b; margin:0; font-size:1.15rem;">
                            <i class="fas fa-server"></i> Technical Summary
                        </h3>
                        <div style="display:flex; gap:8px;">
                            <button onclick="downloadReport()" class="primary-btn" style="padding:8px 14px; font-size:0.85rem;" title="Download PDF Report">
                                <i class="fas fa-file-pdf"></i> PDF
                            </button>
                            <button onclick="shareReport()" class="primary-btn" style="padding:8px 14px; font-size:0.85rem; background:#2563eb;" title="Share Report">
                                <i class="fas fa-share-alt"></i>
                            </button>
                        </div>
                    </div>
                    
                    <h4 style="color:#64748b; font-size:0.85rem; text-transform:uppercase; margin:0 0 0.75rem 0; letter-spacing:0.5px;">Domain Information</h4>
                    ${createItem('Domain Age', tech.domain_age_days !== 'Unknown' ? `${tech.domain_age_days} Days` : 'Unknown', tech.domain_age_days < 30)}
                    ${createItem('Registrar', (tech.registrar || 'Unknown').substring(0, 30), false)}
                    ${createItem('Organization', (tech.category || 'Unknown').substring(0, 30), tech.category && tech.category.includes('Hidden'))}
                    ${createItem('Server IP', tech.server_ip || 'Unknown', false)}
                    
                    <h4 style="color:#64748b; font-size:0.85rem; text-transform:uppercase; margin:1.5rem 0 0.75rem 0; letter-spacing:0.5px;">SSL Certificate</h4>
                    ${createItem('Status', tech.ssl_valid ? '✓ Valid (HTTPS)' : '✗ Invalid/Missing', !tech.ssl_valid)}
                    ${createItem('Issuer', (tech.ssl_issuer || 'Unknown').substring(0, 30), false)}
                    ${tech.ssl_issued_date && tech.ssl_issued_date !== 'Unknown' ? createItem('Issued Date', tech.ssl_issued_date, false) : ''}
                    ${tech.ssl_expiry_date && tech.ssl_expiry_date !== 'Unknown' ? createItem('Expiry Date', tech.ssl_expiry_date, tech.ssl_expired) : ''}
                    ${tech.ssl_cert_age_days && tech.ssl_cert_age_days !== 'Unknown' ? createItem('Certificate Age', `${tech.ssl_cert_age_days} Days`, tech.ssl_cert_age_days < 7) : ''}
                    
                    <h4 style="color:#64748b; font-size:0.85rem; text-transform:uppercase; margin:1.5rem 0 0.75rem 0; letter-spacing:0.5px;">Threat Signals</h4>
                    ${createItem('Typosquatting', signals.typosquatting ? '⚠️ DETECTED' : '✓ Clean', signals.typosquatting)}
                    ${createItem('Blacklist Status', signals.blacklist_hit ? '⚠️ FLAGGED' : '✓ Clean', signals.blacklist_hit)}
                    ${createItem('New Domain', signals.new_domain ? '⚠️ YES' : '✓ No', signals.new_domain)}
                    ${createItem('IP-Based URL', signals.ip_usage ? '⚠️ YES' : '✓ No', signals.ip_usage)}
                    ${createItem('URL Shortener', signals.url_shortener ? '⚠️ YES' : '✓ No', signals.url_shortener)}
                    ${createItem('Homograph Attack', signals.homograph_attack ? '⚠️ YES' : '✓ No', signals.homograph_attack)}
                    ${createItem('Suspicious Keywords', signals.suspicious_keywords ? '⚠️ YES' : '✓ No', signals.suspicious_keywords)}
                    
                    ${communityHtml}
                    ${reputationHtml}
                    ${apiHtml}
                </div>
            </div>
        </div>
        
        <!-- Action Buttons -->
        <div style="margin-top: 2rem; display: flex; gap: 1rem; justify-content: center; flex-wrap:wrap;">
            <button class="primary-btn" onclick="clearInput()" style="background:#2563eb;">
                <i class="fas fa-search"></i> New Scan
            </button>
            <button class="primary-btn" onclick="submitReport('${data.url.replace(/'/g, "\\'")}', 'phishing')" style="background:#dc2626;">
                <i class="fas fa-flag"></i> Report as Phishing
            </button>
            <button class="primary-btn" onclick="submitReport('${data.url.replace(/'/g, "\\'")}', 'false_positive')" style="background:#16a34a;">
                <i class="fas fa-check"></i> Report False Positive
            </button>
        </div>

        <!-- Disclaimer Section -->
        <div style="margin-top: 2rem; padding: 1.5rem; background: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px;">
            <h4 style="color: #92400e; margin: 0 0 0.75rem 0; display: flex; align-items: center; gap: 8px;">
                <i class="fas fa-info-circle"></i> Important Notice
            </h4>
            <p style="color: #78350f; margin: 0; line-height: 1.6; font-size: 0.95rem;">
                <strong>Rule-Based Analysis:</strong> This system uses heuristic detection rules and external threat intelligence. 
                While highly accurate, it may occasionally produce false positives or miss sophisticated attacks. 
                Always verify suspicious links through official channels and trust your instincts. 
                ${data.confidence === 'LOW' ? '<strong>Low confidence</strong> indicates limited data - exercise extra caution.' : ''}
            </p>
        </div>
    `;
}

// --- 6. SCREENSHOT MODAL ---
function openScreenshotModal(imageUrl) {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.9);
        z-index: 9999;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
    `;
    
    modal.innerHTML = `
        <div style="position: relative; max-width: 90%; max-height: 90%; overflow: auto;">
            <button onclick="this.parentElement.parentElement.remove()" style="position: absolute; top: -40px; right: 0; background: white; color: black; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 1rem;">
                <i class="fas fa-times"></i> Close
            </button>
            <img src="${imageUrl}" style="width: 100%; height: auto; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.3);">
        </div>
    `;
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
    
    document.body.appendChild(modal);
}

// --- 7. COMMUNITY REPORTING ---
async function submitReport(url, reportType = 'phishing') {
    const comment = prompt(`Why are you reporting this as ${reportType}? (Optional)`);
    
    try {
        const response = await fetch('/api/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                url: url, 
                report_type: reportType,
                comment: comment || ''
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('Thank you! Your report has been submitted.', 'success');
        } else {
            showNotification('Failed to submit report. Please try again.', 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// --- 8. ENHANCED REPORT GENERATOR ---
function downloadReport() {
    if (!window.lastResults) return;
    const r = window.lastResults;
    const dateStr = new Date().toLocaleString();
    
    const dangerTxt = r.why_dangerous.map(x => `[!] ${x}`).join('\n');
    const safeTxt = r.why_safe.map(x => `[+] ${x}`).join('\n');
    const actionTxt = r.action_guidance.map(x => `-> ${x}`).join('\n');
    
    const signalsActive = Object.entries(r.detected_signals)
        .filter(([k, v]) => v === true)
        .map(([k, v]) => `  - ${k.replace(/_/g, ' ').toUpperCase()}`)
        .join('\n');

    const text = `
╔═══════════════════════════════════════════════════════════════╗
║           PHISHGUARD FORENSIC ANALYSIS REPORT                 ║
╚═══════════════════════════════════════════════════════════════╝

Date Generated:    ${dateStr}
Target URL:        ${r.url}
Analysis Context:  ${r.context}
Risk Assessment:   ${r.risk_level} RISK
Risk Score:        ${r.risk_score}/100
Confidence Level:  ${r.confidence} (${r.confidence_score}%)

═══════════════════════════════════════════════════════════════

[1] EXECUTIVE SUMMARY
───────────────────────────────────────────────────────────────
${r.verdict_summary}

[2] DETECTION REASONING
───────────────────────────────────────────────────────────────
⚠️ Warning Indicators:
${dangerTxt || "None detected."}

✓ Trust Signals:
${safeTxt || "No significant trust signals found."}

[3] TECHNICAL EVIDENCE
───────────────────────────────────────────────────────────────
Domain Information:
  • Age: ${r.technical_summary.domain_age_days} Days
  • Registrar: ${r.technical_summary.registrar}
  • Organization: ${r.technical_summary.category}
  • Server IP: ${r.technical_summary.server_ip}

SSL Certificate:
  • Status: ${r.technical_summary.ssl_valid ? "Valid" : "Invalid/Missing"}
  • Issuer: ${r.technical_summary.ssl_issuer}
  • Issued: ${r.technical_summary.ssl_issued_date || 'Unknown'}
  • Expires: ${r.technical_summary.ssl_expiry_date || 'Unknown'}
  • Age: ${r.technical_summary.ssl_cert_age_days || 'Unknown'} Days

Active Threat Signals:
${signalsActive || "  - None"}

[4] SECURITY ENGINE RESULTS
───────────────────────────────────────────────────────────────
${r.api_results?.google_safe_browsing ? `Google Safe Browsing: ${r.api_results.google_safe_browsing}` : ''}
${r.api_results?.virustotal ? `VirusTotal: ${r.api_results.virustotal}` : ''}

[5] COMMUNITY INTELLIGENCE
───────────────────────────────────────────────────────────────
${r.community_reports ? `
Total Reports: ${r.community_reports.total_reports}
Phishing Reports: ${r.community_reports.phishing_reports}
Safe Reports: ${r.community_reports.safe_reports}
` : 'No community reports available.'}

[6] RECOMMENDED ACTIONS
───────────────────────────────────────────────────────────────
${actionTxt}

═══════════════════════════════════════════════════════════════
Generated by PhishGuard Security Analysis System
Report ID: ${Date.now()}
═══════════════════════════════════════════════════════════════
    `;
    
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `PhishGuard_Report_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    showNotification('Report downloaded successfully!', 'success');
}

function shareReport() {
    if (!window.lastResults) return;
    const r = window.lastResults;
    
    const shareText = `PhishGuard Analysis Report
URL: ${r.url}
Risk Level: ${r.risk_level}
Score: ${r.risk_score}/100
${r.verdict_summary}`;

    if (navigator.share) {
        navigator.share({
            title: 'PhishGuard Report',
            text: shareText,
            url: window.location.href
        }).catch(err => console.log('Share failed:', err));
    } else {
        // Fallback: Copy to clipboard
        navigator.clipboard.writeText(shareText).then(() => {
            showNotification('Report copied to clipboard!', 'success');
        });
    }
}

// --- 9. BATCH ANALYSIS ---
function initBatchAnalysis() {
    const batchBtn = document.getElementById('analyzeBatchBtn');
    if (batchBtn) {
        batchBtn.addEventListener('click', analyzeBatch);
    }
}

async function analyzeBatch() {
    const input = document.getElementById('batchUrlInput').value.trim();
    if (!input) {
        showNotification('Please enter at least one URL.', 'error');
        return;
    }
    
    const urls = input.split('\n').filter(url => url.trim()).slice(0, 10);
    
    if (urls.length === 0) {
        showNotification('No valid URLs found.', 'error');
        return;
    }
    
    const resultsContainer = document.getElementById('batchResults');
    resultsContainer.innerHTML = '<div style="text-align:center; padding:2rem;"><i class="fas fa-spinner fa-spin" style="font-size:2rem; color:#2563eb;"></i><p>Analyzing ' + urls.length + ' URLs...</p></div>';
    resultsContainer.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/analyze-batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: urls })
        });
        
        const data = await response.json();
        
        if (data.results) {
            renderBatchResults(data.results);
        } else {
            showNotification('Batch analysis failed.', 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

function renderBatchResults(results) {
    const container = document.getElementById('batchResults');
    
    const html = results.map((r, idx) => {
        const theme = getTheme(r.risk_level || 'UNKNOWN');
        return `
            <div style="background:white; border:1px solid #e2e8f0; border-left:4px solid ${theme.color}; border-radius:8px; padding:1.5rem; margin-bottom:1rem; box-shadow:0 2px 4px rgba(0,0,0,0.05);">
                <div style="display:flex; justify-content:space-between; align-items:start; gap:1rem; flex-wrap:wrap;">
                    <div style="flex:1;">
                        <div style="font-size:0.85rem; color:#64748b; margin-bottom:0.5rem;">URL ${idx + 1}</div>
                        <div style="font-size:0.95rem; color:#2563eb; word-break:break-all; margin-bottom:0.75rem;">${r.url}</div>
                        <div style="display:flex; gap:1rem; flex-wrap:wrap;">
                            <span style="background:${theme.bg}; color:${theme.color}; padding:4px 12px; border-radius:20px; font-size:0.85rem; font-weight:600;">
                                ${r.risk_level || 'ERROR'}
                            </span>
                            <span style="color:#64748b; font-size:0.85rem;">Score: <strong>${r.risk_score || 0}</strong>/100</span>
                        </div>
                    </div>
                    ${r.thumbnail_url ? `<img src="${r.thumbnail_url}" style="width:120px; height:auto; border-radius:6px; border:1px solid #e2e8f0;">` : ''}
                </div>
                ${r.verdict_summary ? `<p style="margin:0.75rem 0 0 0; color:#64748b; font-size:0.9rem;">${r.verdict_summary}</p>` : ''}
                ${r.error ? `<p style="margin:0.75rem 0 0 0; color:#dc2626; font-size:0.9rem;"><i class="fas fa-exclamation-circle"></i> ${r.error}</p>` : ''}
            </div>
        `;
    }).join('');
    
    container.innerHTML = `
        <h3 style="color:#1e293b; margin-bottom:1.5rem;">
            <i class="fas fa-list-check"></i> Batch Analysis Results (${results.length})
        </h3>
        ${html}
    `;
}

// --- 10. STATISTICS DASHBOARD ---
async function loadStatistics() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) return;
        
        const stats = await response.json();
        
        // Update dashboard if it exists
        const statsContainer = document.getElementById('statsContainer');
        if (!statsContainer) {
            // Update individual stat cards
            const totalScans = document.getElementById('totalScans');
            const highRiskCount = document.getElementById('highRiskCount');
            const highRiskPercent = document.getElementById('highRiskPercent');
            const suspiciousCount = document.getElementById('suspiciousCount');
            const todayScans = document.getElementById('todayScans');
            
            if (totalScans) totalScans.textContent = stats.total_scans || 0;
            if (highRiskCount) highRiskCount.textContent = stats.by_risk_level?.HIGH || 0;
            if (highRiskPercent) highRiskPercent.textContent = `${stats.high_risk_percentage || 0}% of total`;
            if (suspiciousCount) suspiciousCount.textContent = stats.by_risk_level?.SUSPICIOUS || 0;
            if (todayScans) todayScans.textContent = stats.today_scans || 0;
            
            return;
        }
        
        statsContainer.innerHTML = `
            <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:1.5rem; margin-bottom:2rem;">
                <div style="background:linear-gradient(135deg, #2563eb 0%, #1e40af 100%); color:white; padding:1.5rem; border-radius:12px; box-shadow:0 4px 12px rgba(37,99,235,0.3);">
                    <div style="font-size:0.85rem; opacity:0.9; margin-bottom:0.5rem;">Total Scans</div>
                    <div style="font-size:2.5rem; font-weight:800;">${stats.total_scans || 0}</div>
                    <div style="font-size:0.75rem; opacity:0.8;">All-time analyses</div>
                </div>
                <div style="background:linear-gradient(135deg, #dc2626 0%, #991b1b 100%); color:white; padding:1.5rem; border-radius:12px; box-shadow:0 4px 12px rgba(220,38,38,0.3);">
                    <div style="font-size:0.85rem; opacity:0.9; margin-bottom:0.5rem;">High Risk</div>
                    <div style="font-size:2.5rem; font-weight:800;">${stats.by_risk_level?.HIGH || 0}</div>
                    <div style="font-size:0.75rem; opacity:0.8;">${stats.high_risk_percentage || 0}% of total</div>
                </div>
                <div style="background:linear-gradient(135deg, #d97706 0%, #92400e 100%); color:white; padding:1.5rem; border-radius:12px; box-shadow:0 4px 12px rgba(217,119,6,0.3);">
                    <div style="font-size:0.85rem; opacity:0.9; margin-bottom:0.5rem;">Suspicious</div>
                    <div style="font-size:2.5rem; font-weight:800;">${stats.by_risk_level?.SUSPICIOUS || 0}</div>
                    <div style="font-size:0.75rem; opacity:0.8;">Flagged for review</div>
                </div>
                <div style="background:linear-gradient(135deg, #16a34a 0%, #15803d 100%); color:white; padding:1.5rem; border-radius:12px; box-shadow:0 4px 12px rgba(22,163,74,0.3);">
                    <div style="font-size:0.85rem; opacity:0.9; margin-bottom:0.5rem;">Today</div>
                    <div style="font-size:2.5rem; font-weight:800;">${stats.today_scans || 0}</div>
                    <div style="font-size:0.75rem; opacity:0.8;">Scans performed</div>
                </div>
            </div>
            
            <div style="background:white; padding:1.5rem; border-radius:12px; border:1px solid #e2e8f0; box-shadow:0 2px 4px rgba(0,0,0,0.03);">
                <h3 style="margin:0 0 1rem 0; color:#1e293b;"><i class="fas fa-chart-bar"></i> Top Scanned Domains</h3>
                ${stats.top_domains && stats.top_domains.length > 0 ? stats.top_domains.map(d => `
                    <div style="display:flex; justify-content:space-between; padding:0.75rem 0; border-bottom:1px solid #f1f5f9;">
                        <span style="color:#2563eb;">${d.domain}</span>
                        <span style="font-weight:600;">${d.count} scans</span>
                    </div>
                `).join('') : '<p style="color:#64748b; text-align:center;">No data available yet.</p>'}
            </div>
        `;
        
    } catch (error) {
        console.error('Stats loading error:', error);
    }
}

// --- 11. QUIZ ENGINE ---
function loadQuizQuestions() {
    const shuffled = [...allQuizQuestions].sort(() => 0.5 - Math.random());
    quizQuestions = shuffled.slice(0, 5);
    currentQuestionIndex = 0;
    userAnswers = [];
    currentScore = 0;
    updateQuizDisplay();
}

function updateQuizDisplay() {
    const quizContainer = document.getElementById('quizContainer');
    const resultsContainer = document.getElementById('quizResults');
    if(!quizContainer) return;

    quizContainer.style.display = 'block';
    quizContainer.classList.remove('hidden');
    if(resultsContainer) resultsContainer.classList.add('hidden');
    
    if (currentQuestionIndex >= quizQuestions.length) { 
        showQuizResults(); 
        return; 
    }
    
    const question = quizQuestions[currentQuestionIndex];
    document.getElementById('questionText').textContent = question.question;
    document.getElementById('quizScore').textContent = currentQuestionIndex === 0 ? 0 : Math.round((currentScore / currentQuestionIndex) * 100);
    
    const progressBar = document.getElementById('progressBar');
    if (progressBar) progressBar.style.width = `${((currentQuestionIndex) / quizQuestions.length) * 100}%`;
    
    // FIX: Properly escape quotes and handle spacing
    const optionsHtml = question.options.map(option => {
        // Escape single quotes and create safe ID
        const safeOption = option.replace(/'/g, "\\'");
        const optionId = `opt_${Math.random().toString(36).substr(2, 9)}`;
        
        return `
            <button 
                class="option-button" 
                id="${optionId}"
                onclick="selectAnswer(\`${safeOption}\`, this)"
            >
                ${option}
            </button>
        `;
    }).join('');
    
    document.getElementById('optionsContainer').innerHTML = optionsHtml;
    document.getElementById('nextBtn').disabled = true;
}

function selectAnswer(answer, btn) {
    // Remove selected class from all buttons
    document.querySelectorAll('.option-button').forEach(b => {
        b.classList.remove('selected');
        b.style.background = '';
        b.style.borderColor = '';
    });
    
    // Add selected class to clicked button
    btn.classList.add('selected');
    btn.style.background = '#eff6ff';
    btn.style.borderColor = '#2563eb';
    
    // Store answer
    userAnswers[currentQuestionIndex] = answer;
    
    // Enable next button
    document.getElementById('nextBtn').disabled = false;
}

function nextQuestion() {
    if (userAnswers[currentQuestionIndex] === quizQuestions[currentQuestionIndex].answer) {
        currentScore++;
    }
    currentQuestionIndex++;
    updateQuizDisplay();
}

function showQuizResults() {
    document.getElementById('quizContainer').style.display = 'none';
    const resDiv = document.getElementById('quizResults');
    resDiv.classList.remove('hidden');
    resDiv.style.display = 'block';
    
    const percent = Math.round((currentScore / quizQuestions.length) * 100);
    document.getElementById('scoreDisplay').textContent = `${percent}%`;
    
    let message = '';
    if (percent >= 80) message = '🎉 Excellent! You know your phishing defense!';
    else if (percent >= 60) message = '👍 Good job! Keep learning to stay safe.';
    else message = '📚 Review the awareness tips to improve your score!';
    
    document.getElementById('scoreMessage').textContent = `You got ${currentScore} out of ${quizQuestions.length} correct. ${message}`;
}

function restartQuiz() {
    document.getElementById('quizResults').style.display = 'none';
    loadQuizQuestions();
}

// --- 12. ENHANCED HISTORY ---
async function loadHistory() {
    try {
        const response = await fetch('/api/history?limit=20');
        if (!response.ok) return;
        
        const history = await response.json();
        const tbody = document.getElementById('historyTableBody');
        const noMsg = document.getElementById('noHistoryMessage');
        
        if(!tbody) return;
        tbody.innerHTML = '';
        
        if (!history || history.length === 0) { 
            if(noMsg) noMsg.style.display = 'block'; 
            return; 
        }
        
        if(noMsg) noMsg.style.display = 'none';
        
        history.forEach(entry => {
            const row = document.createElement('tr');
            row.style.cursor = 'pointer';
            row.style.transition = 'background 0.2s';
            row.onmouseover = () => row.style.background = '#f8fafc';
            row.onmouseout = () => row.style.background = 'white';
            
            const theme = getTheme(entry.risk_level);
            const safeUrl = (entry.url || 'Unknown').substring(0, 40);
            
            row.innerHTML = `
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <div style="font-size:0.85rem; color:#64748b;">${entry.date}</div>
                </td>
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <div style="color:#2563eb; font-weight:500;">${safeUrl}...</div>
                    <div style="font-size:0.8rem; color:#64748b; margin-top:0.25rem;">${entry.context || ''}</div>
                </td>
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <span style="background:${theme.bg}; color:${theme.color}; padding:4px 12px; border-radius:20px; font-size:0.85rem; font-weight:600; white-space:nowrap;">
                        ${entry.risk_level}
                    </span>
                </td>
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <div style="display:flex; align-items:center; gap:0.5rem;">
                        <div style="flex:1; background:#f1f5f9; border-radius:10px; height:8px; overflow:hidden;">
                            <div style="background:${theme.color}; height:100%; width:${entry.risk_score}%; transition:width 0.3s;"></div>
                        </div>
                        <span style="font-weight:600; color:#1e293b; min-width:40px;">${entry.risk_score}</span>
                    </div>
                </td>
            `;
            
            row.onclick = () => viewScanDetails(entry.id || entry.history_id);
            tbody.appendChild(row);
        });
    } catch(e) { 
        console.error("History Error", e); 
    }
}

async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}`);
        if (!response.ok) return;
        
        const scan = await response.json();
        window.lastResults = scan;
        renderReport(scan);
        document.getElementById('urlResults').classList.remove('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (error) {
        showNotification('Failed to load scan details.', 'error');
    }
}

// --- 13. SEARCH FUNCTIONALITY ---
async function searchHistory() {
    const query = document.getElementById('historySearch')?.value.trim();
    if (!query) {
        loadHistory();
        return;
    }
    
    try {
        const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
        if (!response.ok) return;
        
        const results = await response.json();
        const tbody = document.getElementById('historyTableBody');
        
        if (!tbody) return;
        tbody.innerHTML = '';
        
        if (results.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:2rem; color:#64748b;">No results found.</td></tr>';
            return;
        }
        
        results.forEach(entry => {
            const row = document.createElement('tr');
            const theme = getTheme(entry.risk_level);
            
            row.innerHTML = `
                <td style="padding:1rem;">${entry.timestamp}</td>
                <td style="padding:1rem; color:#2563eb;">${entry.url.substring(0, 40)}...</td>
                <td style="padding:1rem;">
                    <span style="background:${theme.bg}; color:${theme.color}; padding:4px 12px; border-radius:20px; font-size:0.85rem; font-weight:600;">
                        ${entry.risk_level}
                    </span>
                </td>
                <td style="padding:1rem; font-weight:600;">${entry.risk_score}</td>
            `;
            
            row.onclick = () => viewScanDetails(entry.id);
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Search error:', error);
    }
}

// --- 14. TAB SWITCHING ---
function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    const targetTab = document.getElementById(tabName + '-tab');
    if (targetTab) {
        targetTab.classList.add('active');
    }
    
    // Add active class to clicked button
    event.target.closest('.tab-button').classList.add('active');
}

// --- 15. FILTER HISTORY ---
function filterHistory(level) {
    // Update button states
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    
    // Reload history with filter
    if (level === 'all') {
        loadHistory();
    } else {
        loadHistoryFiltered(level);
    }
}

async function loadHistoryFiltered(riskLevel) {
    try {
        const response = await fetch(`/api/history?risk_level=${riskLevel}&limit=20`);
        if (!response.ok) return;
        
        const history = await response.json();
        const tbody = document.getElementById('historyTableBody');
        const noMsg = document.getElementById('noHistoryMessage');
        
        if(!tbody) return;
        tbody.innerHTML = '';
        
        if (!history || history.length === 0) { 
            if(noMsg) noMsg.style.display = 'block'; 
            return; 
        }
        
        if(noMsg) noMsg.style.display = 'none';
        
        history.forEach(entry => {
            const row = document.createElement('tr');
            row.style.cursor = 'pointer';
            row.style.transition = 'background 0.2s';
            row.onmouseover = () => row.style.background = '#f8fafc';
            row.onmouseout = () => row.style.background = 'white';
            
            const theme = getTheme(entry.risk_level);
            const safeUrl = (entry.url || 'Unknown').substring(0, 40);
            
            row.innerHTML = `
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <div style="font-size:0.85rem; color:#64748b;">${entry.date}</div>
                </td>
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <div style="color:#2563eb; font-weight:500;">${safeUrl}...</div>
                    <div style="font-size:0.8rem; color:#64748b; margin-top:0.25rem;">${entry.context || ''}</div>
                </td>
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <span style="background:${theme.bg}; color:${theme.color}; padding:4px 12px; border-radius:20px; font-size:0.85rem; font-weight:600; white-space:nowrap;">
                        ${entry.risk_level}
                    </span>
                </td>
                <td style="padding:1rem; border-bottom:1px solid #e2e8f0;">
                    <div style="display:flex; align-items:center; gap:0.5rem;">
                        <div style="flex:1; background:#f1f5f9; border-radius:10px; height:8px; overflow:hidden;">
                            <div style="background:${theme.color}; height:100%; width:${entry.risk_score}%; transition:width 0.3s;"></div>
                        </div>
                        <span style="font-weight:600; color:#1e293b; min-width:40px;">${entry.risk_score}</span>
                    </div>
                </td>
            `;
            
            row.onclick = () => viewScanDetails(entry.id || entry.history_id);
            tbody.appendChild(row);
        });
    } catch(e) { 
        console.error("History Filter Error", e); 
    }
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    @keyframes bounce {
        0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
        40% { transform: translateY(-20px); }
        60% { transform: translateY(-10px); }
    }
    .option-button {
        transition: all 0.2s ease;
    }
    .option-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    .option-button.selected {
        border-color: #2563eb !important;
        background: #eff6ff !important;
        color: #2563eb !important;
        font-weight: 600;
    }
`;
document.head.appendChild(style);
