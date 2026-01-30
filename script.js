
"use strict";

// ============================================================================
// GLOBAL STATE MANAGEMENT
// ============================================================================

const PhishGuard = {
    // Application state
    state: {
        currentTab: 'scanner',
        lastAnalysis: null,
        isAnalyzing: false,
        statsData: null,
        historyData: []
    },
    
    // Quiz state
    quiz: {
        questions: [],
        currentIndex: 0,
        userAnswers: [],
        score: 0
    },
    
    // Configuration
    config: {
        API_BASE: window.location.origin,
        CACHE_DURATION: 300000, // 5 minutes
        MAX_BATCH_URLS: 10,
        HISTORY_PAGE_SIZE: 20
    }
};

// ============================================================================
// QUIZ DATABASE
// ============================================================================

const QUIZ_QUESTIONS = [
    {
        question: "What is the most common sign of a phishing email?",
        options: [
            "Urgent action required",
            "Personalized greeting",
            "Official domain",
            "No links"
        ],
        answer: "Urgent action required"
    },
    {
        question: "Which of these URLs is suspicious?",
        options: [
            "paypal.com",
            "paypal-secure-login.com",
            "paypal.co.uk",
            "help.paypal.com"
        ],
        answer: "paypal-secure-login.com"
    },
    {
        question: "What does HTTPS ensure on a website?",
        options: [
            "The site is legitimate",
            "The connection is encrypted",
            "The site has no viruses",
            "Google Verified"
        ],
        answer: "The connection is encrypted"
    },
    {
        question: "How should you verify a suspicious link?",
        options: [
            "Click it immediately",
            "Hover over it to see the URL",
            "Forward it to a friend",
            "Ignore it"
        ],
        answer: "Hover over it to see the URL"
    },
    {
        question: "What is Two-Factor Authentication (2FA)?",
        options: [
            "Using two passwords",
            "A second security layer (like SMS code)",
            "Double encryption",
            "Two firewalls"
        ],
        answer: "A second security layer (like SMS code)"
    },
    {
        question: "What is a homograph attack?",
        options: [
            "Using similar-looking characters to mimic domains",
            "Attacking home networks",
            "Grammar mistakes in emails",
            "Graph-based visualization"
        ],
        answer: "Using similar-looking characters to mimic domains"
    },
    {
        question: "Why is a newly registered domain suspicious?",
        options: [
            "It's always malicious",
            "Attackers often use new domains to avoid detection",
            "New domains are slower",
            "They can't have SSL"
        ],
        answer: "Attackers often use new domains to avoid detection"
    },
    {
        question: "What does a self-signed SSL certificate indicate?",
        options: [
            "Maximum security",
            "Not verified by a trusted authority",
            "Google approved",
            "Bank-grade encryption"
        ],
        answer: "Not verified by a trusted authority"
    },
    {
        question: "What should you do if you receive a suspicious email?",
        options: [
            "Click all links to investigate",
            "Reply asking if it's legitimate",
            "Report it as spam and delete",
            "Forward to all contacts as warning"
        ],
        answer: "Report it as spam and delete"
    },
    {
        question: "Which domain extension is commonly abused by phishers?",
        options: [
            ".com",
            ".org",
            ".tk",
            ".edu"
        ],
        answer: ".tk"
    }
];

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 PhishGuard v2.0 Initializing...');
    
    // Initialize all components
    initializeEventListeners();
    initializeQuiz();
    loadDashboardData();
    
    console.log('✅ PhishGuard Ready!');
});

/**
 * Initialize all event listeners
 */
function initializeEventListeners() {
    // URL Input - Enter key support
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                analyzeURL();
            }
        });
    }
    
    // History search - Enter key support
    const historySearch = document.getElementById('historySearch');
    if (historySearch) {
        historySearch.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                searchHistory();
            }
        });
        
        // Real-time search (debounced)
        let searchTimeout;
        historySearch.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                if (this.value.trim()) {
                    searchHistory();
                } else {
                    loadHistory();
                }
            }, 500);
        });
    }
    
    // Batch analysis
    const batchBtn = document.getElementById('analyzeBatchBtn');
    if (batchBtn) {
        batchBtn.addEventListener('click', analyzeBatch);
    }
}

/**
 * Load dashboard statistics and history
 */
async function loadDashboardData() {
    await Promise.all([
        loadStatistics(),
        loadHistory()
    ]);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    const colors = {
        error: '#dc2626',
        success: '#16a34a',
        info: '#2563eb',
        warning: '#d97706'
    };
    
    const icons = {
        error: 'fa-exclamation-circle',
        success: 'fa-check-circle',
        info: 'fa-info-circle',
        warning: 'fa-exclamation-triangle'
    };
    
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 16px 20px;
        background: ${colors[type] || colors.info};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 10000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
        word-wrap: break-word;
        display: flex;
        align-items: center;
        gap: 12px;
        font-weight: 500;
    `;
    
    notification.innerHTML = `
        <i class="fas ${icons[type] || icons.info}" style="font-size: 1.2rem;"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

/**
 * Get theme colors based on risk level
 */
function getTheme(level) {
    const themes = {
        'HIGH': {
            color: '#dc2626',
            icon: 'fa-ban',
            bg: '#fef2f2',
            gradient: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)'
        },
        'SUSPICIOUS': {
            color: '#d97706',
            icon: 'fa-exclamation-triangle',
            bg: '#fffbeb',
            gradient: 'linear-gradient(135deg, #d97706 0%, #92400e 100%)'
        },
        'LOW': {
            color: '#16a34a',
            icon: 'fa-check-circle',
            bg: '#f0fdf4',
            gradient: 'linear-gradient(135deg, #16a34a 0%, #15803d 100%)'
        },
        'UNKNOWN': {
            color: '#64748b',
            icon: 'fa-question-circle',
            bg: '#f8fafc',
            gradient: 'linear-gradient(135deg, #64748b 0%, #475569 100%)'
        }
    };
    
    return themes[level] || themes.UNKNOWN;
}

/**
 * Get category icon
 */
function getCategoryIcon(context) {
    const icons = {
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
    
    return icons[context] || 'fa-globe';
}

/**
 * Format date for display
 */
function formatDate(dateString) {
    try {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now - date;
        const minutes = Math.floor(diff / 60000);
        const hours = Math.floor(diff / 3600000);
        const days = Math.floor(diff / 86400000);
        
        if (minutes < 1) return 'Just now';
        if (minutes < 60) return `${minutes}m ago`;
        if (hours < 24) return `${hours}h ago`;
        if (days < 7) return `${days}d ago`;
        
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
        });
    } catch (e) {
        return dateString;
    }
}

/**
 * Sanitize HTML to prevent XSS
 */
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Truncate URL for display
 */
function truncateURL(url, maxLength = 50) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
}

// ============================================================================
// INPUT HANDLERS
// ============================================================================

/**
 * Clear URL input
 */
function clearInput() {
    const input = document.getElementById('urlInput');
    if (input) {
        input.value = '';
        input.focus();
        document.getElementById('urlResults')?.classList.add('hidden');
    }
}

/**
 * Paste from clipboard
 */
async function pasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        const input = document.getElementById('urlInput');
        if (input) {
            input.value = text.trim();
            showNotification('URL pasted from clipboard', 'success');
        }
    } catch (err) {
        showNotification('Failed to read clipboard. Please paste manually (Ctrl+V)', 'error');
    }
}

// ============================================================================
// MAIN ANALYSIS FUNCTION
// ============================================================================

/**
 * Analyze URL - Main entry point
 */
async function analyzeURL() {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput?.value.trim();
    
    // Validation
    if (!url) {
        showNotification('Please enter a URL to analyze', 'error');
        urlInput?.focus();
        return;
    }
    
    // Prevent duplicate analysis
    if (PhishGuard.state.isAnalyzing) {
        showNotification('Analysis already in progress...', 'warning');
        return;
    }
    
    // Show loading state
    PhishGuard.state.isAnalyzing = true;
    const spinner = document.getElementById('loadingOverlay');
    const resultsDiv = document.getElementById('urlResults');
    
    if (spinner) spinner.classList.remove('hidden');
    if (resultsDiv) resultsDiv.classList.add('hidden');
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/analyze-url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }
        
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        // Store result
        PhishGuard.state.lastAnalysis = data;
        
        // Render results
        renderAnalysisReport(data);
        
        if (resultsDiv) {
            resultsDiv.classList.remove('hidden');
            resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
        // Reload dashboard data
        loadDashboardData();
        
        // Show success message
        const cacheMsg = data.from_cache 
            ? ` (Cached result from ${data.cache_age_minutes} minutes ago)` 
            : '';
        showNotification(`Analysis complete!${cacheMsg}`, 'success');
        
    } catch (error) {
        console.error('Analysis error:', error);
        
        let errorMsg = 'Analysis failed. ';
        if (error.message.includes('Failed to fetch')) {
            errorMsg += 'Cannot connect to server. Please check if the server is running.';
        } else if (error.message.includes('timeout')) {
            errorMsg += 'Request timed out. The website may be slow or unreachable.';
        } else if (error.message.includes('NetworkError')) {
            errorMsg += 'Network error. Check your internet connection.';
        } else {
            errorMsg += error.message;
        }
        
        showNotification(errorMsg, 'error');
        
    } finally {
        PhishGuard.state.isAnalyzing = false;
        if (spinner) spinner.classList.add('hidden');
    }
}

// ============================================================================
// REPORT RENDERING
// ============================================================================

/**
 * Render complete analysis report
 */
function renderAnalysisReport(data) {
    const container = document.getElementById('urlResults');
    if (!container) return;
    
    const theme = getTheme(data.risk_level);
    const categoryIcon = getCategoryIcon(data.context);
    const tech = data.technical_summary || {};
    const signals = data.detected_signals || {};
    
    // Build HTML
    container.innerHTML = `
        ${renderHeroBanner(data, theme, categoryIcon)}
        ${renderScreenshot(data)}
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2rem; margin-bottom: 2rem;">
            ${renderDetectionLogic(data, theme)}
            ${renderTechnicalSummary(data, theme)}
        </div>
        ${renderActionButtons(data)}
        ${renderDisclaimer(data)}
    `;
}

/**
 * Render hero banner section
 */
function renderHeroBanner(data, theme, categoryIcon) {
    return `
        <div style="background: ${theme.gradient}; color: white; padding: 2.5rem; border-radius: 12px; margin-bottom: 2rem; box-shadow: 0 8px 20px rgba(0,0,0,0.15);">
            <div style="display: flex; align-items: center; gap: 20px; flex-wrap: wrap;">
                <i class="fas ${theme.icon}" style="font-size: 4rem; text-shadow: 0 2px 4px rgba(0,0,0,0.2);"></i>
                <div style="flex: 1;">
                    <div style="display: flex; align-items: center; gap: 10px; font-size: 0.85rem; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">
                        <i class="fas ${categoryIcon}"></i>
                        <span>${sanitizeHTML(data.context)}</span>
                        ${data.category ? `<span style="opacity: 0.7;">•</span><span style="text-transform: capitalize; opacity: 0.8;">${sanitizeHTML(data.category)}</span>` : ''}
                    </div>
                    <h1 style="margin: 0; font-size: 2.5rem; font-weight: 800; line-height: 1.2; text-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                        ${sanitizeHTML(data.risk_level)} RISK
                    </h1>
                    <p style="margin: 10px 0 0 0; font-size: 1.15rem; opacity: 0.95; max-width: 600px;">
                        ${sanitizeHTML(data.verdict_summary)}
                    </p>
                </div>
            </div>
            
            <div style="margin-top: 1.5rem; display: flex; gap: 10px; flex-wrap: wrap;">
                <div style="background: rgba(255,255,255,0.25); backdrop-filter: blur(10px); padding: 8px 18px; border-radius: 25px; font-size: 0.9rem; font-weight: 600;">
                    <i class="fas fa-tachometer-alt"></i> Confidence: ${sanitizeHTML(data.confidence)} (${data.confidence_score}%)
                </div>
                <div style="background: rgba(255,255,255,0.25); backdrop-filter: blur(10px); padding: 8px 18px; border-radius: 25px; font-size: 0.9rem; font-weight: 600;">
                    <i class="fas fa-chart-line"></i> Risk Score: ${data.risk_score}/100
                </div>
            </div>
        </div>
    `;
}

/**
 * Render screenshot section
 */
function renderScreenshot(data) {
    if (data.screenshot_path && data.screenshot_url) {
        return `
            <div style="margin-bottom: 2rem;">
                <h3 style="color: #1e293b; margin-bottom: 1rem; font-size: 1.1rem;">
                    <i class="fas fa-camera"></i> Website Preview
                </h3>
                <div style="border: 2px solid #e2e8f0; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 8px rgba(0,0,0,0.1); cursor: pointer;" onclick="openScreenshotModal('${data.screenshot_url}')">
                    <img src="${data.screenshot_url}" alt="Website Screenshot" style="width: 100%; height: auto; display: block;" onerror="this.parentElement.innerHTML='<div style=padding:2rem;text-align:center;color:#94a3b8><i class=fas fa-image-slash style=font-size:3rem;margin-bottom:1rem></i><p>Screenshot unavailable</p></div>'">
                </div>
                ${data.from_cache ? `<p style="color: #64748b; font-size: 0.85rem; margin-top: 0.5rem; text-align: center;"><i class="fas fa-clock"></i> Cached ${data.cache_age_minutes} minutes ago</p>` : ''}
            </div>
        `;
    } else if (data.screenshot_status) {
        return `
            <div style="background: #fef3c7; border: 1px solid #fbbf24; border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; text-align: center;">
                <i class="fas fa-info-circle" style="color: #d97706; font-size: 2rem; margin-bottom: 0.5rem;"></i>
                <p style="color: #92400e; margin: 0; font-weight: 600;">Screenshot feature is ${sanitizeHTML(data.screenshot_status)}</p>
                <p style="color: #78350f; font-size: 0.9rem; margin: 0.5rem 0 0 0;">Configure SCREENSHOT_API_KEY in environment to enable</p>
            </div>
        `;
    }
    return '';
}

/**
 * Render detection logic section
 */
function renderDetectionLogic(data, theme) {
    const reasons = [...(data.why_dangerous || []), ...(data.why_safe || [])];
    
    const reasoningHTML = reasons.length > 0 
        ? reasons.map(reason => {
            const isDanger = (data.why_dangerous || []).includes(reason);
            const icon = isDanger ? 'fa-exclamation-circle' : 'fa-check-circle';
            const color = isDanger ? '#dc2626' : '#16a34a';
            return `
                <div style="padding: 12px; background: white; border-left: 4px solid ${color}; margin-bottom: 10px; font-size: 0.95rem; border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); display: flex; gap: 10px;">
                    <i class="fas ${icon}" style="color: ${color}; margin-top: 2px; flex-shrink: 0;"></i>
                    <span>${sanitizeHTML(reason)}</span>
                </div>
            `;
        }).join('')
        : `<div style="color: #64748b; font-style: italic; padding: 1rem; text-align: center;">No specific anomalies detected</div>`;
    
    const guidanceHTML = (data.action_guidance || []).map(item => `
        <li style="margin-bottom: 8px; display: flex; align-items: start; gap: 8px;">
            <i class="fas fa-chevron-right" style="color: ${theme.color}; margin-top: 4px; flex-shrink: 0;"></i>
            <span>${sanitizeHTML(item)}</span>
        </li>
    `).join('');
    
    return `
        <div>
            <div style="background: #f8fafc; padding: 1.5rem; border-radius: 12px; border: 1px solid #e2e8f0; margin-bottom: 1.5rem; box-shadow: 0 2px 4px rgba(0,0,0,0.03);">
                <h3 style="color: #1e293b; margin-bottom: 1rem; font-size: 1.15rem; display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-microscope" style="color: ${theme.color};"></i> Detection Logic
                </h3>
                ${reasoningHTML}
            </div>
            
            <div style="background: ${theme.bg}; padding: 1.5rem; border-radius: 12px; border: 2px solid ${theme.color}40; box-shadow: 0 2px 4px rgba(0,0,0,0.03);">
                <h3 style="color: ${theme.color}; margin-bottom: 1rem; font-size: 1.15rem; display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-user-shield"></i> Recommended Actions
                </h3>
                <ul style="list-style: none; padding: 0; color: #334155; margin: 0; line-height: 1.8;">
                    ${guidanceHTML}
                </ul>
            </div>
        </div>
    `;
}

/**
 * Render technical summary section
 */
function renderTechnicalSummary(data, theme) {
    const tech = data.technical_summary || {};
    const signals = data.detected_signals || {};
    const community = data.community_reports || {};
    const reputation = data.domain_reputation || {};
    const apiResults = data.api_results || {};
    
    const createItem = (label, value, isBad = false) => `
        <div style="display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #f1f5f9;">
            <span style="color: #64748b; font-size: 0.9rem;">${sanitizeHTML(label)}</span>
            <span style="font-weight: 600; color: ${isBad ? '#dc2626' : '#1e293b'}; font-size: 0.95rem; text-align: right;">${sanitizeHTML(String(value))}</span>
        </div>
    `;
    
    return `
        <div>
            <div style="background: white; padding: 1.5rem; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 2px 6px rgba(0,0,0,0.04);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 2px solid #f1f5f9;">
                    <h3 style="color: #1e293b; margin: 0; font-size: 1.15rem;">
                        <i class="fas fa-server"></i> Technical Summary
                    </h3>
                    <div style="display: flex; gap: 8px;">
                        <button onclick="downloadReport()" class="primary-btn" style="padding: 8px 14px; font-size: 0.85rem;" title="Download Report">
                            <i class="fas fa-file-download"></i> PDF
                        </button>
                        <button onclick="shareReport()" class="primary-btn" style="padding: 8px 14px; font-size: 0.85rem; background: #2563eb;" title="Share">
                            <i class="fas fa-share-alt"></i>
                        </button>
                    </div>
                </div>
                
                <h4 style="color: #64748b; font-size: 0.85rem; text-transform: uppercase; margin: 0 0 0.75rem 0; letter-spacing: 0.5px;">Website Information</h4>
                ${data.category ? createItem('Category', data.category, false) : ''}
                ${createItem('Domain Age', tech.domain_age_days !== 'Unknown' ? `${tech.domain_age_days} Days` : 'Unknown', tech.domain_age_days < 30)}
                ${createItem('Registrar', truncateURL(tech.registrar || 'Unknown', 30), false)}
                ${createItem('Organization', truncateURL(tech.category || 'Unknown', 30), String(tech.category).includes('Hidden'))}
                ${createItem('Server IP', tech.server_ip || 'Unknown', false)}
                
                <h4 style="color: #64748b; font-size: 0.85rem; text-transform: uppercase; margin: 1.5rem 0 0.75rem 0; letter-spacing: 0.5px;">SSL Certificate</h4>
                ${createItem('Status', tech.ssl_valid ? '✓ Valid (HTTPS)' : '✗ Invalid/Missing', !tech.ssl_valid)}
                ${createItem('Issuer', truncateURL(tech.ssl_issuer || 'Unknown', 30), false)}
                ${tech.ssl_issued_date && tech.ssl_issued_date !== 'Unknown' ? createItem('Issued', tech.ssl_issued_date, false) : ''}
                ${tech.ssl_expiry_date && tech.ssl_expiry_date !== 'Unknown' ? createItem('Expires', tech.ssl_expiry_date, tech.ssl_expired) : ''}
                ${tech.ssl_cert_age_days && tech.ssl_cert_age_days !== 'Unknown' ? createItem('Cert Age', `${tech.ssl_cert_age_days} Days`, tech.ssl_cert_age_days < 7) : ''}
                
                <h4 style="color: #64748b; font-size: 0.85rem; text-transform: uppercase; margin: 1.5rem 0 0.75rem 0; letter-spacing: 0.5px;">Threat Signals</h4>
                ${createItem('Typosquatting', signals.typosquatting ? '⚠️ DETECTED' : '✓ Clean', signals.typosquatting)}
                ${createItem('Blacklist', signals.blacklist_hit ? '⚠️ FLAGGED' : '✓ Clean', signals.blacklist_hit)}
                ${createItem('New Domain', signals.new_domain ? '⚠️ YES' : '✓ No', signals.new_domain)}
                ${createItem('IP-Based', signals.ip_usage ? '⚠️ YES' : '✓ No', signals.ip_usage)}
                ${createItem('URL Shortener', signals.url_shortener ? '⚠️ YES' : '✓ No', signals.url_shortener)}
                ${createItem('Homograph', signals.homograph_attack ? '⚠️ YES' : '✓ No', signals.homograph_attack)}
                
                ${community.total_reports > 0 ? `
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 8px; margin-top: 1rem; border: 1px solid #e2e8f0;">
                        <h4 style="margin: 0 0 0.5rem 0; color: #1e293b; font-size: 0.9rem;">
                            <i class="fas fa-users"></i> Community Reports
                        </h4>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; font-size: 0.85rem;">
                            <div><strong>${community.phishing_reports || 0}</strong> Phishing</div>
                            <div><strong>${community.safe_reports || 0}</strong> Safe</div>
                            <div><strong>${community.total_reports || 0}</strong> Total</div>
                        </div>
                    </div>
                ` : ''}
                
                ${reputation.total_scans > 0 ? `
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 8px; margin-top: 1rem; border: 1px solid #e2e8f0;">
                        <h4 style="margin: 0 0 0.5rem 0; color: #1e293b; font-size: 0.9rem;">
                            <i class="fas fa-history"></i> Domain Reputation
                        </h4>
                        <div style="font-size: 0.85rem; line-height: 1.6;">
                            <div>First Seen: <strong>${sanitizeHTML(reputation.first_seen || 'Unknown')}</strong></div>
                            <div>Total Scans: <strong>${reputation.total_scans || 0}</strong></div>
                            <div>Times Flagged: <strong>${reputation.times_flagged || 0}</strong></div>
                            <div>Avg Risk: <strong>${reputation.average_risk_score || 0}</strong></div>
                        </div>
                    </div>
                ` : ''}
                
                ${Object.keys(apiResults).length > 0 ? `
                    <div style="background: #f8fafc; padding: 1rem; border-radius: 8px; margin-top: 1rem; border: 1px solid #e2e8f0;">
                        <h4 style="margin: 0 0 0.5rem 0; color: #1e293b; font-size: 0.9rem;">
                            <i class="fas fa-shield-alt"></i> Security Engines
                        </h4>
                        <div style="font-size: 0.85rem; line-height: 1.6;">
                            ${apiResults.google_safe_browsing ? `<div>Google: <strong>${sanitizeHTML(apiResults.google_safe_browsing)}</strong></div>` : ''}
                            ${apiResults.virustotal ? `<div>VirusTotal: <strong>${sanitizeHTML(apiResults.virustotal)}</strong></div>` : ''}
                        </div>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

/**
 * Render action buttons
 */
function renderActionButtons(data) {
    const safeUrl = sanitizeHTML(data.url).replace(/'/g, "\\'");
    
    return `
        <div style="margin-top: 2rem; display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
            <button class="primary-btn" onclick="clearInput()" style="background: #2563eb;">
                <i class="fas fa-search"></i> New Scan
            </button>
            <button class="primary-btn" onclick="submitReport('${safeUrl}', 'phishing')" style="background: #dc2626;">
                <i class="fas fa-flag"></i> Report Phishing
            </button>
            <button class="primary-btn" onclick="submitReport('${safeUrl}', 'false_positive')" style="background: #16a34a;">
                <i class="fas fa-check"></i> Report False Positive
            </button>
        </div>
    `;
}

/**
 * Render disclaimer
 */
function renderDisclaimer(data) {
    return `
        <div style="margin-top: 2rem; padding: 1.5rem; background: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 8px;">
            <h4 style="color: #92400e; margin: 0 0 0.75rem 0; display: flex; align-items: center; gap: 8px;">
                <i class="fas fa-info-circle"></i> Important Notice
            </h4>
            <p style="color: #78350f; margin: 0; line-height: 1.6; font-size: 0.95rem;">
                <strong>Rule-Based Analysis:</strong> This system uses heuristic detection rules and external threat intelligence. 
                While highly accurate, it may occasionally produce false positives or miss sophisticated attacks. 
                Always verify suspicious links through official channels and trust your instincts.
                ${data.confidence === 'LOW' ? '<br><br><strong>⚠️ Low confidence detected:</strong> Limited data available - exercise extra caution and verify through multiple sources.' : ''}
            </p>
        </div>
    `;
}

// ============================================================================
// SCREENSHOT MODAL
// ============================================================================

/**
 * Open screenshot in modal
 */
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
        animation: fadeIn 0.2s ease;
    `;
    
    modal.innerHTML = `
        <div style="position: relative; max-width: 95%; max-height: 95%; overflow: auto;">
            <button onclick="this.parentElement.parentElement.remove()" style="position: absolute; top: -50px; right: 0; background: white; color: black; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
                <i class="fas fa-times"></i> Close
            </button>
            <img src="${imageUrl}" style="width: 100%; height: auto; border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5);">
        </div>
    `;
    
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
    
    document.body.appendChild(modal);
}

// ============================================================================
// COMMUNITY REPORTING
// ============================================================================

/**
 * Submit community report
 */
async function submitReport(url, reportType = 'phishing') {
    const reportTypes = {
        'phishing': 'phishing site',
        'safe': 'safe site',
        'false_positive': 'false positive'
    };
    
    const comment = prompt(`Why are you reporting this as a ${reportTypes[reportType]}? (Optional)`);
    
    // User cancelled
    if (comment === null) return;
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url,
                report_type: reportType,
                comment: comment || ''
            })
        });
        
        const result = await response.json();
        
        if (result.success || response.ok) {
            showNotification('Thank you! Your report has been submitted.', 'success');
        } else {
            throw new Error(result.message || 'Failed to submit report');
        }
    } catch (error) {
        console.error('Report submission error:', error);
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// ============================================================================
// REPORT GENERATION
// ============================================================================

/**
 * Download text report
 */
function downloadReport() {
    const data = PhishGuard.state.lastAnalysis;
    if (!data) {
        showNotification('No analysis data available', 'error');
        return;
    }
    
    const dateStr = new Date().toLocaleString();
    const dangerTxt = (data.why_dangerous || []).map(x => `  • ${x}`).join('\n');
    const safeTxt = (data.why_safe || []).map(x => `  • ${x}`).join('\n');
    const actionTxt = (data.action_guidance || []).map(x => `  → ${x}`).join('\n');
    
    const signalsActive = Object.entries(data.detected_signals || {})
        .filter(([k, v]) => v === true)
        .map(([k, v]) => `  - ${k.replace(/_/g, ' ').toUpperCase()}`)
        .join('\n');
    
    const tech = data.technical_summary || {};
    
    const reportText = `
╔══════════════════════════════════════════════════════════════════╗
║              PHISHGUARD FORENSIC ANALYSIS REPORT                 ║
╚══════════════════════════════════════════════════════════════════╝

Generated:     ${dateStr}
Target URL:    ${data.url}
Category:      ${data.category || 'Unknown'}
Context:       ${data.context}
Risk Level:    ${data.risk_level} RISK
Risk Score:    ${data.risk_score}/100
Confidence:    ${data.confidence} (${data.confidence_score}%)

══════════════════════════════════════════════════════════════════

[1] EXECUTIVE SUMMARY
──────────────────────────────────────────────────────────────────
${data.verdict_summary}

[2] DETECTION REASONING
──────────────────────────────────────────────────────────────────
⚠️  Warning Indicators:
${dangerTxt || '  None detected'}

✓  Trust Signals:
${safeTxt || '  None found'}

[3] TECHNICAL EVIDENCE
──────────────────────────────────────────────────────────────────
Domain Information:
  • Age: ${tech.domain_age_days} Days
  • Registrar: ${tech.registrar}
  • Organization: ${tech.category}
  • Server IP: ${tech.server_ip}

SSL Certificate:
  • Status: ${tech.ssl_valid ? 'Valid' : 'Invalid/Missing'}
  • Issuer: ${tech.ssl_issuer}
  • Issued: ${tech.ssl_issued_date || 'Unknown'}
  • Expires: ${tech.ssl_expiry_date || 'Unknown'}
  • Age: ${tech.ssl_cert_age_days || 'Unknown'} Days

Active Threat Signals:
${signalsActive || '  None'}

[4] SECURITY ENGINE RESULTS
──────────────────────────────────────────────────────────────────
${data.api_results?.google_safe_browsing ? `Google Safe Browsing: ${data.api_results.google_safe_browsing}` : 'Google Safe Browsing: Not checked'}
${data.api_results?.virustotal ? `VirusTotal: ${data.api_results.virustotal}` : 'VirusTotal: Not checked'}

[5] COMMUNITY INTELLIGENCE
──────────────────────────────────────────────────────────────────
${data.community_reports ? `
Total Reports: ${data.community_reports.total_reports}
Phishing Reports: ${data.community_reports.phishing_reports}
Safe Reports: ${data.community_reports.safe_reports}
` : 'No community reports available'}

[6] RECOMMENDED ACTIONS
──────────────────────────────────────────────────────────────────
${actionTxt}

══════════════════════════════════════════════════════════════════
Generated by PhishGuard v2.0 Security Analysis System
Report ID: ${Date.now()}
══════════════════════════════════════════════════════════════════
    `.trim();
    
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `PhishGuard_Report_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Report downloaded successfully!', 'success');
}

/**
 * Share report
 */
function shareReport() {
    const data = PhishGuard.state.lastAnalysis;
    if (!data) {
        showNotification('No analysis data available', 'error');
        return;
    }
    
    const shareText = `PhishGuard Security Analysis Report

URL: ${data.url}
Category: ${data.category || 'Unknown'}
Risk Level: ${data.risk_level}
Risk Score: ${data.risk_score}/100
Verdict: ${data.verdict_summary}

Analyzed with PhishGuard v2.0`;

    if (navigator.share) {
        navigator.share({
            title: 'PhishGuard Security Report',
            text: shareText,
            url: window.location.href
        }).catch(err => {
            if (err.name !== 'AbortError') {
                copyToClipboard(shareText);
            }
        });
    } else {
        copyToClipboard(shareText);
    }
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Report copied to clipboard!', 'success');
        }).catch(err => {
            console.error('Clipboard error:', err);
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

/**
 * Fallback copy method
 */
function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        showNotification('Report copied to clipboard!', 'success');
    } catch (err) {
        showNotification('Failed to copy. Please try manually.', 'error');
    }
    document.body.removeChild(textarea);
}

// ============================================================================
// BATCH ANALYSIS
// ============================================================================

/**
 * Analyze multiple URLs
 */
async function analyzeBatch() {
    const textarea = document.getElementById('batchUrlInput');
    const input = textarea?.value.trim();
    
    if (!input) {
        showNotification('Please enter at least one URL', 'error');
        textarea?.focus();
        return;
    }
    
    const urls = input.split('\n')
        .map(url => url.trim())
        .filter(url => url)
        .slice(0, PhishGuard.config.MAX_BATCH_URLS);
    
    if (urls.length === 0) {
        showNotification('No valid URLs found', 'error');
        return;
    }
    
    const resultsContainer = document.getElementById('batchResults');
    if (!resultsContainer) return;
    
    resultsContainer.innerHTML = `
        <div style="text-align: center; padding: 3rem; background: #f8fafc; border-radius: 12px; border: 1px solid #e2e8f0;">
            <i class="fas fa-spinner fa-spin" style="font-size: 3rem; color: #2563eb; margin-bottom: 1rem;"></i>
            <h3 style="color: #1e293b; margin-bottom: 0.5rem;">Analyzing ${urls.length} URL${urls.length > 1 ? 's' : ''}...</h3>
            <p style="color: #64748b;">This may take a moment. Please wait.</p>
        </div>
    `;
    resultsContainer.classList.remove('hidden');
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/analyze-batch`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ urls: urls })
        });
        
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.results && Array.isArray(data.results)) {
            renderBatchResults(data.results);
            showNotification(`Batch analysis complete! ${urls.length} URLs processed.`, 'success');
        } else {
            throw new Error('Invalid response format');
        }
        
    } catch (error) {
        console.error('Batch analysis error:', error);
        showNotification(`Batch analysis failed: ${error.message}`, 'error');
        resultsContainer.classList.add('hidden');
    }
}

/**
 * Render batch analysis results
 */
function renderBatchResults(results) {
    const container = document.getElementById('batchResults');
    if (!container) return;
    
    const html = results.map((result, index) => {
        const theme = getTheme(result.risk_level || 'UNKNOWN');
        const hasError = result.error;
        
        return `
            <div style="background: white; border: 1px solid #e2e8f0; border-left: 4px solid ${theme.color}; border-radius: 12px; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 2px 4px rgba(0,0,0,0.05); transition: all 0.2s ease;" onmouseover="this.style.boxShadow='0 4px 12px rgba(0,0,0,0.1)'" onmouseout="this.style.boxShadow='0 2px 4px rgba(0,0,0,0.05)'">
                <div style="display: flex; justify-content: space-between; align-items: start; gap: 1rem; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 250px;">
                        <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 0.5rem; font-weight: 600;">
                            <i class="fas fa-link"></i> URL ${index + 1}
                        </div>
                        <div style="font-size: 0.95rem; color: #2563eb; word-break: break-all; margin-bottom: 0.75rem; font-weight: 500;">
                            ${truncateURL(sanitizeHTML(result.url), 60)}
                        </div>
                        <div style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center;">
                            <span style="background: ${theme.bg}; color: ${theme.color}; padding: 6px 14px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; white-space: nowrap;">
                                <i class="fas ${theme.icon}"></i> ${result.risk_level || 'ERROR'}
                            </span>
                            ${!hasError ? `<span style="color: #64748b; font-size: 0.85rem;">Score: <strong>${result.risk_score || 0}</strong>/100</span>` : ''}
                            ${result.category ? `<span style="color: #64748b; font-size: 0.85rem;"><i class="fas ${getCategoryIcon(result.context)}"></i> ${sanitizeHTML(result.category)}</span>` : ''}
                        </div>
                    </div>
                    ${result.thumbnail_url ? `
                        <img src="${result.thumbnail_url}" style="width: 140px; height: auto; border-radius: 8px; border: 1px solid #e2e8f0; cursor: pointer;" onclick="openScreenshotModal('${result.screenshot_url}')" onerror="this.style.display='none'">
                    ` : ''}
                </div>
                ${result.verdict_summary ? `
                    <p style="margin: 1rem 0 0 0; color: #64748b; font-size: 0.9rem; padding-top: 1rem; border-top: 1px solid #f1f5f9;">
                        ${sanitizeHTML(result.verdict_summary)}
                    </p>
                ` : ''}
                ${hasError ? `
                    <p style="margin: 1rem 0 0 0; color: #dc2626; font-size: 0.9rem; padding: 0.75rem; background: #fef2f2; border-radius: 6px;">
                        <i class="fas fa-exclamation-circle"></i> ${sanitizeHTML(result.error)}
                    </p>
                ` : ''}
            </div>
        `;
    }).join('');
    
    container.innerHTML = `
        <div style="margin-bottom: 1.5rem;">
            <h3 style="color: #1e293b; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 10px;">
                <i class="fas fa-list-check"></i> Batch Analysis Results
                <span style="font-size: 0.9rem; color: #64748b; font-weight: normal;">(${results.length} URLs)</span>
            </h3>
            <p style="color: #64748b; font-size: 0.9rem;">Click on screenshots to view full size</p>
        </div>
        ${html}
    `;
}

// ============================================================================
// STATISTICS & DASHBOARD
// ============================================================================

/**
 * Load statistics
 */
async function loadStatistics() {
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/stats`);
        
        if (!response.ok) {
            console.error('Stats API failed:', response.status);
            return;
        }
        
        const stats = await response.json();
        PhishGuard.state.statsData = stats;
        
        // Update stat cards
        updateStatCard('totalScans', stats.total_scans || 0);
        updateStatCard('highRiskCount', stats.by_risk_level?.HIGH || 0);
        updateStatCard('suspiciousCount', stats.by_risk_level?.SUSPICIOUS || 0);
        updateStatCard('todayScans', stats.today_scans || 0);
        
        // Update percentage
        const percentElem = document.getElementById('highRiskPercent');
        if (percentElem) {
            percentElem.textContent = `${stats.high_risk_percentage || 0}% of total`;
        }
        
    } catch (error) {
        console.error('Stats loading error:', error);
        // Set defaults
        updateStatCard('totalScans', 0);
        updateStatCard('highRiskCount', 0);
        updateStatCard('suspiciousCount', 0);
        updateStatCard('todayScans', 0);
    }
}

/**
 * Update stat card
 */
function updateStatCard(id, value) {
    const elem = document.getElementById(id);
    if (elem) {
        // Animate number change
        const current = parseInt(elem.textContent) || 0;
        if (current !== value) {
            animateNumber(elem, current, value, 500);
        }
    }
}

/**
 * Animate number
 */
function animateNumber(element, start, end, duration) {
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
            current = end;
            clearInterval(timer);
        }
        element.textContent = Math.round(current);
    }, 16);
}

// ============================================================================
// HISTORY MANAGEMENT
// ============================================================================

/**
 * Load scan history
 */
async function loadHistory(riskLevel = null) {
    try {
        let url = `${PhishGuard.config.API_BASE}/api/history?limit=${PhishGuard.config.HISTORY_PAGE_SIZE}`;
        if (riskLevel) {
            url += `&risk_level=${riskLevel}`;
        }
        
        const response = await fetch(url);
        
        if (!response.ok) {
            console.error('History API failed:', response.status);
            return;
        }
        
        const history = await response.json();
        PhishGuard.state.historyData = history;
        
        renderHistory(history);
        
    } catch (error) {
        console.error('History loading error:', error);
    }
}

/**
 * Render history table
 */
function renderHistory(history) {
    const tbody = document.getElementById('historyTableBody');
    const noMsg = document.getElementById('noHistoryMessage');
    
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!history || history.length === 0) {
        if (noMsg) noMsg.style.display = 'block';
        return;
    }
    
    if (noMsg) noMsg.style.display = 'none';
    
    history.forEach(entry => {
        const row = document.createElement('tr');
        row.style.cursor = 'pointer';
        row.style.transition = 'background 0.2s ease';
        
        row.addEventListener('mouseenter', () => {
            row.style.background = '#f8fafc';
        });
        
        row.addEventListener('mouseleave', () => {
            row.style.background = 'white';
        });
        
        const theme = getTheme(entry.risk_level);
        const displayUrl = truncateURL(entry.url || 'Unknown', 50);
        
        row.innerHTML = `
            <td style="padding: 1rem; border-bottom: 1px solid #e2e8f0;">
                <div style="font-size: 0.85rem; color: #64748b;">${formatDate(entry.date || entry.timestamp)}</div>
            </td>
            <td style="padding: 1rem; border-bottom: 1px solid #e2e8f0;">
                <div style="color: #2563eb; font-weight: 500; margin-bottom: 0.25rem;">${sanitizeHTML(displayUrl)}</div>
                ${entry.context ? `<div style="font-size: 0.8rem; color: #64748b;"><i class="fas ${getCategoryIcon(entry.context)}"></i> ${sanitizeHTML(entry.context)}</div>` : ''}
            </td>
            <td style="padding: 1rem; border-bottom: 1px solid #e2e8f0;">
                <span style="background: ${theme.bg}; color: ${theme.color}; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px;">
                    <i class="fas ${theme.icon}"></i> ${entry.risk_level}
                </span>
            </td>
            <td style="padding: 1rem; border-bottom: 1px solid #e2e8f0;">
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <div style="flex: 1; background: #f1f5f9; border-radius: 10px; height: 8px; overflow: hidden;">
                        <div style="background: ${theme.color}; height: 100%; width: ${entry.risk_score}%; transition: width 0.3s ease;"></div>
                    </div>
                    <span style="font-weight: 600; color: #1e293b; min-width: 40px; text-align: right;">${entry.risk_score}</span>
                </div>
            </td>
        `;
        
        row.addEventListener('click', () => {
            viewScanDetails(entry.id || entry.history_id);
        });
        
        tbody.appendChild(row);
    });
}

/**
 * View scan details
 */
async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/scan/${scanId}`);
        
        if (!response.ok) {
            throw new Error('Failed to load scan details');
        }
        
        const scan = await response.json();
        
        PhishGuard.state.lastAnalysis = scan;
        renderAnalysisReport(scan);
        
        const resultsDiv = document.getElementById('urlResults');
        if (resultsDiv) {
            resultsDiv.classList.remove('hidden');
            resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
        
        // Switch to scanner tab
        switchTab('scanner');
        
    } catch (error) {
        console.error('Scan details error:', error);
        showNotification('Failed to load scan details', 'error');
    }
}

/**
 * Search history
 */
async function searchHistory() {
    const searchInput = document.getElementById('historySearch');
    const query = searchInput?.value.trim();
    
    if (!query) {
        loadHistory();
        return;
    }
    
    try {
        const response = await fetch(`${PhishGuard.config.API_BASE}/api/search?q=${encodeURIComponent(query)}`);
        
        if (!response.ok) {
            console.error('Search API failed:', response.status);
            return;
        }
        
        const results = await response.json();
        renderHistory(results);
        
    } catch (error) {
        console.error('Search error:', error);
        showNotification('Search failed', 'error');
    }
}

/**
 * Filter history by risk level
 */
function filterHistory(level) {
    // Update filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    if (event && event.target) {
        event.target.classList.add('active');
    }
    
    // Load filtered history
    if (level === 'all') {
        loadHistory();
    } else {
        loadHistory(level);
    }
}

// ============================================================================
// TAB MANAGEMENT
// ============================================================================

/**
 * Switch between tabs
 */
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Remove active class from all tab buttons
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    const targetTab = document.getElementById(`${tabName}-tab`);
    if (targetTab) {
        targetTab.classList.add('active');
    }
    
    // Activate clicked button
    if (event && event.target) {
        const clickedBtn = event.target.closest('.tab-button');
        if (clickedBtn) {
            clickedBtn.classList.add('active');
        }
    }
    
    // Update state
    PhishGuard.state.currentTab = tabName;
}

// ============================================================================
// QUIZ SYSTEM
// ============================================================================

/**
 * Initialize quiz
 */
function initializeQuiz() {
    const quizContainer = document.getElementById('quizContainer');
    if (!quizContainer) return;
    
    loadQuizQuestions();
}

/**
 * Load and shuffle quiz questions
 */
function loadQuizQuestions() {
    // Shuffle and select 5 questions
    const shuffled = [...QUIZ_QUESTIONS].sort(() => 0.5 - Math.random());
    PhishGuard.quiz.questions = shuffled.slice(0, 5);
    PhishGuard.quiz.currentIndex = 0;
    PhishGuard.quiz.userAnswers = [];
    PhishGuard.quiz.score = 0;
    
    displayQuizQuestion();
}

/**
 * Display current quiz question
 */
function displayQuizQuestion() {
    const quizContainer = document.getElementById('quizContainer');
    const resultsContainer = document.getElementById('quizResults');
    
    if (!quizContainer) return;
    
    // Show quiz, hide results
    quizContainer.style.display = 'block';
    quizContainer.classList.remove('hidden');
    if (resultsContainer) {
        resultsContainer.classList.add('hidden');
        resultsContainer.style.display = 'none';
    }
    
    // Check if quiz is complete
    if (PhishGuard.quiz.currentIndex >= PhishGuard.quiz.questions.length) {
        showQuizResults();
        return;
    }
    
    const question = PhishGuard.quiz.questions[PhishGuard.quiz.currentIndex];
    const progress = ((PhishGuard.quiz.currentIndex) / PhishGuard.quiz.questions.length) * 100;
    
    // Update question text
    const questionText = document.getElementById('questionText');
    if (questionText) {
        questionText.textContent = question.question;
    }
    
    // Update progress bar
    const progressBar = document.getElementById('progressBar');
    if (progressBar) {
        progressBar.style.width = `${progress}%`;
    }
    
    // Update score display
    const scoreDisplay = document.getElementById('quizScore');
    if (scoreDisplay && PhishGuard.quiz.currentIndex > 0) {
        const currentScore = Math.round((PhishGuard.quiz.score / PhishGuard.quiz.currentIndex) * 100);
        scoreDisplay.textContent = currentScore;
    } else if (scoreDisplay) {
        scoreDisplay.textContent = '0';
    }
    
    // Render options
    const optionsContainer = document.getElementById('optionsContainer');
    if (optionsContainer) {
        optionsContainer.innerHTML = question.options.map((option, index) => {
            const optionId = `quiz-option-${PhishGuard.quiz.currentIndex}-${index}`;
            return `
                <button 
                    class="option-button" 
                    id="${optionId}"
                    data-answer="${sanitizeHTML(option)}"
                    onclick="selectQuizAnswer('${sanitizeHTML(option).replace(/'/g, "\\'")}', '${optionId}')"
                >
                    ${sanitizeHTML(option)}
                </button>
            `;
        }).join('');
    }
    
    // Disable next button
    const nextBtn = document.getElementById('nextBtn');
    if (nextBtn) {
        nextBtn.disabled = true;
    }
}

/**
 * Select quiz answer
 */
function selectQuizAnswer(answer, buttonId) {
    // Remove selected class from all options
    document.querySelectorAll('.option-button').forEach(btn => {
        btn.classList.remove('selected');
    });
    
    // Add selected class to clicked button
    const button = document.getElementById(buttonId);
    if (button) {
        button.classList.add('selected');
    }
    
    // Store answer
    PhishGuard.quiz.userAnswers[PhishGuard.quiz.currentIndex] = answer;
    
    // Enable next button
    const nextBtn = document.getElementById('nextBtn');
    if (nextBtn) {
        nextBtn.disabled = false;
    }
}

/**
 * Move to next question
 */
function nextQuestion() {
    const currentQuestion = PhishGuard.quiz.questions[PhishGuard.quiz.currentIndex];
    const userAnswer = PhishGuard.quiz.userAnswers[PhishGuard.quiz.currentIndex];
    
    // Check if answer is correct
    if (userAnswer === currentQuestion.answer) {
        PhishGuard.quiz.score++;
    }
    
    // Move to next question
    PhishGuard.quiz.currentIndex++;
    displayQuizQuestion();
}

/**
 * Show quiz results
 */
function showQuizResults() {
    const quizContainer = document.getElementById('quizContainer');
    const resultsContainer = document.getElementById('quizResults');
    
    if (!resultsContainer) return;
    
    // Hide quiz, show results
    if (quizContainer) {
        quizContainer.style.display = 'none';
        quizContainer.classList.add('hidden');
    }
    
    resultsContainer.classList.remove('hidden');
    resultsContainer.style.display = 'block';
    
    // Calculate percentage
    const totalQuestions = PhishGuard.quiz.questions.length;
    const percentage = Math.round((PhishGuard.quiz.score / totalQuestions) * 100);
    
    // Update score display
    const scoreDisplay = document.getElementById('scoreDisplay');
    if (scoreDisplay) {
        scoreDisplay.textContent = `${percentage}%`;
    }
    
    // Generate message
    let message = '';
    let icon = 'fa-trophy';
    
    if (percentage >= 80) {
        message = `🎉 Excellent! You got ${PhishGuard.quiz.score} out of ${totalQuestions} correct. You're a phishing detection expert!`;
        icon = 'fa-trophy';
    } else if (percentage >= 60) {
        message = `👍 Good job! You got ${PhishGuard.quiz.score} out of ${totalQuestions} correct. Keep learning to improve your security awareness.`;
        icon = 'fa-thumbs-up';
    } else {
        message = `📚 You got ${PhishGuard.quiz.score} out of ${totalQuestions} correct. Review the security tips to better protect yourself from phishing.`;
        icon = 'fa-book';
    }
    
    const messageElem = document.getElementById('scoreMessage');
    if (messageElem) {
        messageElem.textContent = message;
    }
    
    // Update icon
    const iconElem = resultsContainer.querySelector('.fa-trophy');
    if (iconElem) {
        iconElem.className = `fas ${icon}`;
    }
}

/**
 * Restart quiz
 */
function restartQuiz() {
    loadQuizQuestions();
    
    const resultsContainer = document.getElementById('quizResults');
    if (resultsContainer) {
        resultsContainer.style.display = 'none';
        resultsContainer.classList.add('hidden');
    }
}

// ============================================================================
// CSS ANIMATIONS
// ============================================================================

const animationStyles = document.createElement('style');
animationStyles.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    @keyframes bounce {
        0%, 20%, 50%, 80%, 100% {
            transform: translateY(0);
        }
        40% {
            transform: translateY(-20px);
        }
        60% {
            transform: translateY(-10px);
        }
    }
    
    .option-button {
        transition: all 0.2s ease;
    }
    
    .option-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    .option-button.selected {
        background: #eff6ff !important;
        border-color: #2563eb !important;
        color: #2563eb !important;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2);
    }
`;

document.head.appendChild(animationStyles);

// ============================================================================
// EXPORT FOR DEBUGGING
// ============================================================================

window.PhishGuard = PhishGuard;

console.log('✨ PhishGuard v2.0 - Frontend Loaded Successfully');

