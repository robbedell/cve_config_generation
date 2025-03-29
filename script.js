// State management
let currentCVE = null;
let recentCVEs = [];
let cveCache = new Map();

// Repository Configuration
const CVE_REPO_BASE_URL = 'https://raw.githubusercontent.com/RobBedell/cvelistV5/main/cves';

// DOM Elements
const cveForm = document.getElementById('cve-form');
const cveInput = document.getElementById('cve-input');
const resultsDiv = document.getElementById('results');
const recentCveList = document.getElementById('recent-cve-list');
const tabButtons = document.querySelectorAll('.tab-button');
const configPanels = document.querySelectorAll('.config-panel');
const copyButtons = document.querySelectorAll('.copy-button');

// Event Listeners
cveForm.addEventListener('submit', handleSearch);
tabButtons.forEach(button => button.addEventListener('click', handleTabChange));
copyButtons.forEach(button => button.addEventListener('click', handleCopy));

// Load recent CVEs from localStorage
loadRecentCVEs();

function getCveGitHubUrl(cveId) {
    const match = cveId.match(/CVE-(\d{4})-(\d+)/);
    if (!match) return null;

    const year = match[1];
    const number = match[2];
    const prefix = number.substring(0, 1) + 'xxx';

    return `${CVE_REPO_BASE_URL}/${year}/${prefix}/${cveId}.json`;
}

async function fetchCVEById(cveId) {
    try {
        if (cveCache.has(cveId)) {
            return cveCache.get(cveId);
        }

        const fileUrl = getCveGitHubUrl(cveId);
        if (!fileUrl) {
            throw new Error('Invalid CVE ID format');
        }

        const response = await fetch(fileUrl);
        if (!response.ok) {
            throw new Error(`CVE not found: ${response.status}`);
        }

        const data = await response.json();
        const cna = data.containers.cna;

        const description = cna.descriptions?.find(d => d.lang === 'en')?.value ||
                          cna.descriptions?.[0]?.value ||
                          'No description available';

        // Determine severity from problem types
        let severity = 'UNKNOWN';
        if (cna.problemTypes) {
            const hasCritical = cna.problemTypes.some(pt =>
                pt.descriptions.some(d => d.description.includes('Critical'))
            );
            const hasHigh = cna.problemTypes.some(pt =>
                pt.descriptions.some(d => d.description.includes('High'))
            );

            if (hasCritical) severity = 'CRITICAL';
            else if (hasHigh) severity = 'HIGH';
            else severity = 'MEDIUM';
        }

        const result = {
            id: cveId,
            title: cna.title || 'No title available',
            description: description,
            severity: severity,
            references: cna.references?.map(ref => ref.url) || [],
            affected: cna.affected?.map(item => ({
                product: item.product,
                vendor: item.vendor,
                status: item.defaultStatus,
                versions: item.versions
            })) || [],
            metrics: data.containers.metrics || [],
            problemTypes: cna.problemTypes || []
        };

        cveCache.set(cveId, result);
        return result;
    } catch (error) {
        console.error('Error in fetchCVEById:', error);
        throw error;
    }
}

async function handleSearch(e) {
    e.preventDefault();
    showLoading();

    try {
        const cveId = cveInput.value.trim();
        if (!cveId) {
            showError('Please enter a CVE ID');
            return;
        }

        const cveData = await fetchCVEById(cveId);
        displayResults(cveData);
    } catch (error) {
        console.error('Search error:', error);
        showError('Failed to fetch CVE data. Please try again.');
    } finally {
        hideLoading();
    }
}

function displayResults(cveData) {
    if (!cveData) {
        resultsDiv.innerHTML = `
            <div class="error-message">
                <p>No CVE data found. Please try a different search.</p>
            </div>
        `;
        return;
    }

    const { id, title, description, severity, affected, references, metrics } = cveData;
    const cvssScore = metrics?.[0]?.cvssV3_1?.baseScore || 'N/A';

    const resultsHTML = `
        <div class="cve-details">
            <div class="cve-header">
                <h2>${id}</h2>
                <span class="severity-badge ${severity.toLowerCase()}">${severity}</span>
                <span class="cvss-score">CVSS Score: ${cvssScore}</span>
            </div>

            <div class="cve-title">
                <h3>${title}</h3>
            </div>

            <div class="cve-description">
                <h4>Description</h4>
                <p>${description}</p>
            </div>

            <div class="cve-affected">
                <h4>Affected Products</h4>
                <ul>
                    ${affected.map(item => `
                        <li>
                            <strong>${item.vendor}</strong> - ${item.product}
                            ${item.versions ? `
                                <ul>
                                    ${item.versions.map(v => `
                                        <li>Version: ${v.version} (Status: ${v.status})</li>
                                    `).join('')}
                                </ul>
                            ` : ''}
                        </li>
                    `).join('')}
                </ul>
            </div>

            ${references.length > 0 ? `
                <div class="cve-references">
                    <h4>References</h4>
                    <ul>
                        ${references.map(ref => `
                            <li><a href="${ref}" target="_blank">${ref}</a></li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}

            ${metrics.length > 0 ? `
                <div class="cve-metrics">
                    <h4>Metrics</h4>
                    <ul>
                        ${metrics.map(metric => `
                            <li>
                                <strong>${metric.type}</strong>
                                ${metric.cvssV3_1 ? `
                                    <ul>
                                        <li>Base Score: ${metric.cvssV3_1.baseScore}</li>
                                        <li>Vector: ${metric.cvssV3_1.vectorString}</li>
                                    </ul>
                                ` : ''}
                            </li>
                        `).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;

    resultsDiv.innerHTML = resultsHTML;
    generateConfigurations(cveData);
    addToRecentCVEs(id);
}

function generateConfigurations(cveData) {
    if (!cveData) return;

    const paloAltoConfig = generatePaloAltoConfig(cveData);
    const ciscoConfig = generateCiscoConfig(cveData);
    const fortinetConfig = generateFortinetConfig(cveData);

    document.querySelector('#palo-alto-config .config-code').textContent = paloAltoConfig;
    document.querySelector('#cisco-config .config-code').textContent = ciscoConfig;
    document.querySelector('#fortinet-config .config-code').textContent = fortinetConfig;
}

function generatePaloAltoConfig(cveData) {
    const { id, description, severity, affected, references } = cveData;
    const severityMap = {
        'CRITICAL': 'critical',
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
        'UNKNOWN': 'medium'
    };

    return [
        `# Palo Alto Networks Security Configuration for ${id}`,
        `# Generated based on CVE information`,
        '',
        `# Security Profile Configuration`,
        `set security profiles vulnerability-protection profile "${id}_profile"`,
        `set security profiles vulnerability-protection profile "${id}_profile" rules "${id}_rule" action "${severityMap[severity] || 'medium'}"`,
        '',
        `# Threat Prevention Configuration`,
        `set security profiles threat-prevention profile "${id}_threat_profile"`,
        `set security profiles threat-prevention profile "${id}_threat_profile" rules "${id}_threat_rule" action "${severityMap[severity] || 'medium'}"`,
        '',
        `# Affected Products`,
        ...affected.map(item => `# ${item.vendor} - ${item.product}`),
        '',
        `# References`,
        ...references.map(ref => `# ${ref}`),
        '',
        `# Description`,
        `# ${description.replace(/\n/g, '\n# ')}`
    ].join('\n');
}

function generateCiscoConfig(cveData) {
    const { id, description, severity, affected, references } = cveData;
    const severityMap = {
        'CRITICAL': 'critical',
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
        'UNKNOWN': 'medium'
    };

    return [
        `! Cisco Security Configuration for ${id}`,
        `! Generated based on CVE information`,
        '',
        `! Object Group for Affected Products`,
        `object-group network ${id}_affected_products`,
        ...affected.map(item => ` network-object host ${item.product}`),
        '',
        `! Access Control List`,
        `ip access-list extended ${id}_acl`,
        ` permit ip any ${id}_affected_products`,
        '',
        `! Class Map for Traffic Classification`,
        `class-map match-all ${id}_class`,
        ` match access-group name ${id}_acl`,
        '',
        `! Policy Map for Traffic Handling`,
        `policy-map ${id}_policy`,
        ` class ${id}_class`,
        `  set dscp ${severityMap[severity] || 'medium'}`,
        '',
        `! Service Policy Application`,
        `service-policy ${id}_policy global`,
        '',
        `! References`,
        ...references.map(ref => `! ${ref}`),
        '',
        `! Description`,
        `! ${description.replace(/\n/g, '\n! ')}`
    ].join('\n');
}

function generateFortinetConfig(cveData) {
    const { id, description, severity, affected, references } = cveData;
    const severityMap = {
        'CRITICAL': 'critical',
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
        'UNKNOWN': 'medium'
    };

    return [
        `# Fortinet Security Configuration for ${id}`,
        `# Generated based on CVE information`,
        '',
        `# Vulnerability Protection Profile`,
        `config ips global`,
        `    set signature-auto-update enable`,
        `    set signature-update-interval 1`,
        `end`,
        '',
        `config ips sensor`,
        `    edit "${id}_sensor"`,
        `        set comment "${description}"`,
        `        config entries`,
        `            edit 0`,
        `                set severity ${severityMap[severity] || 'medium'}`,
        `                set status enable`,
        `                set action block`,
        `            next`,
        `        end`,
        `    next`,
        `end`,
        '',
        `# Affected Products`,
        ...affected.map(item => `# ${item.vendor} - ${item.product}`),
        '',
        `# References`,
        ...references.map(ref => `# ${ref}`),
        '',
        `# Description`,
        `# ${description.replace(/\n/g, '\n# ')}`
    ].join('\n');
}

function handleTabChange(e) {
    const targetTab = e.target.dataset.tab;

    tabButtons.forEach(button => button.classList.remove('active'));
    e.target.classList.add('active');

    configPanels.forEach(panel => {
        panel.classList.remove('active');
        if (panel.id === `${targetTab}-config`) {
            panel.classList.add('active');
        }
    });
}

function handleCopy(e) {
    const configCode = e.target.previousElementSibling.textContent;
    navigator.clipboard.writeText(configCode).then(() => {
        showSuccess('Configuration copied to clipboard!');
    }).catch(() => {
        showError('Failed to copy configuration');
    });
}

function loadRecentCVEs() {
    const saved = localStorage.getItem('recentCVEs');
    if (saved) {
        recentCVEs = JSON.parse(saved);
        updateRecentCVEsList();
    }
}

function addToRecentCVEs(cveId) {
    if (!recentCVEs.includes(cveId)) {
        recentCVEs.unshift(cveId);
        if (recentCVEs.length > 10) {
            recentCVEs.pop();
        }
        localStorage.setItem('recentCVEs', JSON.stringify(recentCVEs));
        updateRecentCVEsList();
    }
}

function updateRecentCVEsList() {
    recentCveList.innerHTML = recentCVEs
        .map(cveId => `
            <li>
                <a href="#" class="recent-cve" data-cve="${cveId}">${cveId}</a>
            </li>
        `).join('');

    document.querySelectorAll('.recent-cve').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            cveInput.value = e.target.dataset.cve;
            cveForm.dispatchEvent(new Event('submit'));
        });
    });
}

// UI Helper Functions
function showLoading() {
    resultsDiv.innerHTML = '<div class="loading">Loading...</div>';
}

function hideLoading() {
    // Loading state is cleared when results are displayed
}

function showError(message) {
    resultsDiv.innerHTML = `
        <div class="error-message">
            <p>${message}</p>
        </div>
    `;
}

function showSuccess(message) {
    const notification = document.createElement('div');
    notification.className = 'success';
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.remove();
    }, 3000);
}
