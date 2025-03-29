// CVE data handling
let recentCves = [];

// Function to parse CVE ID and get GitHub raw content URL
function getCveGitHubUrl(cveId) {
    const match = cveId.match(/CVE-(\d{4})-(\d+)/);
    if (!match) return null;

    const year = match[1];
    const number = match[2];
    const prefix = number.substring(0, 1) + 'xxx';

    return `https://raw.githubusercontent.com/robbedell/cvelistV5/main/cves/${year}/${prefix}/${cveId}.json`;
}

// Function to fetch CVE data
async function fetchCveData(cveId) {
    const fileUrl = getCveGitHubUrl(cveId);
    if (!fileUrl) {
        throw new Error('Invalid CVE ID format');
    }

    console.log('Attempting to fetch CVE from:', fileUrl);
    try {
        const response = await fetch(fileUrl);
        console.log('Response status:', response.status);
        if (!response.ok) {
            throw new Error(`CVE not found (Status: ${response.status})`);
        }
        const data = await response.json();
        console.log('Successfully fetched CVE data');
        return data;
    } catch (error) {
        console.error('Error fetching CVE:', error);
        throw error;
    }
}

// Function to display CVE information
function displayCveInfo(cveData) {
    const resultsDiv = document.getElementById('results');
    const cna = cveData.containers.cna;

    const html = `
        <div class="cve-info">
            <h2>${cveData.cveMetadata.cveId}</h2>
            <div class="metadata">
                <p><strong>Published:</strong> ${new Date(cveData.cveMetadata.datePublished).toLocaleDateString()}</p>
                <p><strong>Last Updated:</strong> ${new Date(cveData.cveMetadata.dateUpdated).toLocaleDateString()}</p>
                <p><strong>Status:</strong> ${cveData.cveMetadata.state}</p>
            </div>
            <div class="description">
                <h3>Description</h3>
                <p>${cna.descriptions[0].value}</p>
            </div>
            <div class="affected">
                <h3>Affected Products</h3>
                <ul>
                    ${cna.affected.map(aff => `
                        <li>
                            <strong>${aff.vendor} - ${aff.product}</strong>
                            <ul>
                                ${aff.versions.map(ver => `
                                    <li>Version ${ver.version} (${ver.status})</li>
                                `).join('')}
                            </ul>
                        </li>
                    `).join('')}
                </ul>
            </div>
            <div class="metrics">
                <h3>CVSS Metrics</h3>
                ${cna.metrics.map(metric => {
                    const version = Object.keys(metric)[0];
                    const data = metric[version];
                    return `
                        <div class="metric">
                            <h4>CVSS ${data.version}</h4>
                            <p><strong>Score:</strong> ${data.baseScore}</p>
                            <p><strong>Vector:</strong> ${data.vectorString}</p>
                            <p><strong>Severity:</strong> ${data.baseSeverity}</p>
                        </div>
                    `;
                }).join('')}
            </div>
            <div class="references">
                <h3>References</h3>
                <ul>
                    ${cna.references.map(ref => `
                        <li><a href="${ref.url}" target="_blank">${ref.url}</a></li>
                    `).join('')}
                </ul>
            </div>
        </div>
    `;

    resultsDiv.innerHTML = html;

    // Add to recent CVEs if not already present
    if (!recentCves.includes(cveData.cveMetadata.cveId)) {
        recentCves.unshift(cveData.cveMetadata.cveId);
        if (recentCves.length > 10) {
            recentCves.pop();
        }
        updateRecentCvesList();
    }
}

// Function to update recent CVEs list
function updateRecentCvesList() {
    const recentList = document.getElementById('recent-cve-list');
    recentList.innerHTML = recentCves.map(cveId => `
        <li><a href="#" class="recent-cve" data-cve="${cveId}">${cveId}</a></li>
    `).join('');

    // Add click handlers to recent CVE links
    document.querySelectorAll('.recent-cve').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const cveId = e.target.dataset.cve;
            document.getElementById('cve-input').value = cveId;
            handleCveSearch(cveId);
        });
    });
}

// Function to handle CVE search
async function handleCveSearch(cveId) {
    try {
        const cveData = await fetchCveData(cveId);
        displayCveInfo(cveData);
    } catch (error) {
        const resultsDiv = document.getElementById('results');
        resultsDiv.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('cve-form');
    const input = document.getElementById('cve-input');

    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const cveId = input.value.trim();
        if (cveId) {
            handleCveSearch(cveId);
        }
    });
});
