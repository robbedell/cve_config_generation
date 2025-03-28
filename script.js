document.getElementById('cve-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const cveInput = document.getElementById('cve-input').value.trim();
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<p>Loading...</p>';

    // GitHub Personal Access Token
    const GITHUB_TOKEN = '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';
    const headers = { Authorization: `token ${GITHUB_TOKEN}` };

    try {
        // Fetch the list of CVEs from your GitHub repository
        const response = await fetch('https://api.github.com/repos/robbedell/cvelistV5/contents/cves', { headers });
        if (!response.ok) throw new Error(`Failed to fetch CVEs: ${response.statusText}`);
        const data = await response.json();

        // Find the specific CVE file
        const cveFile = data.find((item) => item.name.includes(cveInput));
        if (!cveFile) throw new Error('CVE not found in the repository');

        // Fetch the CVE details
        const cveResponse = await fetch(cveFile.download_url, { headers });
        if (!cveResponse.ok) throw new Error(`Failed to fetch CVE details for ${cveInput}: ${cveResponse.statusText}`);
        const cveData = await cveResponse.json();

        // Extract relevant CVE information
        const cveId = cveData.cveMetadata.cveId;
        const description = cveData.containers.cna.descriptions[0]?.value || 'No description available';

        // Display CVE information
        resultsDiv.innerHTML = `
            <h2>Results for ${cveId}</h2>
            <p><strong>Description:</strong> ${description}</p>
            <p><strong>Applipedia Reference:</strong> <a href="https://applipedia.paloaltonetworks.com/" target="_blank">Check Applipedia</a></p>
            <p><strong>Recommended Configuration:</strong> Ensure proper firewall rules and IPS signatures are updated.</p>
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<p>Error: ${error.message}</p>`;
    }
});

// Fetch and display recent CVEs
async function fetchRecentCVEs() {
    const recentCveList = document.getElementById('recent-cve-list');
    recentCveList.innerHTML = '<li>Loading...</li>';

    // GitHub Personal Access Token
    const GITHUB_TOKEN = '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';
    const headers = { Authorization: `token ${GITHUB_TOKEN}` };

    try {
        // Fetch the list of recent CVEs from your GitHub repository
        const response = await fetch('https://api.github.com/repos/robbedell/cvelistV5/contents/cves', { headers });
        if (!response.ok) throw new Error(`Failed to fetch recent CVEs: ${response.statusText}`);
        const data = await response.json();

        // Extract and display the most recent CVEs
        recentCveList.innerHTML = '';
        const recentCves = data.slice(0, 5); // Get the 5 most recent CVEs
        for (const cve of recentCves) {
            const cveResponse = await fetch(cve.download_url, { headers });
            if (!cveResponse.ok) throw new Error(`Failed to fetch CVE details for ${cve.name}: ${cveResponse.statusText}`);
            const cveData = await cveResponse.json();

            const cveId = cveData.cveMetadata.cveId;
            const description = cveData.containers.cna.descriptions[0]?.value || 'No description available';
            const listItem = document.createElement('li');
            listItem.innerHTML = `<strong>${cveId}:</strong> ${description}`;
            recentCveList.appendChild(listItem);
        }
    } catch (error) {
        recentCveList.innerHTML = `<li>Error: ${error.message}</li>`;
    }
}

// Call fetchRecentCVEs on page load
document.addEventListener('DOMContentLoaded', fetchRecentCVEs);
