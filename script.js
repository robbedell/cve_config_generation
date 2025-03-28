document.getElementById('cve-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const cveInput = document.getElementById('cve-input').value.trim();
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<p>Loading...</p>';

    try {
        // Use the raw content URL to fetch the list of CVEs
        const baseUrl = 'https://raw.githubusercontent.com/robbedell/cvelistV5/main/cves/';
        const cveFileUrl = `${baseUrl}${cveInput}.json`;

        // Fetch the CVE details
        const cveResponse = await fetch(cveFileUrl);
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

async function fetchRecentCVEs() {
    const recentCveList = document.getElementById('recent-cve-list');
    recentCveList.innerHTML = '<li>Loading...</li>';

    try {
        // Use the raw content URL to fetch the list of recent CVEs
        const baseUrl = 'https://raw.githubusercontent.com/robbedell/cvelistV5/main/cves/';
        const cveFiles = ['cve1.json', 'cve2.json', 'cve3.json', 'cve4.json', 'cve5.json']; // Example file names

        recentCveList.innerHTML = '';
        for (const fileName of cveFiles) {
            const cveResponse = await fetch(`${baseUrl}${fileName}`);
            if (!cveResponse.ok) throw new Error(`Failed to fetch CVE details for ${fileName}: ${cveResponse.statusText}`);
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
