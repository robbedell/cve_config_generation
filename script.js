document.getElementById('cve-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const cveInput = document.getElementById('cve-input').value.trim();
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<p>Loading...</p>';

    try {
        const baseUrl = 'https://raw.githubusercontent.com/robbedell/cvelistV5/main/cves/';
        const cveFileUrl = `${baseUrl}${cveInput}.json`;

        const cveResponse = await fetch(cveFileUrl);
        if (!cveResponse.ok) throw new Error(`Failed to fetch CVE details for ${cveInput}: ${cveResponse.statusText}`);
        const cveData = await cveResponse.json();

        const cveId = cveData.cveMetadata.cveId;
        const description = cveData.containers.cna.descriptions[0]?.value || 'No description available';

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
        const baseUrl = 'https://raw.githubusercontent.com/robbedell/cvelistV5/main/cves/';
        const cveFiles = ['cve1.json', 'cve2.json', 'cve3.json', 'cve4.json', 'cve5.json'];

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

async function populateCveSuggestions() {
    const cveSuggestions = document.getElementById('cve-suggestions');

    try {
        const baseUrl = 'https://raw.githubusercontent.com/robbedell/cvelistV5/main/cves/';
        const response = await fetch(`${baseUrl}index.json`);
        if (!response.ok) throw new Error('Failed to fetch CVE index');
        const cveList = await response.json();

        cveSuggestions.innerHTML = '';
        cveList.forEach((cve) => {
            const option = document.createElement('option');
            option.value = cve;
            cveSuggestions.appendChild(option);
        });
    } catch (error) {
        console.error('Error populating CVE suggestions:', error);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    fetchRecentCVEs();
    populateCveSuggestions();
});
