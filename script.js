document.getElementById('cve-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const cveInput = document.getElementById('cve-input').value.trim();
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<p>Loading...</p>';

    try {
        // Fetch CVE details from NVD API
        const response = await fetch(`https://services.nvd.nist.gov/rest/json/cve/1.0/${cveInput}`);
        if (!response.ok) throw new Error('CVE not found');
        const data = await response.json();

        // Extract relevant CVE information
        const cveDescription = data.result.CVE_Items[0].cve.description.description_data[0].value;

        // Display CVE information
        resultsDiv.innerHTML = `
            <h2>Results for ${cveInput}</h2>
            <p><strong>Description:</strong> ${cveDescription}</p>
            <p><strong>Applipedia Reference:</strong> <a href="https://applipedia.paloaltonetworks.com/" target="_blank">Check Applipedia</a></p>
            <p><strong>Recommended Configuration:</strong> Ensure proper firewall rules and IPS signatures are updated.</p>
        `;
    } catch (error) {
        resultsDiv.innerHTML = `<p>Error: ${error.message}</p>`;
    }
});
