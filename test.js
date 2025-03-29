// Test script for CVE fetching functionality
async function testCveFetching() {
    console.log('Starting CVE fetching test...');

    // Test 1: Check if we can access the CVE file directly
    try {
        const response = await fetch('../cvelistV5/cves/2024/0xxx/CVE-2024-0988.json');
        console.log('Test 1 - Direct file access:', response.ok ? 'PASS' : 'FAIL');
        console.log('Response status:', response.status);
    } catch (error) {
        console.error('Test 1 - Direct file access: FAIL', error);
    }

    // Test 2: Check if the CVE file exists and is readable
    try {
        const response = await fetch('http://localhost:8080/cve/cves/2024/0xxx/CVE-2024-0988.json');
        console.log('Test 2 - HTTP server access:', response.ok ? 'PASS' : 'FAIL');
        console.log('Response status:', response.status);
    } catch (error) {
        console.error('Test 2 - HTTP server access: FAIL', error);
    }

    // Test 3: Check if we can parse a CVE ID correctly
    const cveId = 'CVE-2024-0988';
    const match = cveId.match(/CVE-(\d{4})-(\d+)/);
    console.log('Test 3 - CVE ID parsing:', match ? 'PASS' : 'FAIL');
    if (match) {
        console.log('Year:', match[1]);
        console.log('Number:', match[2]);
    }

    // Test 4: Check if we can construct the correct file path
    const year = '2024';
    const number = '0988';
    const prefix = number.substring(0, 1) + 'xxx';
    const filePath = `/cve/cves/${year}/${prefix}/${cveId}.json`;
    console.log('Test 4 - File path construction:', filePath);
    console.log('Expected path:', '/cve/cves/2024/0xxx/CVE-2024-0988.json');
    console.log('Path matches:', filePath === '/cve/cves/2024/0xxx/CVE-2024-0988.json' ? 'PASS' : 'FAIL');
}

// Run the tests
testCveFetching();
