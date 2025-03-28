require('dotenv').config();
const express = require('express');
const app = express();
const PORT = 3000;

// Endpoint to serve the GitHub token
app.get('/get-github-token', (req, res) => {
    res.json({ token: process.env.GITHUB_TOKEN });
});

// Serve static files (frontend)
app.use(express.static(__dirname));

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
