require('dotenv').config();
const express = require('express');
const app = express();
const PORT = 3000;

// Serve static files (frontend)
app.use(express.static(__dirname));

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
