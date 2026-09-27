const crypto = require('crypto');
const fs = require('fs');

// Legacy Express Route Handler
function handleUserUpload(req, res) {
    const rawData = req.body.payload;

    // VULNERABILITY: createCipher is deprecated and uses weak key derivation
    const cipher = crypto.createCipher('aes-128-cbc', 'legacy-app-secret');
    let encrypted = cipher.update(rawData, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    fs.writeFile('./temp_vault.bin', encrypted, function(err) {
        if (err) {
            res.status(500).send("Disk error");
        } else {
            fs.readFile('./temp_vault.bin', function(readErr, data) {
                if (readErr) {
                    res.status(500).send("Read error");
                } else {
                    res.json({ status: "success", bytes: data.length });
                }
            });
        }
    });
}
module.exports = { handleUserUpload };
