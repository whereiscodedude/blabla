// backend/src/routes/import.js

module.exports = function(app) {
    const express = require('express');
    const router = express.Router();
    const { importNessusFile } = require('../lib/import');

    router.post('/import/nessus', (req, res) => {
        if (!req.files || Object.keys(req.files).length === 0) {
            return res.status(400).send({ success: false, message: 'No files were uploaded.' });
        }

        const file = req.files.file;
        const filePath = `/tmp/${file.name}`;

        file.mv(filePath, function(err) {
            if (err) {
                return res.status(500).send({ success: false, message: 'File upload failed.' });
            }

            importNessusFile(filePath)
                .then(data => res.status(200).send({ success: true, data }))
                .catch(err => res.status(500).send({ success: false, message: 'Import failed', error: err }));
        });
    });

    app.use('/api', router);
};
