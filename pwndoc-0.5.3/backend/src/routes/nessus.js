const express = require('express');
const router = express.Router();
const Network = require('../models/network'); // Network modelini ekleyin

// Nessus verilerini veritabanına kaydetmek için endpoint
router.post('/network/nessus', (req, res) => {
    const data = req.body.data;

    Network.insertMany(data)
        .then(result => {
            res.status(200).send({ success: true, data: result });
        })
        .catch(err => {
            res.status(500).send({ success: false, message: 'Failed to save Nessus data', error: err });
        });
});

// Veritabanından Nessus verilerini çekmek için endpoint
router.get('/network/nessus', (req, res) => {
    Network.find({})
        .then(data => {
            res.status(200).send({ success: true, data });
        })
        .catch(err => {
            res.status(500).send({ success: false, message: 'Failed to retrieve Nessus data', error: err });
        });
});

module.exports = router;
