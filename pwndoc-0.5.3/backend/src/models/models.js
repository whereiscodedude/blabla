const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const networkSchema = new Schema({
    pluginId: String,
    cve: String,
    cvssScore: String,
    cvssVector: String,
    risk: String,
    host: String,
    protocol: String,
    port: String,
    name: String,
    synopsis: String,
    description: String,
    solution: String,
    seeAlso: String,
    pluginOutput: String,
    // Diğer gerekli alanlar...
});

module.exports = mongoose.model('Network', networkSchema);
