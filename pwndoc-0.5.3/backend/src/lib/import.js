// backend/src/lib/import.js

const fs = require('fs');
const parseString = require('xml2js').parseString;
const Vulnerability = require('../models/vulnerability');

const importNessusFile = (filePath) => {
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) return reject(err);

            parseString(data, (err, result) => {
                if (err) return reject(err);

                const vulnerabilities = result.NessusClientData_v2.Report[0].ReportHost.flatMap(host => {
                    return host.ReportItem.map(item => {
                        return {
                            pluginId: item.$.pluginID,
                            cve: item.cve,
                            cvssScore: item.cvss_base_score,
                            cvssVector: item.cvss_vector,
                            risk: item.risk_factor,
                            host: host.$.name,
                            protocol: item.protocol,
                            port: item.port,
                            name: item.pluginName,
                            synopsis: item.synopsis,
                            description: item.description,
                            solution: item.solution,
                            seeAlso: item.see_also,
                            pluginOutput: item.plugin_output,
                        };
                    });
                });

                Vulnerability.insertMany(vulnerabilities)
                    .then(() => resolve(vulnerabilities))
                    .catch(err => reject(err));
            });
        });
    });
};

module.exports = {
    importNessusFile
};
