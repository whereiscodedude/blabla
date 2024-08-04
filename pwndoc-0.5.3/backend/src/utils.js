const xml2js = require('xml2js');

const parseXmlNessus = (data) => {
    return new Promise((resolve, reject) => {
        const parser = new xml2js.Parser();

        parser.parseString(data, (err, result) => {
            if (err) {
                console.error('XML Parsing Error:', err);
                return reject('XML parsing failed');
            }

            try {
                const hosts = result.NessusClientData_v2.Report[0].ReportHost;
                if (!hosts || hosts.length === 0) throw 'Parsing Error: No "ReportHost" element found';

                const hostsRes = hosts.map(host => {
                    const properties = host.HostProperties[0].tag.reduce((acc, tag) => {
                        acc[tag.$.name] = tag._;
                        return acc;
                    }, {});

                    const ports = host.ReportItem.map(item => ({
                        port: item.$.port,
                        protocol: item.$.protocol,
                        service: item.$.svc_name,
                        severity: item.$.severity,
                    }));

                    return {
                        properties,
                        ports,
                    };
                });

                resolve(hostsRes);
            } catch (error) {
                console.error('Processing Error:', error);
                reject('Data processing failed');
            }
        });
    });
};

module.exports = { parseXmlNessus };
