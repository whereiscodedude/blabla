const express = require('express');
const fs = require('fs');
const https = require('https');
const socketIo = require('socket.io');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const app = express();
const server = https.createServer({
  key: fs.readFileSync(__dirname + '/../ssl/server.key'),
  cert: fs.readFileSync(__dirname + '/../ssl/server.cert')
}, app);
const io = socketIo(server, {
  cors: {
    origin: "*"
  }
});

app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ limit: '10mb', extended: false }));
app.use(cookieParser());

mongoose.connect('mongodb://mongo-pwndoc:27017/pwndoc', { useNewUrlParser: true, useUnifiedTopology: true });

// Modeller
const NessusReport = mongoose.model('NessusReport', new mongoose.Schema({
  properties: Object,
  ports: Array,
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
}));

require('./models/user');
require('./models/audit');
require('./models/client');
require('./models/company');
require('./models/template');
require('./models/vulnerability');
require('./models/vulnerability-update');
require('./models/language');
require('./models/audit-type');
require('./models/vulnerability-type');
require('./models/vulnerability-category');
require('./models/custom-section');
require('./models/custom-field');
require('./models/image');
require('./models/settings');

require('./routes/user')(app);
require('./routes/audit')(app, io);
require('./routes/client')(app);
require('./routes/company')(app);
require('./routes/vulnerability')(app);
require('./routes/template')(app);
require('./routes/data')(app);
require('./routes/image')(app);
require('./routes/settings')(app);
require('./routes/import')(app);

// Nessus JSON verisini parse edip veritabanına kaydeden route
app.post('/api/network/nessus', async (req, res) => {
  const { data } = req.body;

  console.log('Received data for parsing:', data);  // Log received data

  try {
    const hostsRes = data.map(host => {
      const properties = host.properties;

      const ports = host.services.map(service => ({
        port: service.port,
        protocol: service.protocol,
        service: service.name,
        severity: service.severity,
        pluginId: service.pluginId,
        pluginName: service.pluginName,
        cve: service.cve,
        cvssScore: service.cvssScore,
        cvssVector: service.cvssVector,
        synopsis: service.synopsis,
        description: service.description,
        solution: service.solution,
        seeAlso: service.seeAlso,
        pluginOutput: service.pluginOutput
      }));

      return {
        properties,
        ports
      };
    });

    console.log('Transformed hosts:', hostsRes);  // Log transformed hosts

    await NessusReport.insertMany(hostsRes);

    res.status(200).send({ message: `Successfully imported ${hostsRes.length} hosts`, data: hostsRes });
  } catch (error) {
    console.error('Error processing Nessus data:', error);
    res.status(500).send({ message: 'Error processing Nessus data', error: error });
  }
});

// Veritabanındaki Nessus verilerini çeken route
app.get('/api/network/nessus', async (req, res) => {
  try {
    const reports = await NessusReport.find();
    res.status(200).send(reports);
  } catch (error) {
    console.error('Error fetching Nessus data:', error);
    res.status(500).send({ message: 'Error fetching Nessus data', error: error });
  }
});

// Nessus bulgularını veritabanına kaydeden route
app.post('/api/network/nessus/vulnerabilities', async (req, res) => {
  const vulnerabilities = req.body.data;
  
  console.log('Received vulnerabilities for saving:', vulnerabilities);  // Log received vulnerabilities

  try {
    await NessusReport.insertMany(vulnerabilities);
    res.status(200).send({ message: 'Successfully added all findings', data: vulnerabilities });
  } catch (error) {
    console.error('Error adding findings:', error);
    res.status(500).send({ message: 'Error adding findings', error: error });
  }
});

server.listen(4242, () => {
  console.log('Server is running on port 4242');
});

module.exports = app;
