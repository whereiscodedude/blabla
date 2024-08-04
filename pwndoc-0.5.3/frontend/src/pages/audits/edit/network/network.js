import { Notify } from 'quasar';
import axios from 'axios';

export default {
  data() {
    return {
      breadcrumbItems: [
        { label: this.$t('breadcrumb.home'), to: '/' },
        { label: this.$t('breadcrumb.audit'), to: '/audits' },
        { label: this.$route.params.auditId }
      ],
      targetsOptions: [],
      dtHostHeaders: [
        { name: 'ip', label: 'IP Address', field: 'ip', align: 'left' },
        { name: 'os', label: 'Operating System', field: 'os', align: 'left' },
        { name: 'hostname', label: 'Hostname', field: 'hostname', align: 'left' },
        { name: 'services', label: 'Services', field: 'services', align: 'left' }
      ],
      hostPagination: {
        page: 1,
        rowsPerPage: 10
      }
    };
  },
  methods: {
    triggerFileInput(type) {
      if (type === 'nmap') {
        this.$refs.nmapFileInput.click();
      } else if (type === 'nessus') {
        this.$refs.nessusFileInput.click();
      }
    },
    handleFileChange(type, event) {
      console.log("handleFileChange called with type:", type);  // Debugging log
      const file = event.target.files[0];
      if (!file) {
        console.error("No file selected");  // Error log
        return;
      }
      const reader = new FileReader();
      reader.onloadend = (e) => {
        console.log("FileReader onloadend called");  // Debugging log
        if (type === 'nmap') {
          this.parseXmlNmap(e.target.result);
        } else if (type === 'nessus') {
          this.parseXmlNessus(e.target.result);
        }
      };
      reader.readAsText(file);
    },
    parseXmlNmap(data) {
      console.log('Starting Nmap parser');
      var parser = new DOMParser();
      var xmlData = parser.parseFromString(data, "application/xml");
      try {
        var hosts = xmlData.getElementsByTagName("host");
        if (hosts.length == 0) throw ("Parsing Error: No 'host' element");
        var hostsRes = [];
        for (var i = 0; i < hosts.length; i++) {
          if (hosts[i].getElementsByTagName("status")[0].getAttribute("state") === "up") {
            var host = {};
            var addrElmt = hosts[i].getElementsByTagName("address")[0];
            if (typeof (addrElmt) == "undefined") throw ("Parsing Error: No 'address' element in host number " + i);
            host["ip"] = addrElmt.getAttribute("addr");

            var osElmt = hosts[i].getElementsByTagName("os")[0];
            if (typeof (osElmt) !== "undefined") {
              var osClassElmt = osElmt.getElementsByTagName("osclass")[0];
              if (typeof (osClassElmt) == "undefined") {
                host["os"] = "";
              }
              else {
                host["os"] = osClassElmt.getAttribute("osfamily");
              }
            }
            var hostnamesElmt = hosts[i].getElementsByTagName("hostnames")[0];
            if (typeof (hostnamesElmt) === "undefined") {
              host["hostname"] = "Unknown";
            }
            else {
              var dnElmt = this.getXmlElementByAttribute(hostnamesElmt.getElementsByTagName("hostname"), "type", "PTR");
              host["hostname"] = dnElmt ? dnElmt.getAttribute("name") : "Unknown";
            }

            var portsElmt = hosts[i].getElementsByTagName("ports")[0];
            if (typeof (portsElmt) === "undefined") throw ("Parsing Error: No 'ports' element in host number " + i);
            var ports = portsElmt.getElementsByTagName("port");
            host["services"] = [];
            for (var j = 0; j < ports.length; j++) {
              var service = {};
              service["protocol"] = ports[j].getAttribute("protocol");
              service["port"] = ports[j].getAttribute("portid");
              service["state"] = ports[j].getElementsByTagName("state")[0].getAttribute("state");
              var service_details = ports[j].getElementsByTagName("service")[0];
              if (typeof (service_details) === "undefined") {
                service["product"] = "Unknown";
                service["name"] = "Unknown";
                service["version"] = "Unknown";
              } else {
                service["product"] = service_details.getAttribute("product") || "Unknown";
                service["name"] = service_details.getAttribute("name") || "Unknown";
                service["version"] = service_details.getAttribute("version") || "Unknown";
              }
              console.log('Service found: ' + JSON.stringify(service));

              if (service["state"] === "open") {
                host["services"].push(service);
              }
            }

            hostsRes.push({ label: host.ip, value: host.ip, host: host });
          }
        }
        this.targetsOptions = hostsRes;
        console.log('targetsOptions:', this.targetsOptions);  // Debugging log
        Notify.create({
          message: `Successfully imported ${hostsRes.length} hosts`,
          color: 'positive',
          textColor: 'white',
          position: 'top-right'
        });
      } catch (err) {
        console.log(err);
        Notify.create({
          message: 'Error parsing Nmap',
          color: 'negative',
          textColor: 'white',
          position: 'top-right'
        });
      }
    },
    parseXmlNessus(data) {
      var parser = new DOMParser();
      var xmlData = parser.parseFromString(data, "application/xml");
      
      // Parse the Nessus XML data to a JSON object
      try {
        var hosts = xmlData.getElementsByTagName("ReportHost");
        if (hosts.length == 0) throw ("Parsing Error: No 'ReportHost' element");
        
        var hostsRes = [];
        for (var i = 0; i < hosts.length; i++) {
          var hostProperties = hosts[i].getElementsByTagName("HostProperties")[0];
          var hostIp = hostProperties.querySelector("[name='host-ip']").textContent;
          var host = { properties: { "host-ip": hostIp }, services: [] };

          var reportItems = hosts[i].getElementsByTagName("ReportItem");
          for (var j = 0; j < reportItems.length; j++) {
            var service = {
              protocol: reportItems[j].getAttribute("protocol"),
              port: reportItems[j].getAttribute("port"),
              name: reportItems[j].getAttribute("svc_name"),
              severity: reportItems[j].getAttribute("severity"),
              pluginId: reportItems[j].getAttribute("pluginID"),
              pluginName: reportItems[j].getAttribute("pluginName"),
              cve: reportItems[j].getAttribute("cve"),
              cvssScore: reportItems[j].getAttribute("cvss_base_score"),
              cvssVector: reportItems[j].getAttribute("cvss_vector"),
              synopsis: reportItems[j].getElementsByTagName("synopsis")[0]?.textContent,
              description: reportItems[j].getElementsByTagName("description")[0]?.textContent,
              solution: reportItems[j].getElementsByTagName("solution")[0]?.textContent,
              seeAlso: reportItems[j].getElementsByTagName("see_also")[0]?.textContent,
              pluginOutput: reportItems[j].getElementsByTagName("plugin_output")[0]?.textContent
            };

            host.services.push(service);
          }

          hostsRes.push(host);
        }

        console.log("Parsed hosts: ", JSON.stringify(hostsRes, null, 2)); // Debugging log

        // Veriyi veritabanına kaydetmek için API çağrısı
        axios.post('/api/network/nessus', { data: hostsRes })
          .then(response => {
            console.log("Data saved to database: ", response.data);
            // targetsOptions'u güncelleyin
            this.targetsOptions = hostsRes;
            Notify.create({
              message: `Successfully imported ${hostsRes.length} hosts`,
              color: 'positive',
              textColor: 'white',
              position: 'top-right'
            });
          })
          .catch(err => {
            console.log(err);
            Notify.create({
              message: 'Error saving data to database',
              color: 'negative',
              textColor: 'white',
              position: 'top-right'
            });
          });
        
      } catch (err) {
        console.log(err);
        Notify.create({
          message: 'Error parsing Nessus XML',
          color: 'negative',
          textColor: 'white',
          position: 'top-right'
        });
      }
    },
    fetchNessusReports() {
      axios.get('/api/network/nessus')
        .then(response => {
          this.targetsOptions = response.data;
        })
        .catch(err => {
          console.log(err);
          Notify.create({
            message: 'Error fetching Nessus reports',
            color: 'negative',
            textColor: 'white',
            position: 'top-right'
          });
        });
    },
    addAllToFindings() {
      const vulnerabilities = this.targetsOptions.map(target => {
        return target.services.map(service => ({
          pluginId: service.pluginId,
          cve: service.cve,
          cvssScore: service.cvssScore,
          cvssVector: service.cvssVector,
          risk: service.severity,
          host: target.properties['host-ip'],
          protocol: service.protocol,
          port: service.port,
          name: service.pluginName,
          synopsis: service.synopsis,
          description: service.description,
          solution: service.solution,
          seeAlso: service.seeAlso,
          pluginOutput: service.pluginOutput,
        }));
      }).flat();
      
      axios.post('/api/network/nessus/vulnerabilities', { data: vulnerabilities })
        .then(response => {
          Notify.create({
            message: `Successfully added all findings`,
            color: 'positive',
            textColor: 'white',
            position: 'top-right'
          });
        })
        .catch(err => {
          console.log(err);
          Notify.create({
            message: 'Error adding findings',
            color: 'negative',
            textColor: 'white',
            position: 'top-right'
          });
        });
    }
  },
  mounted() {
    this.fetchNessusReports();
  }
};
