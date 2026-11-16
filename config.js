'use strict';
const path = require('node:path');
const port = (name, def) => Number(process.env[name] || def);

module.exports = {
  host: '127.0.0.1',
  httpsPort: port('HTTPS_PORT', 4433),       // secure server
  httpPort: port('HTTP_PORT', 8080),         // insecure server (for comparison)
  redirectPort: port('REDIRECT_PORT', 8082), // plain HTTP that only redirects to HTTPS
  tapHttpPort: port('TAP_HTTP_PORT', 8081),  // recording relay in front of the HTTP server
  tapHttpsPort: port('TAP_HTTPS_PORT', 4434),// recording relay in front of the HTTPS server
  labValidPort: port('LAB_VALID_PORT', 4441),     // certificate lab: CA-signed, valid
  labExpiredPort: port('LAB_EXPIRED_PORT', 4442), // certificate lab: CA-signed, expired
  certsDir: path.join(__dirname, 'certs'),
  // Browsers apply HSTS per HOST (ignoring the port): turning it on for localhost would also force
  // https onto the plain-HTTP demo. Enable with HSTS=1 for a real deployment.
  hsts: process.env.HSTS === '1',
  keylogFile: process.env.SSLKEYLOGFILE || '', // lets Wireshark decrypt this server's traffic (lab use only)
};
