'use strict';
// The SECURE server: Express + Helmet on Node's https module (TLS 1.2 minimum).
const express = require('express');
const helmet = require('helmet');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');
const { Tap } = require('./tap');
const { createExperiments, certInfo } = require('./experiments');

const read = (...p) => fs.readFileSync(path.join(config.certsDir, ...p));
const taps = { http: new Tap(config.tapHttpPort, config.httpPort), https: new Tap(config.tapHttpsPort, config.httpsPort) };
const experiments = createExperiments({ config, taps });

const app = express();
app.use(helmet({ strictTransportSecurity: config.hsts ? { maxAge: 31_536_000 } : false }));
app.use(express.json({ limit: '10kb' }));

// The endpoint from the brief. The password is never echoed or logged.
app.post('/login', (req, res) => res.json({ message: 'Login request received securely', username: req.body.username }));

// What this connection negotiated + certificate expiry (the "TLS monitor")
app.get('/api/whoami', (req, res) => {
  const s = req.socket;
  res.json({ secure: req.secure, tlsVersion: s.getProtocol(), cipher: s.getCipher().standardName, serverName: s.servername || null, certificate: certInfo(path.join(config.certsDir, 'server.crt')) });
});

const text = (v, d) => (typeof v === 'string' && v && v.length <= 64 ? v : d);
app.post('/api/compare', async (req, res) => {
  const b = req.body || {};
  res.json(await experiments.compare({ username: text(b.username, 'sujal'), password: text(b.password, 'S3cret!pw'), tlsVersion: b.tlsVersion === '1.2' ? 'TLSv1.2' : 'TLSv1.3' }));
});
app.get('/api/certs', async (req, res) => res.json(await experiments.certCheck()));

app.use(express.static(path.join(__dirname, 'public')));

const server = https.createServer({ key: read('server.key'), cert: read('server.crt'), minVersion: 'TLSv1.2' }, app);
if (config.keylogFile) {
  const out = fs.createWriteStream(config.keylogFile, { flags: 'a', mode: 0o600 });
  server.on('keylog', (line) => out.write(line));
}

const fail = (what, port) => (e) => { console.error(e.code === 'EADDRINUSE' ? `${what}: port ${port} is already in use - stop the other program (e.g. version 1) or change it in config.js` : e.message); process.exit(1); };
server.once('error', fail('HTTPS server', config.httpsPort));
server.listen(config.httpsPort, config.host, async () => {
  for (const t of Object.values(taps)) { t.server.once('error', fail('relay', t.listenPort)); await t.listen(config.host); }
  // Certificate lab: two more TLS listeners with a valid and an expired CA-signed certificate
  for (const [name, port] of [['valid', config.labValidPort], ['expired', config.labExpiredPort]]) {
    https.createServer({ key: read('lab', `${name}.key`), cert: read('lab', `${name}.crt`) }, (req, res) => res.end('ok')).listen(port, config.host);
  }
  console.log(`HTTPS (secure)    https://localhost:${config.httpsPort}   <- open this (self-signed certificate: accept the browser warning)`);
});
