'use strict';
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const count = (buf, s) => { let n = 0; let i = 0; while ((i = buf.indexOf(s, i)) !== -1) { n++; i += s.length; } return n; };
const printable = (buf) => buf.toString('latin1').replace(/[^\x20-\x7e\r\n]/g, '·');
/** Wireshark-style hex dump of the first `max` bytes. */
function hexdump(buf, max = 64) {
  const lines = [];
  for (let i = 0; i < Math.min(buf.length, max); i += 16) {
    const row = buf.subarray(i, i + 16);
    lines.push(`${i.toString(16).padStart(4, '0')}  ${[...row].map((b) => b.toString(16).padStart(2, '0')).join(' ').padEnd(47)}  ${[...row].map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : '.')).join('')}`);
  }
  return lines.join('\n');
}

function createExperiments({ config, taps }) {
  const read = (...p) => fs.readFileSync(path.join(config.certsDir, ...p));
  let queue = Promise.resolve(); // one experiment at a time: they share the relays
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };

  /** Send POST /login through a relay, over HTTP or HTTPS. */
  function send(useTls, body, tlsVersion) {
    return new Promise((resolve) => {
      const opts = { host: '127.0.0.1', path: '/login', method: 'POST', agent: false,
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), Connection: 'close' } };
      const onRes = (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d, tls: useTls ? { version: res.socket.getProtocol(), cipher: res.socket.getCipher().standardName } : null })); };
      const req = useTls
        ? https.request({ ...opts, port: taps.https.listenPort, servername: 'localhost', ca: read('server.crt'), minVersion: tlsVersion, maxVersion: tlsVersion }, onRes) // trust only our self-signed cert
        : http.request({ ...opts, port: taps.http.listenPort }, onRes);
      req.on('error', (e) => resolve({ error: e.message.replace(/^.*SSL routines:[^:]*:([^:]+):.*$/s, '$1') }));
      req.setTimeout(4000, () => req.destroy(new Error('timeout')));
      req.end(body);
    });
  }

  /** Experiments 1 + 2: the same login over HTTP and HTTPS, as seen by someone on the wire. */
  function compare({ username, password, tlsVersion }) {
    return exclusive(async () => {
      const body = JSON.stringify({ username, password });
      const h0 = taps.http.lastId; const httpRes = await send(false, body); await sleep(80); const hw = taps.http.capture(h0);
      const s0 = taps.https.lastId; const httpsRes = await send(true, body, tlsVersion); await sleep(80); const sw = taps.https.capture(s0);
      if (httpRes.error) return { error: `HTTP server not reachable (${httpRes.error}). Start it with "npm start".` };
      if (httpsRes.error) return { error: `HTTPS request failed: ${httpsRes.error}` };
      const found = (w) => ({ username: count(w.toServer, username) + count(w.toClient, username), password: count(w.toServer, password) + count(w.toClient, password) });
      const sec = ['content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'strict-transport-security'];
      return {
        username, password,
        http: { bytes: hw.toServer.length + hw.toClient.length, found: found(hw), toServer: printable(hw.toServer), toClient: printable(hw.toClient), headers: sec.filter((h) => h in httpRes.headers) },
        https: {
          bytes: sw.toServer.length + sw.toClient.length, found: found(sw), tls: httpsRes.tls,
          // "localhost" in the clear = the server name (SNI) in the ClientHello; in the server's flight = the certificate (TLS 1.2 only)
          serverNameVisible: count(sw.toServer, 'localhost') > 0, certificateVisible: count(sw.toClient, 'localhost') > 0,
          serverNameBytes: (() => { const i = sw.toServer.indexOf('localhost'); return i === -1 ? '(not found)' : hexdump(sw.toServer.subarray(Math.max(0, i - 16), i + 48)); })(), encryptedBytes: hexdump(sw.toServer.subarray(-64)), headers: sec.filter((h) => h in httpsRes.headers),
        },
        allHeaders: sec,
      };
    });
  }

  /** Experiment 3: who trusts which certificate? */
  async function certCheck() {
    const servers = [
      { title: 'Self-signed (main server)', port: config.httpsPort, trust: read('server.crt') },
      { title: 'Signed by Lab CA, valid', port: config.labValidPort, trust: read('ca.crt') },
      { title: 'Signed by Lab CA, EXPIRED', port: config.labExpiredPort, trust: read('ca.crt') },
    ];
    const meaning = { DEPTH_ZERO_SELF_SIGNED_CERT: 'self-signed: nobody vouches for it', UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'issuer (CA) not trusted', CERT_HAS_EXPIRED: 'certificate has expired' };
    const attempt = (port, opts) => new Promise((resolve) => {
      const s = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ...opts }, () => { resolve(s.authorized ? { ok: true } : { ok: true, unverified: s.authorizationError }); s.destroy(); });
      s.setTimeout(3000, () => { s.destroy(); resolve({ ok: false, code: 'TIMEOUT' }); });
      s.on('error', (e) => resolve({ ok: false, code: e.code, meaning: meaning[e.code] || e.message }));
    });
    const clients = ['Default trust store (a browser)', 'Trusts the issuer', 'Verification OFF (curl -k)'];
    const rows = [];
    for (const s of servers) rows.push({ server: s.title, cells: [await attempt(s.port, {}), await attempt(s.port, { ca: s.trust }), await attempt(s.port, { rejectUnauthorized: false })] });
    return { clients, rows };
  }

  return { compare, certCheck };
}

/** Subject, issuer and days left of a certificate file (for the monitor card). */
function certInfo(file) {
  const x = new crypto.X509Certificate(fs.readFileSync(file));
  const daysLeft = Math.floor((new Date(x.validTo) - Date.now()) / 86_400_000);
  return { subject: x.subject, issuer: x.issuer, selfSigned: x.subject === x.issuer, validTo: x.validTo, daysLeft, status: daysLeft < 0 ? 'expired' : daysLeft < 30 ? 'expiring soon' : 'valid', publicKey: x.publicKey.asymmetricKeyType.toUpperCase() + (x.publicKey.asymmetricKeyDetails.modulusLength ? '-' + x.publicKey.asymmetricKeyDetails.modulusLength : '') };
}

module.exports = { createExperiments, certInfo };
