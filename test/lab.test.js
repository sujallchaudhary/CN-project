'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const https = require('node:https');
const fs = require('node:fs');

const P = { HTTPS_PORT: 14533, HTTP_PORT: 18180, REDIRECT_PORT: 18182, TAP_HTTP_PORT: 18181, TAP_HTTPS_PORT: 14534, LAB_VALID_PORT: 14541, LAB_EXPIRED_PORT: 14542 };
const root = path.join(__dirname, '..');
let proc;

test.before(async () => {
  proc = spawn(process.execPath, ['start.js'], { cwd: root, env: { ...process.env, ...Object.fromEntries(Object.entries(P).map(([k, v]) => [k, String(v)])) }, stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((res, rej) => { proc.stdout.on('data', (d) => { if (String(d).includes('HTTPS (secure)')) res(); }); proc.once('exit', () => rej(new Error('server exited'))); setTimeout(() => rej(new Error('timeout')), 5000); });
});
test.after(() => proc.kill());

const call = (method, url, body) => new Promise((resolve, reject) => {
  const req = https.request({ host: '127.0.0.1', port: P.HTTPS_PORT, path: url, method, ca: fs.readFileSync(path.join(root, 'certs/server.crt')), servername: 'localhost', headers: { 'Content-Type': 'application/json' } }, (res) => {
    let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, json: d.startsWith('{') ? JSON.parse(d) : null }));
  });
  req.on('error', reject); req.end(body && JSON.stringify(body));
});

test('HTTPS login works and sends Helmet security headers', async () => {
  const r = await call('POST', '/login', { username: 'sujal', password: 'x' });
  assert.equal(r.status, 200);
  assert.equal(r.json.username, 'sujal');
  assert.ok(!('password' in r.json), 'password must not be echoed');
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
  assert.ok(r.headers['content-security-policy']);
});

test('TLS 1.1 is refused (minVersion is TLS 1.2)', async () => {
  const err = await new Promise((res) => { const https2 = require('node:tls').connect({ port: P.HTTPS_PORT, host: '127.0.0.1', minVersion: 'TLSv1', maxVersion: 'TLSv1.1', ciphers: 'DEFAULT:@SECLEVEL=0', rejectUnauthorized: false }, () => res(null)); https2.on('error', res); });
  assert.ok(err, 'handshake should fail');
});

test('experiment: password is visible over HTTP, not over HTTPS', async () => {
  for (const tlsVersion of ['1.3', '1.2']) {
    const { json: d } = await call('POST', '/api/compare', { username: 'sujal', password: 'S3cret!pw', tlsVersion });
    assert.ok(d.http.found.password > 0 && d.http.found.username > 0);
    assert.equal(d.https.found.password, 0);
    assert.equal(d.https.found.username, 0);
    assert.equal(d.https.tls.version, tlsVersion === '1.3' ? 'TLSv1.3' : 'TLSv1.2');
    assert.equal(d.https.serverNameVisible, true, 'SNI is sent in clear');
    assert.equal(d.https.certificateVisible, tlsVersion === '1.2', 'only TLS 1.2 sends the certificate in clear');
  }
});

test('certificate check: self-signed, expired and trusted cases', async () => {
  const { json: d } = await call('GET', '/api/certs');
  const [self, valid, expired] = d.rows.map((r) => r.cells);
  assert.equal(self[0].code, 'DEPTH_ZERO_SELF_SIGNED_CERT');
  assert.equal(self[1].ok && !self[1].unverified, true);
  assert.equal(valid[1].ok && !valid[1].unverified, true);
  assert.equal(expired[1].code, 'CERT_HAS_EXPIRED');
  for (const row of [self, valid, expired]) assert.ok(row[2].ok && row[2].unverified, 'verification off accepts anything');
});

test('plain HTTP redirector answers 308 to HTTPS', async () => {
  const res = await new Promise((resolve) => require('node:http').get({ host: '127.0.0.1', port: P.REDIRECT_PORT, path: '/x?y=1' }, resolve));
  assert.equal(res.statusCode, 308);
  assert.equal(res.headers.location, `https://localhost:${P.HTTPS_PORT}/x?y=1`);
  res.resume();
});
