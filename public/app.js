'use strict';
// Build the page with textContent only (never innerHTML), so no string from the network can inject markup.
const $ = (id) => document.getElementById(id);
function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props && props.class) e.className = props.class;
  for (const k of kids.flat()) if (k !== null && k !== undefined) e.append(k instanceof Node ? k : String(k));
  return e;
}
const api = (url, body) => fetch(url, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {}).then((r) => r.json());
const fill = (dl, pairs) => dl.replaceChildren(...pairs.flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));

// Wrap every occurrence of the secrets in <mark>.
function mark(text, secrets) {
  const out = document.createDocumentFragment(); let rest = text;
  for (;;) {
    const hits = secrets.map((s) => [rest.indexOf(s), s]).filter(([i]) => i !== -1).sort((a, b) => a[0] - b[0]);
    if (!hits.length) { out.append(rest); return out; }
    const [i, s] = hits[0]; out.append(rest.slice(0, i), h('mark', {}, s)); rest = rest.slice(i + s.length);
  }
}

api('/api/whoami').then((w) => {
  fill($('conn'), [['HTTPS', w.secure], ['TLS version', w.tlsVersion], ['cipher suite', w.cipher], ['server name', w.serverName]]);
  const c = w.certificate;
  fill($('cert'), [['subject', c.subject], ['issuer', c.issuer + (c.selfSigned ? '  (self-signed)' : '')], ['valid until', c.validTo], ['days left', `${c.daysLeft} (${c.status})`], ['public key', c.publicKey]]);
});

function showCompare(d) {
  if (d.error) return h('div', { class: 'banner bad' }, d.error);
  const secrets = [d.username, d.password];
  const leaked = (w) => w.found.username + w.found.password > 0;
  const httpPanel = h('div', { class: 'card' }, h('h3', {}, `HTTP - ${d.http.bytes} bytes on the wire`),
    h('div', { class: `banner ${leaked(d.http) ? 'bad' : 'ok'}` }, leaked(d.http) ? '⚠ username and password are readable by anyone on the path' : 'secrets not found'),
    h('div', { class: 'muted' }, 'client → server:'), h('pre', {}, mark(d.http.toServer, secrets)),
    h('div', { class: 'muted' }, 'server → client:'), h('pre', {}, mark(d.http.toClient, secrets)));
  const httpsPanel = h('div', { class: 'card' }, h('h3', {}, `HTTPS (${d.https.tls.version}) - ${d.https.bytes} bytes on the wire`),
    h('div', { class: `banner ${leaked(d.https) ? 'bad' : 'ok'}` }, leaked(d.https) ? '⚠ secret found on the wire' : '✔ username and password do not appear anywhere in the capture'),
    h('div', { class: 'muted' }, 'client → server, inside the ClientHello (sent before encryption starts): the server name is readable:'), h('pre', {}, d.https.serverNameBytes),
    h('div', { class: 'muted' }, 'client → server, last 64 bytes (the encrypted request):'), h('pre', {}, d.https.encryptedBytes));
  const rows = [
    ['Username readable on the wire', d.http.found.username ? 'YES' : 'no', d.https.found.username ? 'YES' : 'no'],
    ['Password readable on the wire', d.http.found.password ? 'YES' : 'no', d.https.found.password ? 'YES' : 'no'],
    ['TLS handshake', 'none', `yes - ${d.https.tls.version}, ${d.https.tls.cipher}`],
    ['Server name visible', 'n/a', d.https.serverNameVisible ? 'YES - HTTPS does not hide who you talk to' : 'no'],
    ['Server certificate visible', 'n/a', d.https.certificateVisible ? 'YES (TLS 1.2 sends it in clear)' : 'no (TLS 1.3 encrypts it)'],
    ['Security headers (Helmet)', `${d.http.headers.length} of ${d.allHeaders.length}`, `${d.https.headers.length} of ${d.allHeaders.length}`],
  ];
  const bad = (i, col) => (i < 2 && col === 1 && rows[i][1] === 'YES' ? 'badc' : i < 2 && col === 2 && rows[i][2] === 'no' ? 'good' : '');
  const table = h('table', {}, h('thead', {}, h('tr', {}, ['', 'HTTP', 'HTTPS'].map((t) => h('th', {}, t)))),
    h('tbody', {}, rows.map((r, i) => h('tr', {}, h('td', {}, r[0]), h('td', { class: bad(i, 1) }, r[1]), h('td', { class: bad(i, 2) }, r[2])))));
  return h('div', {}, h('div', { class: 'row' }, httpPanel, httpsPanel), table);
}

function showCerts(d) {
  const head = h('tr', {}, h('th', {}, 'Server presents'), d.clients.map((c) => h('th', {}, c)));
  const body = d.rows.map((r) => h('tr', {}, h('td', {}, r.server), r.cells.map((c) => {
    if (c.ok && !c.unverified) return h('td', { class: 'good' }, '✔ trusted');
    if (c.ok) return h('td', { class: 'badc' }, `⚠ accepted WITHOUT verifying (${c.unverified})`);
    return h('td', { class: 'badc' }, `✖ rejected: ${c.code}`, h('div', { class: 'muted' }, c.meaning));
  })));
  return h('div', {}, h('table', {}, h('thead', {}, head), h('tbody', {}, body)),
    h('p', { class: 'muted' }, 'With verification off the connection is still encrypted - but to whoever answers, which is why “curl -k” must stay a testing-only tool.'));
}

function wire(formId, outId, run, show) {
  $(formId).addEventListener('submit', async (ev) => {
    ev.preventDefault(); const btn = $(formId).querySelector('button'); btn.disabled = true;
    try { $(outId).replaceChildren(show(await run(new FormData($(formId))))); } catch (e) { $(outId).replaceChildren(h('div', { class: 'banner bad' }, String(e))); }
    btn.disabled = false;
  });
}
wire('cmpForm', 'cmpOut', (f) => api('/api/compare', Object.fromEntries(f)), showCompare);
wire('certForm', 'certOut', () => api('/api/certs'), showCerts);

// ?autorun runs both experiments on load (handy for screenshots)
if (new URLSearchParams(location.search).has('autorun')) { $('cmpForm').requestSubmit(); $('certForm').requestSubmit(); }
