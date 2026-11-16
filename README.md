# Secure Web Server Lab (v2)

A Computer Networks mini project: **a plain-HTTP server and an HTTPS (TLS) server side by side**, plus a small lab page that shows - with real captured bytes - what HTTPS protects and what it does not.

Stack: Node.js · Express · Helmet · Node's `https` module · OpenSSL · Wireshark · curl.

## Run it

```bash
npm install
npm run certs      # OpenSSL: self-signed cert (+ a tiny local CA for the certificate lab)
npm start          # starts everything
```

Open **https://localhost:4433**. The browser warns about the certificate because it is *self-signed* - that is exactly what experiment 2 explains. Click through (Advanced → Proceed) for the demo.

| Port | What | Security |
|---|---|---|
| 8080 | HTTP server (`http-server.js`) | none - deliberately insecure, for comparison |
| 4433 | HTTPS server (`server.js`) + the lab page | TLS 1.2+, Helmet headers |
| 8082 | HTTP → HTTPS redirector (`http-server.js`) | redirect only - the production pattern |
| 8081, 4434 | recording relays (`tap.js`) in front of 8080 / 4433 | stand-in for Wireshark inside the lab |
| 4441, 4442 | extra TLS listeners with a valid / an expired CA-signed certificate | certificate lab only |

> If `npm start` says **port already in use**, another program holds it (for example version 1 of this project on 8080). Stop it, or change the ports in `config.js` (each port can also be set by environment variable, e.g. `HTTP_PORT=8090 npm start`).

## Files

```
server.js         HTTPS server: Express + Helmet, /login, /api/*, serves the lab page
http-server.js    plain HTTP server (/login) and the redirector
tap.js            TCP relay that records the bytes passing through ("attacker on the path")
experiments.js    the two experiments (compare HTTP/HTTPS, certificate check)
config.js         ports and options
certs/gen-certs.sh   all OpenSSL commands
public/           the lab page (index.html, app.js, style.css)
test/lab.test.js  5 automated tests          docs/   wireshark guide, report, slides
```
About 220 lines of server code in total.

## The experiments

**1 · HTTP vs HTTPS (lab page, section 1)** - the same `POST /login` goes to both servers through a recording relay. Result: over HTTP the username and password appear in clear text in the capture; over HTTPS they appear nowhere. The page also shows what *is* still visible with HTTPS: the server name (SNI) in the ClientHello, the TLS version and cipher suite, packet sizes, and (TLS 1.2 only) the server certificate. Pick TLS 1.2 or 1.3 to compare.

**2 · Certificates (lab page, section 2)** - three certificates (self-signed, CA-signed, expired) against three clients (default trust store, "trusts the issuer", verification off). Shows when a client accepts a certificate, why a self-signed one is rejected by default, and why `curl -k` removes the protection.

**3 · The same thing with real tools** - see [docs/wireshark-guide.md](docs/wireshark-guide.md) for Wireshark, and:

```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"username":"sujal"}'
curl -k -X POST https://localhost:4433/login -H "Content-Type: application/json" -d '{"username":"sujal"}'   # -k: testing only
curl --cacert certs/server.crt https://localhost:4433/api/whoami                                              # verified properly
curl -i http://localhost:8082/anything                                                                        # 308 -> HTTPS
openssl s_client -connect localhost:4433 -servername localhost                                                # certificate, TLS version, cipher
openssl s_client -connect localhost:4433 -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0'                                      # server refuses: minVersion TLS 1.2 (modern OpenSSL won't even try TLS 1.1 without the -cipher option)
```

## Concepts this project demonstrates

| Concept | Where to see it |
|---|---|
| TCP | every experiment runs over TCP connections; the relay forwards TCP streams |
| HTTP | `http-server.js`, readable requests in experiment 1 |
| HTTPS = HTTP over TLS | `server.js` uses `https.createServer` with the same Express app |
| TLS handshake | Wireshark filter `tls`; `openssl s_client` output |
| Asymmetric crypto | the certificate's public key (RSA-2048) authenticates the server and takes part in key setup |
| Symmetric encryption | after the handshake the data is encrypted with a session key (AES-GCM) - the unreadable bytes in experiment 1 |
| Certificates | experiment 2; `certs/gen-certs.sh` |
| Integrity | each TLS record is authenticated (AEAD), so tampering is detected |

## Design notes

- **`minVersion: 'TLSv1.2'`** - TLS 1.0/1.1 are obsolete. Try the `-tls1_1` command above and watch the server refuse it.
- **Helmet** adds security headers (CSP, `X-Content-Type-Options`, …). **HSTS is off by default** because browsers apply it per *host* and ignore the port: on `localhost` it would force HTTPS onto the plain-HTTP demo too. Start with `HSTS=1 npm start` to see the header.
- **The password is never echoed or logged** by either server.
- **The redirector** uses a fixed target host instead of the request's `Host` header, so it cannot be abused as an open redirect.

## Limitations

- Self-signed / local-CA certificates are for learning only; a public site needs a certificate from a real CA (for example Let's Encrypt).
- The lab relay records traffic on `127.0.0.1` only; it demonstrates what an eavesdropper sees, it is not a network sniffer.
- HTTPS hides *content*, not *metadata*: the server name, timing and sizes remain visible.
- The lab page was checked through its API and an element-ID check; the visual rendering has not been verified in a browser.
