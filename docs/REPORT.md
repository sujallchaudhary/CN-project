# Design and Implementation of a Secure Web Server Using TLS

**Course:** Computer Networks - Mini Project  **Name:** [your name]  **Roll no.:** [your roll no.]  **Date:** [date]

## 1. Abstract
This project builds a small web server that serves the same application over plain HTTP and over HTTPS (HTTP on TLS), and demonstrates with captured network traffic why HTTP is unsafe and what TLS protects. A lab page runs the experiment automatically; the same experiment is described for Wireshark and OpenSSL.

## 2. Objectives
1. Show how an HTTP server works and why its traffic can be read by anyone on the path.
2. Show how TLS encrypts and authenticates the communication.
3. Show how certificates establish the identity of a server, and what happens when they are self-signed, from an unknown CA, or expired.
4. Compare HTTP and HTTPS packets.

## 3. Background
- **TCP** carries a reliable byte stream; HTTP and TLS both run on top of it.
- **HTTP** sends requests and responses as readable text.
- **TLS** sits between TCP and HTTP. In the handshake the client and server agree on a protocol version and cipher suite, the server proves its identity with a certificate, and both derive shared **session keys** using an ephemeral Diffie-Hellman exchange. Afterwards the data is protected with **symmetric** authenticated encryption (AES-GCM), which is fast and also detects modification.
- **Asymmetric cryptography** (the certificate's public/private key pair) is used for authentication and key establishment, not for bulk data.
- **A certificate** binds a public key to a name and is signed by a Certificate Authority. A client accepts it only if the signature chains to a trusted CA, the name matches, and it has not expired. A **self-signed** certificate has no CA behind it, so browsers reject it unless it is explicitly trusted.

## 4. Architecture
```
 browser / curl ──HTTP :8080────────────► Express (no TLS)            insecure server
 browser / curl ──HTTPS (TLS 1.2/1.3) :4433► Express + Helmet on https  secure server + lab page
 browser / curl ──HTTP :8082────────────► 308 redirect to HTTPS
 lab experiment ──► recording relay ──► server    (stands in for Wireshark)
```
Components: `http-server.js`, `server.js`, `tap.js` (relay), `experiments.js`, `public/` (lab page), `certs/gen-certs.sh` (OpenSSL).

## 5. Methodology and implementation
1. **Certificates (OpenSSL):** a self-signed RSA-2048 certificate for `localhost` (SAN `localhost`, `127.0.0.1`), plus a small local CA that signs a valid and an expired certificate for the certificate lab.
2. **HTTPS server:** Express with Helmet on `https.createServer({key, cert, minVersion: 'TLSv1.2'})`.
3. **HTTP server:** the same `/login` endpoint, with no TLS and no security headers.
4. **Redirector:** every HTTP request on :8082 gets `308` to the HTTPS URL; the target host is fixed, not taken from the request.
5. **Experiment 1:** the same `POST /login` (username and password) is sent to both servers through a relay that records every byte; the capture is searched for the secrets and summarised.
6. **Experiment 2:** three certificates are tested against three client configurations.
7. **Wireshark / OpenSSL:** the same comparison with real tools (`docs/wireshark-guide.md`).

## 6. Results
**Experiment 1 - what is visible on the wire** (typical values from the lab page):

| Observation | HTTP | HTTPS |
|---|---|---|
| Username readable | yes | no |
| Password readable | yes, in clear text | no |
| Request line and headers readable | yes | no |
| TLS handshake | none | yes (TLS 1.3: `TLS_AES_256_GCM_SHA384`) |
| Server name (SNI) visible | n/a | **yes** |
| Server certificate visible | n/a | TLS 1.2: yes; TLS 1.3: no (encrypted) |
| Bytes on the wire for one login | ≈ 410 | ≈ 2 900 (TLS 1.2) / ≈ 5 600 (TLS 1.3, includes a large ClientHello) |
| Security headers (Helmet) | 0 | 4 of 5 checked (HSTS is disabled on localhost, see below) |

**Experiment 2 - certificate validation:**

| Server presents | Default trust store | Trusts the issuer | Verification off |
|---|---|---|---|
| Self-signed | rejected (`DEPTH_ZERO_SELF_SIGNED_CERT`) | accepted | accepted unverified |
| CA-signed, valid | rejected (CA unknown) | accepted | accepted unverified |
| CA-signed, expired | rejected | rejected (`CERT_HAS_EXPIRED`) | accepted unverified |

Further checks: `openssl s_client -tls1_1 -cipher 'DEFAULT:@SECLEVEL=0'` is refused by the server because the server requires TLS 1.2 or newer; HTTP requests on :8082 are answered with a redirect.

[Insert screenshots here: Wireshark `http` filter showing the clear-text password; Wireshark `tls` filter showing encrypted application data; the lab page results; `openssl s_client` output.]

## 7. Discussion
- HTTPS gives **confidentiality** (content unreadable), **integrity** (modification detected) and **server authentication** (certificate check).
- It does **not** hide metadata: the server name, IP addresses, packet sizes and timing remain visible.
- Encryption without authentication is not enough: a client with verification disabled (`curl -k`) still has an encrypted channel, but possibly to an attacker.
- Helmet's HSTS header is turned off on localhost because browsers apply HSTS per host, ignoring the port, which would force HTTPS onto the HTTP demo as well. A real deployment should enable it.
- Limitations: self-signed certificates are for learning only; the lab relay observes loopback traffic only.

## 8. Conclusion
The experiments show that plain HTTP exposes credentials to anyone on the network path, while HTTPS keeps the same request unreadable and verifiable, at the cost of a handshake and some extra bytes. Correct certificate validation is what makes the encryption meaningful.

## 9. References
RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 9110/9112 (HTTP), RFC 6797 (HSTS), RFC 5280 (X.509), Node.js `https`/`tls` documentation, Helmet and Wireshark documentation.
