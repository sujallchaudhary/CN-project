# Experiment: HTTP vs HTTPS in Wireshark

## 1. Capture
1. Start the project (`npm start`).
2. Open Wireshark → capture on the **loopback** interface (`Loopback: lo0` on macOS, `lo` on Linux, "Adapter for loopback traffic capture" on Windows with Npcap).
3. Optional capture filter: `tcp port 8080 or tcp port 4433`.
4. Run the requests **directly** (not through the lab page):
```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"username":"sujal","password":"S3cret!pw"}'
curl -k -X POST https://localhost:4433/login -H "Content-Type: application/json" -d '{"username":"sujal","password":"S3cret!pw"}'
```
5. Stop the capture and save it (`.pcapng`).

## 2. Analyse
| Display filter | What you should see |
|---|---|
| `http` | The HTTP request: `POST /login`, headers, and the JSON body with `sujal` and `S3cret!pw` in clear text. Right-click → *Follow → TCP Stream* to see it as text. |
| `tls` | The HTTPS connection: no readable request or body. |
| `tls.handshake.type == 1` | **ClientHello** - expand it: *Server Name* (`localhost`), supported TLS versions, cipher suites. This is sent before encryption starts. |
| `tls.handshake.type == 2` | **ServerHello** - the TLS version and cipher suite that were chosen. |
| `tls.handshake.type == 11` | **Certificate** - visible only with TLS 1.2 (`curl --tlsv1.2 --tls-max 1.2 -k …`). In TLS 1.3 it is encrypted. |
| `tls.record.content_type == 23` | **Application Data** - the encrypted login request. Compare with the `http` capture. |

If Wireshark shows port 4433 as plain TCP: *Analyze → Decode As… → TCP port 4433 → TLS*.

Search test: *Edit → Find Packet → String → "S3cret"*. It is found in the HTTP packet and in no HTTPS packet.

| HTTP | HTTPS |
|---|---|
| Request headers readable | Application data encrypted |
| Body (username/password) readable | Body not readable |
| No TLS handshake | TLS handshake present |
| No server authentication | Server certificate validated by the client |

HTTPS does not hide everything: the server name, IP addresses, ports, packet sizes and timing remain visible.

## 3. Optional: decrypt your own traffic
```bash
SSLKEYLOGFILE=$PWD/keylog.txt npm start
```
Wireshark → *Preferences → Protocols → TLS → (Pre)-Master-Secret log filename* → `keylog.txt`. The HTTPS request now appears decrypted under `http`.
Point for the report: TLS protects data **on the wire**; whoever has the session secrets can read it. Never enable this outside a lab, and don't commit `keylog.txt`.

## 4. Inspect the certificate with OpenSSL
```bash
openssl s_client -connect localhost:4433 -servername localhost
```
Look for: `Protocol : TLSv1.3`, `Cipher`, the certificate subject/issuer (identical for a self-signed cert), and `Verify return code: 18 (self-signed certificate)`. With `-CAfile certs/server.crt` the code becomes `0 (ok)`.
