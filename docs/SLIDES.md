# Slides - Secure Web Server with TLS (9 slides)

**1. Title** - Design and Implementation of a Secure Web Server Using TLS · name · roll no.

**2. Problem** - HTTP is plain text. Anyone on the path (Wi-Fi, router, ISP) can read and change it. Demo idea: show the clear-text password in Wireshark.

**3. Architecture** - diagram: HTTP :8080 (insecure) · HTTPS :4433 (TLS + Helmet) · redirector :8082 · lab relay. Stack: Node.js, Express, Helmet, OpenSSL, Wireshark.

**4. How TLS works** - TCP connection → ClientHello (versions, ciphers, server name) → ServerHello + certificate → key exchange (ephemeral Diffie-Hellman) → encrypted data. Asymmetric for authentication and key setup, symmetric (AES-GCM) for the data.

**5. Certificates** - subject, issuer, validity, public key, CA signature. Self-signed vs CA-signed vs expired. Why the browser warns.

**6. Experiment 1 - HTTP vs HTTPS** - same login on both. Table: password visible / not visible, handshake, encrypted application data. Screenshots: Wireshark `http` vs `tls`.

**7. Experiment 2 - certificate validation** - the 3×3 matrix; why `curl -k` is dangerous.

**8. What HTTPS does not hide** - server name (SNI), IPs, sizes, timing. Also: TLS 1.2 shows the certificate, TLS 1.3 encrypts it.

**9. Conclusion and extras** - confidentiality, integrity, authentication. Extras: Helmet headers, HTTP→HTTPS redirect, `minVersion` TLS 1.2, TLS monitor card. Future work: Let's Encrypt, HSTS preload, mutual TLS (see version 1).
