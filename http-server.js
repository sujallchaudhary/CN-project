'use strict';
// The INSECURE server (plain HTTP, port 8080): no TLS, no security headers.
// Port 8082 does what a real site should do: redirect everything to HTTPS.
const express = require('express');
const config = require('./config');

const fail = (port) => (e) => { console.error(e.code === 'EADDRINUSE' ? `Port ${port} is already in use - stop the other program (e.g. version 1) or change it in config.js` : e.message); process.exit(1); };

const app = express();
app.disable('x-powered-by');
app.use(express.json());
app.post('/login', (req, res) => res.json({ message: 'Login request received over HTTP', username: req.body.username }));
app.listen(config.httpPort, config.host, () => console.log(`HTTP  (insecure)  http://localhost:${config.httpPort}`)).on('error', fail(config.httpPort));

const redirector = express();
redirector.disable('x-powered-by');
redirector.use((req, res) => res.redirect(308, `https://localhost:${config.httpsPort}${req.originalUrl}`));
redirector.listen(config.redirectPort, config.host, () => console.log(`HTTP  (redirect)  http://localhost:${config.redirectPort}  ->  https://localhost:${config.httpsPort}`)).on('error', fail(config.redirectPort));
