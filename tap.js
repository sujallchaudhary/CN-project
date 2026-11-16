'use strict';
// "The attacker on the path": a TCP relay that forwards bytes unchanged and keeps a copy.
// It plays the role of Wireshark / a Wi-Fi sniffer without needing root.
//   client --> tap (listenPort) --> real server (targetPort)
const net = require('node:net');

class Tap {
  constructor(listenPort, targetPort) {
    this.listenPort = listenPort; this.connections = []; this.nextId = 1;
    this.server = net.createServer((client) => {
      const conn = { id: this.nextId++, toServer: [], toClient: [] };
      this.connections.push(conn); if (this.connections.length > 50) this.connections.shift();
      const upstream = net.connect(targetPort, '127.0.0.1');
      client.on('data', (d) => { conn.toServer.push(d); upstream.write(d); });
      upstream.on('data', (d) => { conn.toClient.push(d); client.write(d); });
      const close = () => { client.destroy(); upstream.destroy(); };
      client.on('close', close); upstream.on('close', close); client.on('error', () => {}); upstream.on('error', () => {});
    });
  }
  listen(host) { return new Promise((res) => this.server.listen(this.listenPort, host, res)); }
  get lastId() { return this.nextId - 1; }
  /** The bytes of the first connection opened after `afterId`, per direction. */
  capture(afterId) {
    const c = this.connections.find((x) => x.id > afterId);
    return c ? { toServer: Buffer.concat(c.toServer), toClient: Buffer.concat(c.toClient) } : { toServer: Buffer.alloc(0), toClient: Buffer.alloc(0) };
  }
}
module.exports = { Tap };
