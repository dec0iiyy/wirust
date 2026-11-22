// Local fixture servers for the UI e2e run: HTTP + WebSocket on one port, HTTPS h2 (gRPC-style) on another.
// usage: node scripts/ui-e2e-fixtures.mjs HTTP_PORT HTTPS_PORT CERT.pem KEY.pem (see docs/ui.md)
import http from "node:http";
import http2 from "node:http2";
import zlib from "node:zlib";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";

const [httpPort, httpsPort, certPath, keyPath] = process.argv.slice(2);
const png = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAFklEQVR4nGP8z8BQz0AEYBxVSF+FAP5FDvcfRYWgAAAAAElFTkSuQmCC",
  "base64",
);

function route(req, res) {
  const u = new URL(req.url, "http://x");
  const p = u.pathname;
  if (p === "/json") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ name: "wirust", nested: { a: [1, 2, 3], b: { deep: true } }, list: ["x", "y"] }));
  }
  if (p === "/text") { res.writeHead(200, { "content-type": "text/plain" }); return res.end("hello plain text\nline two\n"); }
  if (p === "/image") { res.writeHead(200, { "content-type": "image/png" }); return res.end(png); }
  if (p === "/bin") { res.writeHead(200, { "content-type": "application/octet-stream" }); return res.end(Buffer.from([0, 1, 2, 3, 250, 251, 252, 253, 254, 255, 10, 13])); }
  if (p === "/gzip") { res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" }); return res.end(zlib.gzipSync(JSON.stringify({ zipped: "gzip", ok: 1 }))); }
  if (p === "/br") { res.writeHead(200, { "content-type": "text/plain", "content-encoding": "br" }); return res.end(zlib.brotliCompressSync("brotli body text")); }
  if (p === "/big") { res.writeHead(200, { "content-type": "text/plain" }); return res.end("A".repeat(300000)); }
  if (p === "/slow") { setTimeout(() => { res.writeHead(200, { "content-type": "text/plain" }); res.end("slow"); }, 1300); return; }
  if (p === "/hang") { setTimeout(() => { res.writeHead(200, { "content-type": "text/plain" }); res.end("late"); }, Number(u.searchParams.get("ms") || 4000)); return; }
  if (p === "/500") { res.writeHead(500, { "content-type": "text/plain" }); return res.end("boom"); }
  if (p === "/404") { res.writeHead(404, { "content-type": "text/plain" }); return res.end("nope"); }
  if (p === "/echo") {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() }));
    });
    return;
  }
  if (p.startsWith("/demo.Greeter/")) {
    req.on("data", () => {});
    req.on("end", () => {
      // protobuf: field 1 string "hi there", field 2 varint 42
      const msg = Buffer.concat([Buffer.from([0x0a, 8]), Buffer.from("hi there"), Buffer.from([0x10, 42])]);
      const frame = Buffer.concat([Buffer.from([0, 0, 0, 0, msg.length]), msg]);
      res.writeHead(200, { "content-type": "application/grpc" });
      res.addTrailers({ "grpc-status": "0", "grpc-message": "ok" });
      res.end(frame);
    });
    return;
  }
  res.writeHead(200, { "content-type": "text/plain" });
  res.end("ok " + p);
}

// Minimal RFC 6455 server: echoes text and binary, greets with a JSON message.
function wsUpgrade(req, sock) {
  const key = req.headers["sec-websocket-key"];
  const accept = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  sock.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  const send = (op, data) => {
    const len = data.length;
    const head = len < 126 ? Buffer.from([0x80 | op, len]) : Buffer.from([0x80 | op, 126, len >> 8, len & 255]);
    sock.write(Buffer.concat([head, data]));
  };
  send(1, Buffer.from(JSON.stringify({ hello: "client", n: 1, items: [1, 2] })));
  let buf = Buffer.alloc(0);
  sock.on("data", (d) => {
    buf = Buffer.concat([buf, d]);
    while (buf.length >= 2) {
      const op = buf[0] & 15;
      let len = buf[1] & 127;
      let off = 2;
      if (len === 126) { len = buf.readUInt16BE(2); off = 4; }
      const masked = buf[1] & 128;
      const mask = masked ? buf.subarray(off, off + 4) : null;
      if (masked) off += 4;
      if (buf.length < off + len) return;
      const data = Buffer.from(buf.subarray(off, off + len));
      if (mask) for (let i = 0; i < data.length; i++) data[i] ^= mask[i % 4];
      buf = buf.subarray(off + len);
      if (op === 8) { send(8, data); sock.end(); return; }
      if (op === 9) { send(10, data); continue; }
      if (op === 1 || op === 2) send(op, Buffer.concat([Buffer.from(op === 1 ? "echo:" : ""), data]));
    }
  });
  sock.on("error", () => {});
}

const h = http.createServer(route);
h.on("upgrade", wsUpgrade);
h.listen(Number(httpPort), "127.0.0.1");
const s = http2.createSecureServer({ cert: readFileSync(certPath), key: readFileSync(keyPath), allowHTTP1: true }, route);
s.listen(Number(httpsPort), "127.0.0.1");
console.log("servers up", httpPort, httpsPort);
