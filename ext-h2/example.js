/**
 * circu:nghttp2 usage examples
 *
 * Assumes circu.js provides:
 *   - TlsSocket  : connect(host, port, {alpn}) / write(buf) / ondata / onclose
 *   - TlsServer  : listen(port) / [Symbol.asyncIterator] → TlsSocket
 *                  socket.alpnProtocol
 */

import { NgHttp2Session, constants } from "./http2" with { type: "native" };

/* ── Helpers ────────────────────────────────────────────────────── */

/** Concat Uint8Arrays */
function concat(...bufs) {
    const total = bufs.reduce((n, b) => n + b.byteLength, 0);
    const out   = new Uint8Array(total);
    let   off   = 0;
    for (const b of bufs) { out.set(new Uint8Array(b), off); off += b.byteLength; }
    return out;
}

/** Attach an NgHttp2Session to an already-connected TlsSocket */
function attachH2(socket, isServer, settings) {
    const sess = new NgHttp2Session(isServer, settings);
    sess.onsend  = chunk => socket.write(chunk);          // wire send directly
    socket.ondata  = buf  => sess.receive(buf);
    socket.onclose = ()   => sess.destroy();
    return sess;
}

/* ══════════════════════════════════════════════════════════════════
 * Example 1 — DoH over HTTP/2 (client)
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Send a raw DNS wire-format query over DoH/H2.
 * @param {string}     server   - hostname, e.g. "dns.google"
 * @param {Uint8Array} dnsMsg   - raw DNS message
 * @returns {Promise<Uint8Array>} raw DNS response
 */
export async function dohQuery(server, dnsMsg) {
    const socket = await TlsSocket.connect(server, 443, { alpn: ["h2"] });
    const sess   = attachH2(socket, false);

    return new Promise((resolve, reject) => {
        const chunks = [];

        sess.onstream = (streamId, headers) => {
            // status check
            const status = headers.find(([n]) => n === ":status")?.[1];
            if (status !== "200") {
                reject(new Error(`DoH: HTTP ${status}`));
                sess.resetStream(streamId, constants.NGHTTP2_CANCEL);
            }
        };

        sess.ondata = (streamId, chunk, endStream) => {
            chunks.push(chunk);
            if (endStream) {
                resolve(concat(...chunks));
                sess.destroy();
                socket.close();
            }
        };

        sess.onstreamclose = (streamId, code) => {
            if (code !== constants.NGHTTP2_NO_ERROR)
                reject(new Error(`stream closed: ${code}`));
        };

        const streamId = sess.request([
            [":method",       "POST"],
            [":path",         "/dns-query"],
            [":scheme",       "https"],
            [":authority",    server],
            ["content-type",  "application/dns-message"],
            ["content-length", String(dnsMsg.byteLength)],
            ["accept",        "application/dns-message"],
        ]);

        sess.sendData(streamId, dnsMsg, /* endStream */ true);
    });
}

/* ══════════════════════════════════════════════════════════════════
 * Example 2 — HTTP/2 echo server
 * ══════════════════════════════════════════════════════════════════ */

export async function runEchoServer(cert, key, port = 8443) {
    const server = await TlsServer.listen(port, { cert, key, alpn: ["h2", "http/1.1"] });
    console.log(`H2 echo server listening on :${port}`);

    for await (const socket of server) {
        if (socket.alpnProtocol !== "h2") {
            /* hand off to existing llhttp path */
            socket.emit("http1");
            continue;
        }
        handleH2Connection(socket);
    }
}

function handleH2Connection(socket) {
    const sess    = attachH2(socket, /* isServer */ true);
    const bodies  = new Map(); // streamId → Uint8Array[]

    sess.onstream = (streamId, headers) => {
        bodies.set(streamId, []);
        // store method/path via stream user data for later use
        sess.setStreamUserData(streamId, { headers });
    };

    sess.ondata = (streamId, chunk, endStream) => {
        bodies.get(streamId)?.push(chunk);
        if (!endStream) return;

        const body     = concat(...(bodies.get(streamId) ?? []));
        const { headers } = sess.getStreamUserData(streamId);
        const method   = headers.find(([n]) => n === ":method")?.[1];
        const path     = headers.find(([n]) => n === ":path")?.[1];

        console.log(`[h2] ${method} ${path} body=${body.byteLength}b`);
        bodies.delete(streamId);

        // echo body back
        sess.respond(streamId, [
            [":status",       "200"],
            ["content-type",  "application/octet-stream"],
            ["content-length", String(body.byteLength)],
        ]);
        sess.sendData(streamId, body, /* endStream */ true);
    };

    sess.onstreamclose = (streamId, code) => {
        bodies.delete(streamId);
        if (code !== constants.NGHTTP2_NO_ERROR)
            console.warn(`[h2] stream ${streamId} closed with error ${code}`);
    };

    sess.ongoaway = (code, lastStreamId) => {
        console.log(`[h2] GOAWAY code=${code} last=${lastStreamId}`);
        sess.destroy();
        socket.close();
    };

    sess.onerror = (code, msg) => {
        console.error(`[h2] error ${code}: ${msg}`);
    };
}

/* ══════════════════════════════════════════════════════════════════
 * Example 3 — ping keepalive
 * ══════════════════════════════════════════════════════════════════ */

export function startPingKeepalive(sess, intervalMs = 30_000) {
    let pending = false;

    const timer = setInterval(() => {
        if (pending) {
            console.warn("[h2] ping timeout, closing");
            sess.goaway();
            clearInterval(timer);
            return;
        }
        pending = true;
        sess.submitPing();
    }, intervalMs);

    const prevOnPing = sess.onping;
    sess.onping = (isAck, payload) => {
        if (isAck) pending = false;
        prevOnPing?.(isAck, payload);
    };

    return () => clearInterval(timer); // returns cancel fn
}
