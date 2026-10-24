# HTTP/2 notes

Why `http/src/h2.ts` is shaped the way it is. The adapter drives an nghttp2
`Session` from `ext-h2` over `TcpSocket`.

## No transport backpressure, so bodies are capped

The session is created without an `nghttp2_option`, so `no_auto_window_update`
is never set: nghttp2 refills the flow-control window itself as soon as DATA
arrives (`H2Connection.manualWindow` stops calling `consume()` after the first
failure). Nothing slows an unread upload down. Two guards replace it:

- `MAX_BUFFERED_BODY_BYTES` (16 MiB) of undelivered server-side body: discard
  the buffer, fail the stream (`ERR_HTTP2_STREAM_ERROR`) and RST_STREAM with
  `FLOW_CONTROL_ERROR`. Only the offending stream dies. Applied to the server
  only: a server handler drains through `bodyChunks()`, while the client merges
  the whole response in one piece, so a client cap would just cap download size.
- After a stream has failed or closed, `acceptData` drops further DATA instead
  of buffering it. Otherwise a peer that ignores the RST_STREAM refills and
  trips the cap once per 16 MiB forever.

`bodyChunks()` therefore has to keep its array small on its own: consumed slots
are nulled, and the consumed prefix is spliced out once the cursor passes the
halfway mark (amortised O(1), array stays O(outstanding) rather than O(total
frames)). Without the splice, a draining handler grows `chunks` by one pointer
per DATA frame while `buffered` stays at 0, invisible to the cap.

## Detecting a truncated body

`on_stream_close` fires for *every* stream, successful ones included, with code
0. So code 0 cannot mean "error" on its own. A stream is truncated when it
closes after headers without `endStreamSeen` and without `locallyEnded`:
RST_STREAM(NO_ERROR) mid-body would otherwise look like a clean finish and hand
a handler a short payload. Reported as `ECONNRESET`, the same code H1's
`failBody` uses.

- `endStreamSeen` is set only by a real END_STREAM on HEADERS/DATA, or by
  `acceptEnd()` (the frame observer, because **nghttp2 does not invoke `ondata`
  for an empty DATA frame**).
- `locallyEnded` covers a server that answers without draining the request: the
  peer's half legitimately stays open, and that must not be reported as
  truncation.

## Informational responses

1xx HEADERS are not the response. Client-side they are dropped so the final
200/204 still lands in the final-header slot. `headers === null` on the trailers
callback means the block is really the response head (nghttp2 routes a final
response after informational ones through the generic HEADERS callback).

## Header list size

SETTINGS_MAX_HEADER_LIST_SIZE is always advertised (`DEFAULT_MAX_HEADER_LIST_SIZE`,
65535 = Node's http2 default). Without it the peer may send any size of
HPACK-decoded block and nghttp2 enforces none. The H1 `maxHeaderSize` (16 KiB)
is deliberately not reused: it would reject blocks Node's http2 server accepts.

## Session wiring order

`sess.onsend` must be assigned first: the C session queues preface/SETTINGS
until it is set, then flushes.

## Duplicate writeHead

`writeHead` is guarded by `finalHeadSent`, not `outputEnded`: a request with a
body never sets `outputEnded`, so the weaker guard let a second HEADERS frame
onto the same stream.
