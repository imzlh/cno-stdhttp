# HTTP/1.x framing, backpressure and header limits

Wire-level rules implemented in `http/src/h1.ts` and `http/src/h1-frame.ts`,
and the reasons the code is shaped the way it is. Anything here that looks like
over-engineering is load-bearing: each item prevents a concrete class of bug.

## Request-body backpressure (server)

Three related thresholds govern how much undelivered body the server keeps:

- `BODY_HIGH_WATER_MARK` (1 MiB): once a handler has polled `req.body()` and this
  many bytes are queued undelivered, the read loop stops reading the socket.
  Not reading leaves the bytes in the kernel receive buffer, which closes the
  TCP window and makes the peer wait. This *is* the flow control.
- `BODY_RESUME_MARK` (256 KiB): the loop resumes when the queue drains below this.
- `MAX_BUFFERED_BODY_BYTES` (16 MiB): hard ceiling for a handler that never
  drains. Reaching it fails the connection (`ERR_HTTP_REQUEST_BODY_TOO_LARGE`)
  rather than growing the queue. Deliberately the same value as the HTTP/2 cap
  in `h2.ts` so a peer cannot use the other protocol as a weaker flood path.

Backpressure only engages after the first `req.body()` call (`bodyPolled`), so a
handler that reads nothing cannot pin a read loop blocked on a drain waiter.

## Header-size accounting

llhttp has no limit on the head, and `maxHeadersCount` is only checked at
`onHeadersComplete`, which a peer streaming an endless header block never
reaches. `chargeHeaderBytes` therefore accounts the request target, each field
name and each field value *as they arrive*, and answers 431 once the total
exceeds `maxHeaderSize` (default 16384, matching Node's `http.maxHeaderSize`).
The request URL counts: a `30k` target is Node's `HPE_HEADER_OVERFLOW`, and it
is what an attacker grows when sending no headers at all.

## Transfer-Encoding / Content-Length

- A coding list is chunked only when `chunked` is the final non-empty token
  (RFC 9112 §7).
- A request with both `Transfer-Encoding` and `Content-Length`, or with a
  transfer coding other than chunked, is rejected before any handler runs
  (request smuggling).
- A malformed framing error detected before `onHeadersComplete` gets a 400
  response rather than a bare FIN.

## Response framing

- HEAD and 1xx/204/205/304 responses end at the header block (`bodyless`). Any
  body byte written for them would be parsed by the peer as the head of the
  next response, so `writeData` drops it. Content-Encoding and
  Transfer-Encoding are stripped from forbidden-status responses, but
  Content-Length is kept as representation metadata.
- 1xx responses are interim: they never mark the final response as sent nor
  change its framing (103 then 200 is valid).
- With no handler-supplied framing: chunked on HTTP/1.1, close-delimited
  otherwise (Node parity). Close-delimited responses set `keepAlive = false`.
- Status lines always say `HTTP/1.1` (Node parity); the request version still
  controls framing.
- Conflicting `Connection` headers are normalised: a handler-supplied
  `keep-alive` is removed when the response disables reuse (except 101 upgrade).

## Truncation detection

- `bodyRead` counts bytes the framing actually delivered, so a peer that
  vanishes short of `Content-Length` (or before the 0-chunk) is told apart from
  one that finished. `failBody` maps a disconnect in that state to
  `ECONNRESET` "request body truncated" instead of a clean EOF.
- On the client side, EOF before the response completes is an error. Returning
  `{status: 0, body: <partial>}` would hand the caller a truncated body that
  looks like a successful short response; Node reports ECONNRESET / "socket hang
  up". A close-delimited response is first completed via `finishOnEof()` so it
  is not mistaken for truncation.

## Chunked trailers

- llhttp does not emit `onHeadersComplete` for the trailer block, so the last
  trailer pair has no following field callback to flush it;
  `onMessageComplete` commits it explicitly.
- Trailer fields go to `trailers`, never to `reqHeaders`, or a trailer could
  forge a request header.
