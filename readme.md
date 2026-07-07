# @cnojs/http

`http/` is the low-level HTTP protocol package used by the `cno` runtime. It is
published as `@cnojs/http` and is imported by Web API, Deno, and Node HTTP
polyfills where raw protocol helpers are needed.

This package should stay independent from Web API objects such as `Request`,
`Response`, `Headers`, and `URL`. Higher layers translate those objects into
the raw shapes used here.

## Exports

The package exports TypeScript source files directly:

```text
@cnojs/http
@cnojs/http/socket
@cnojs/http/dns-cache
@cnojs/http/zlib
@cnojs/http/protocol
@cnojs/http/h1
@cnojs/http/ext-h2
@cnojs/http/server
@cnojs/http/debug
@cnojs/http/process
```

## Directory Layout

| Path | Role |
| --- | --- |
| `src/index.ts` | Main package barrel |
| `src/socket.ts` | TCP/TLS socket wrapper over circu.js native modules |
| `src/dns-cache.ts` | DNS cache helper |
| `src/zlib.ts` | Compression helpers |
| `src/protocol.ts` | Protocol interfaces and raw message types |
| `src/h1.ts` | HTTP/1.x builder/parser/protocol implementation |
| `src/server.ts` | Protocol-aware server helpers |
| `src/debug.ts` | Debug logging utilities |
| `src/process.ts` | Progress display helpers |
| `ext-h2/` | HTTP/2 native extension declarations and glue |
| `types/` | Native module declarations used by this package |

## Design Boundary

Use this package for:

- raw bytes
- sockets
- protocol messages
- HTTP/1 parsing/building
- protocol abstractions
- optional HTTP/2 extension types

Do not put Web API, Deno, or Node compatibility behavior here. Those belong in
`../cno/src/webapi`, `../cno/src/deno`, or `../cno/src/node`.

## Build And Use

The root build consumes this package through workspace-style imports and bundles
the TypeScript into the final CLI:

```sh
pnpm run type-check
cmake --build build
```

The package itself has no separate runtime binary. It depends on circu.js
native modules being available through `import.meta.use()` when executed inside
the cno runtime.

## HTTP/2

HTTP/2 support is provided by the optional native extension under `ext-h2/`.
The root build can statically embed it with:

```sh
cmake -B build -DCNO_EMBED_EXT_H2=ON
```

When not embedded, HTTP/2-specific consumers must arrange for the extension to
be available through the runtime extension loading path.
