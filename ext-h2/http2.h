#ifndef NGHTTP2_CIRCU_H
#define NGHTTP2_CIRCU_H

#ifdef _WIN32
#include <BaseTsd.h>

#include <string.h>
#include <stdlib.h>
typedef SSIZE_T ssize_t;static inline char* strndup(const char* s, size_t n) {
    size_t len = strnlen(s, n);
    char* p = (char*) malloc(len + 1);
    if (p) { memcpy(p, s, len); p[len] = '\0'; }
    return p;
}
#endif

#include <nghttp2/nghttp2.h>
/* Compile against the bundled QuickJS from circu.js deps */
#define FOREIGN_QJS
#include <quickjs.h>
#include <cutils.h>
#include <tjs.h>   /* DEF_MODULE, TJSModuleInfo, TJS_EXPORT */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Callback indices ─────────────────────────────────────────── */
typedef enum {
    H2_CB_SEND = 0,  /* (Uint8Array)                                          */
    H2_CB_STREAM = 1,  /* (streamId, headers, flags)                            */
    H2_CB_HEADERS = 2,  /* (streamId, headers, flags) trailers                   */
    H2_CB_DATA = 3,  /* (streamId, Uint8Array, endStream)                     */
    H2_CB_CLOSE = 4,  /* (streamId, errorCode)                                 */
    H2_CB_GOAWAY = 5,  /* (errorCode, lastStreamId, Uint8Array|null)             */
    H2_CB_SETTINGS = 6,  /* (isAck)                                               */
    H2_CB_PING = 7,  /* (isAck, Uint8Array payload)                           */
    H2_CB_PUSH = 8,  /* (streamId, promisedStreamId, headers)                 */
    H2_CB_WND = 9,  /* (streamId, delta) streamId=0 → connection level       */
    H2_CB_FRAME = 10, /* (frameType, streamId, flags) raw recv, debug          */
    H2_CB_FRAMESENT = 11, /* (frameType, streamId, flags) raw send, debug          */
    H2_CB_ERROR = 12, /* (errorCode, msg)                                      */
    H2_CB_COUNT
} H2CallbackIndex;

/* ── Getter magic ─────────────────────────────────────────────── */
typedef enum {
    H2_GET_WANT_READ = 0,
    H2_GET_WANT_WRITE = 1,
    H2_GET_NEXT_SID = 2,
    H2_GET_LOCAL_WND = 3,
    H2_GET_REMOTE_WND = 4,
} H2GetterMagic;

/* ── Per-stream state ─────────────────────────────────────────── */
typedef struct {
    JSContext* ctx;
    JSValue    userdata;
    JSValue    headers;  /* accumulates pairs during HEADERS frame */
    uint32_t   hcount;
} H2StreamData;

/* ── Session ──────────────────────────────────────────────────── */
typedef struct {
    nghttp2_session* ngsession;
    JSContext* ctx;
    JSValue          callbacks[H2_CB_COUNT]; /* fn or [fn, thisArg] */
    int              is_server;
} H2Session;

/* ── tjs-style callback invoke ────────────────────────────────── */
static inline JSValue h2_call_cb(JSContext* ctx, JSValue cb,
    int argc, JSValue* argv) {
    if (JS_IsFunction(ctx, cb))
        return JS_Call(ctx, cb, JS_UNDEFINED, argc, argv);
    if (!JS_IsArray(cb))
        return JS_UNDEFINED;
    JSValue fn = JS_GetPropertyUint32(ctx, cb, 0);
    JSValue self = JS_GetPropertyUint32(ctx, cb, 1);
    JSValue ret = JS_Call(ctx, fn, self, argc, argv);
    JS_FreeValue(ctx, fn);
    JS_FreeValue(ctx, self);
    return ret;
}

#define H2_CALL(s, idx, argc, argv) \
    do { \
        JSValue _r = h2_call_cb((s)->ctx, (s)->callbacks[idx], argc, argv); \
        if (JS_IsException(_r)) TJS_DumpException((s)->ctx); \
        JS_FreeValue((s)->ctx, _r); \
    } while(0)

/* nghttp2 send callback → onsend, no intermediate buffer */
static inline ssize_t h2_cb_send(nghttp2_session* ng, const uint8_t* data,
    size_t len, int flags, void* ud) {
    (void) ng; (void) flags;
    H2Session* s = ud;
    JSValue    buf = JS_NewArrayBufferCopy(s->ctx, data, len);
    H2_CALL(s, H2_CB_SEND, 1, &buf);
    JS_FreeValue(s->ctx, buf);
    return (ssize_t) len;
}

/* ── Header conversion ────────────────────────────────────────── */

static inline JSValue h2_headers_to_js(JSContext* ctx,
    const nghttp2_nv* nva, size_t nvlen) {
    JSValue arr = JS_NewArray(ctx);
    for (uint32_t i = 0; i < (uint32_t) nvlen; i++) {
        JSValue pair = JS_NewArray(ctx);
        JS_SetPropertyUint32(ctx, pair, 0,
            JS_NewStringLen(ctx, (const char*) nva[i].name, nva[i].namelen));
        JS_SetPropertyUint32(ctx, pair, 1,
            JS_NewStringLen(ctx, (const char*) nva[i].value, nva[i].valuelen));
        JS_SetPropertyUint32(ctx, arr, i, pair);
    }
    return arr;
}

/* caller must h2_free_nva() */
static inline nghttp2_nv* h2_headers_from_js(JSContext* ctx, JSValue arr,
    size_t* out_len) {
    JSValue  lv = JS_GetPropertyStr(ctx, arr, "length");
    uint32_t len; JS_ToUint32(ctx, &len, lv); JS_FreeValue(ctx, lv);

    nghttp2_nv* nva = calloc(len, sizeof(nghttp2_nv));
    if (!nva) { *out_len = 0; return NULL; }

    for (uint32_t i = 0; i < len; i++) {
        JSValue pair = JS_GetPropertyUint32(ctx, arr, i);
        JSValue name = JS_GetPropertyUint32(ctx, pair, 0);
        JSValue val = JS_GetPropertyUint32(ctx, pair, 1);
        size_t nl, vl;
        const char* ns = JS_ToCStringLen(ctx, &nl, name);
        const char* vs = JS_ToCStringLen(ctx, &vl, val);
        nva[i].name = (uint8_t*) strndup(ns, nl); nva[i].namelen = nl;
        nva[i].value = (uint8_t*) strndup(vs, vl); nva[i].valuelen = vl;
        nva[i].flags = NGHTTP2_NV_FLAG_NONE;
        JS_FreeCString(ctx, ns); JS_FreeCString(ctx, vs);
        JS_FreeValue(ctx, name); JS_FreeValue(ctx, val);
        JS_FreeValue(ctx, pair);
    }
    *out_len = len;
    return nva;
}

static inline void h2_free_nva(nghttp2_nv* nva, size_t len) {
    for (size_t i = 0; i < len; i++) { free(nva[i].name); free(nva[i].value); }
    free(nva);
}

extern JSClassID h2session_class_id;
void h2_ns_init(JSContext* ctx, JSValue ns);

#endif /* NGHTTP2_CIRCU_H */
