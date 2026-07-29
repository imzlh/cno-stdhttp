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

typedef struct H2Session H2Session;

/* ── Per-stream state ─────────────────────────────────────────── */
typedef struct H2StreamData {
    JSContext* ctx;
    JSValue    userdata;
    JSValue    headers;  /* accumulates pairs during HEADERS frame */
    uint32_t   hcount;
    int32_t    stream_id;
    H2Session* session;
    struct H2StreamData* next;
} H2StreamData;

typedef struct H2DataSrc {
    uint8_t* data;
    size_t len;
    size_t off;
    int32_t stream_id;
    int eof;
    int submitted;
    int end_stream;
    int retired;
    H2Session* session;
    struct H2DataSrc* next;
} H2DataSrc;

typedef struct H2TrailerSrc {
    int32_t             stream_id;
    nghttp2_nv*         nva;
    size_t              nvlen;
    int                 submitted;
    int                 retired;
    H2Session*          session;
    struct H2TrailerSrc* next;
} H2TrailerSrc;

typedef struct H2HeaderEnd {
    int32_t             stream_id;
    int                 retired;
    H2Session*          session;
    struct H2HeaderEnd* next;
} H2HeaderEnd;

/* ── Session ──────────────────────────────────────────────────── */
struct H2Session {
    nghttp2_session* ngsession;
    JSContext* ctx;
    JSValue          callbacks[H2_CB_COUNT]; /* fn or [fn, thisArg] */
    H2StreamData*    streams;
    H2DataSrc*      data_sources;
    H2TrailerSrc*   trailer_sources;
    H2HeaderEnd*    header_ends;
    unsigned int     operation_depth;
    unsigned int     native_depth;
    int              destroy_pending;
    int              send_pending;
    int              is_server;
};

/* ── tjs-style callback invoke ────────────────────────────────── */
static inline int h2_call_cb(JSContext* ctx, JSValue cb,
    int argc, JSValue* argv) {
    if (JS_HasException(ctx)) return -1;

    JSValue holder = JS_DupValue(ctx, cb);
    JSValue ret = JS_UNDEFINED;
    if (JS_IsFunction(ctx, holder)) {
        ret = JS_Call(ctx, holder, JS_UNDEFINED, argc, argv);
    } else {
        int is_array = JS_IsArray(holder);
        if (is_array <= 0) {
            JS_FreeValue(ctx, holder);
            if (is_array < 0) TJS_DumpException(ctx);
            return 0;
        }
        JSValue fn = JS_GetPropertyUint32(ctx, holder, 0);
        JSValue self = JS_UNDEFINED;
        if (!JS_IsException(fn)) self = JS_GetPropertyUint32(ctx, holder, 1);
        if (!JS_IsException(fn) && !JS_IsException(self))
            ret = JS_Call(ctx, fn, self, argc, argv);
        JS_FreeValue(ctx, fn);
        JS_FreeValue(ctx, self);
    }
    JS_FreeValue(ctx, holder);
    if (JS_IsException(ret) || JS_HasException(ctx))
        TJS_DumpException(ctx);
    JS_FreeValue(ctx, ret);
    return 0;
}

static inline int h2_callback_is_set(JSContext* ctx, JSValue cb) {
    if (JS_IsFunction(ctx, cb)) return 1;
    int is_array = JS_IsArray(cb);
    if (is_array <= 0) return is_array;
    JSValue fn = JS_GetPropertyUint32(ctx, cb, 0);
    if (JS_IsException(fn)) return -1;
    int is_function = JS_IsFunction(ctx, fn);
    JS_FreeValue(ctx, fn);
    if (!is_function)
        return JS_ThrowTypeError(ctx, "callback tuple must contain a function"), -1;
    return 1;
}

/* nghttp2 send callback → onsend. Without a handler, WOULDBLOCK so frames
 * stay queued until onsend is set (and flushed), instead of silent drop. */
static inline ssize_t h2_cb_send(nghttp2_session* ng, const uint8_t* data,
    size_t len, int flags, void* ud) {
    (void) ng; (void) flags;
    H2Session* s = ud;
    JSValue cb = JS_DupValue(s->ctx, s->callbacks[H2_CB_SEND]);
    int callback_state = h2_callback_is_set(s->ctx, cb);
    if (callback_state <= 0) {
        JS_FreeValue(s->ctx, cb);
        if (callback_state < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    JSValue buf = JS_NewUint8ArrayCopy(s->ctx, data, len);
    if (JS_IsException(buf)) {
        JS_FreeValue(s->ctx, cb);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    int rc = h2_call_cb(s->ctx, cb, 1, &buf);
    JS_FreeValue(s->ctx, buf);
    JS_FreeValue(s->ctx, cb);
    if (rc < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
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

/* caller must h2_free_nva(); returns -1 with a pending JS exception */
static inline int h2_headers_from_js(JSContext* ctx, JSValue arr,
    nghttp2_nv** out_nva, size_t* out_len) {
    *out_nva = NULL;
    *out_len = 0;
    int is_array = JS_IsArray(arr);
    if (is_array <= 0) {
        if (is_array == 0) JS_ThrowTypeError(ctx, "headers must be an array of [string, string] pairs");
        return -1;
    }

    JSValue lv = JS_GetPropertyStr(ctx, arr, "length");
    uint32_t len = 0;
    if (JS_IsException(lv) || JS_ToUint32(ctx, &len, lv) < 0) {
        JS_FreeValue(ctx, lv);
        return -1;
    }
    JS_FreeValue(ctx, lv);
    if (len == 0) return 0;

    nghttp2_nv* nva = calloc(len, sizeof(*nva));
    if (!nva) { JS_ThrowOutOfMemory(ctx); return -1; }

    for (uint32_t i = 0; i < len; i++) {
        JSValue pair = JS_GetPropertyUint32(ctx, arr, i);
        JSValue name = JS_UNDEFINED;
        JSValue val = JS_UNDEFINED;
        const char* ns = NULL;
        const char* vs = NULL;
        size_t nl = 0, vl = 0;
        int pair_is_array = JS_IsException(pair) ? -1 : JS_IsArray(pair);
        if (pair_is_array <= 0) {
            if (pair_is_array == 0) JS_ThrowTypeError(ctx, "each header must be a [string, string] pair");
            goto fail_item;
        }
        name = JS_GetPropertyUint32(ctx, pair, 0);
        val = JS_GetPropertyUint32(ctx, pair, 1);
        if (JS_IsException(name) || JS_IsException(val)) goto fail_item;
        if (!JS_IsString(name) || !JS_IsString(val)) {
            JS_ThrowTypeError(ctx, "header names and values must be strings");
            goto fail_item;
        }
        ns = JS_ToCStringLen(ctx, &nl, name);
        if (!ns) goto fail_item;
        vs = JS_ToCStringLen(ctx, &vl, val);
        if (!vs) goto fail_item;
        if (memchr(ns, '\0', nl) || memchr(vs, '\0', vl)) {
            JS_ThrowTypeError(ctx, "header names and values must not contain NUL bytes");
            goto fail_item;
        }
        nva[i].name = malloc(nl ? nl : 1);
        nva[i].value = malloc(vl ? vl : 1);
        if (!nva[i].name || !nva[i].value) {
            JS_ThrowOutOfMemory(ctx);
            goto fail_item;
        }
        if (nl) memcpy(nva[i].name, ns, nl);
        if (vl) memcpy(nva[i].value, vs, vl);
        nva[i].namelen = nl;
        nva[i].valuelen = vl;
        nva[i].flags = NGHTTP2_NV_FLAG_NONE;
        JS_FreeCString(ctx, ns);
        JS_FreeCString(ctx, vs);
        JS_FreeValue(ctx, name);
        JS_FreeValue(ctx, val);
        JS_FreeValue(ctx, pair);
        continue;

fail_item:
        if (ns) JS_FreeCString(ctx, ns);
        if (vs) JS_FreeCString(ctx, vs);
        JS_FreeValue(ctx, name);
        JS_FreeValue(ctx, val);
        JS_FreeValue(ctx, pair);
        for (uint32_t j = 0; j <= i; j++) {
            free(nva[j].name);
            free(nva[j].value);
        }
        free(nva);
        return -1;
    }
    *out_nva = nva;
    *out_len = len;
    return 0;
}

static inline void h2_free_nva(nghttp2_nv* nva, size_t len) {
    for (size_t i = 0; i < len; i++) { free(nva[i].name); free(nva[i].value); }
    free(nva);
}

extern _Thread_local JSClassID h2session_class_id;
void h2_ns_init(JSContext* ctx, JSValue ns);

#endif /* NGHTTP2_CIRCU_H */
