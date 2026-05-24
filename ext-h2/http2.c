/**
 * Circu.js External Module: HTTP/2 support
 *
 * Copyright (c) 2026 iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "http2.h"

JSClassID h2session_class_id;

/* ── Helpers ──────────────────────────────────────────────────── */

static uint8_t *unpack_buffer(JSContext *ctx, JSValue v,
                               size_t *len, JSValue *ab_out) {
    *ab_out = JS_UNDEFINED;
    uint8_t *p = JS_GetArrayBuffer(ctx, len, v);
    if (p) return p;
    JS_FreeValue(ctx, JS_GetException(ctx));
    size_t off, blen;
    JSValue ab = JS_GetTypedArrayBuffer(ctx, v, &off, &blen, NULL);
    if (JS_IsException(ab)) return NULL;
    size_t ablen;
    p = JS_GetArrayBuffer(ctx, &ablen, ab);
    if (!p) { JS_FreeValue(ctx, ab); return NULL; }
    *ab_out = ab; *len = blen;
    return p + off;
}

static inline H2Session *h2_get(JSContext *ctx, JSValue v) {
    return JS_GetOpaque2(ctx, v, h2session_class_id);
}

/* ── H2StreamData ─────────────────────────────────────────────── */

static H2StreamData *sd_new(JSContext *ctx) {
    H2StreamData *sd = calloc(1, sizeof(*sd));
    if (!sd) return NULL;
    sd->ctx      = ctx;
    sd->userdata = JS_UNDEFINED;
    sd->headers  = JS_NewArray(ctx);
    return sd;
}

static void sd_free(H2StreamData *sd) {
    if (!sd) return;
    JS_FreeValue(sd->ctx, sd->userdata);
    JS_FreeValue(sd->ctx, sd->headers);
    free(sd);
}

static void sd_reset_headers(H2StreamData *sd) {
    JS_FreeValue(sd->ctx, sd->headers);
    sd->headers = JS_NewArray(sd->ctx);
    sd->hcount  = 0;
}

/* ── nghttp2 callbacks ────────────────────────────────────────── */

static int cb_begin_headers(nghttp2_session *ng, const nghttp2_frame *frame,
                             void *ud) {
    if (frame->hd.type != NGHTTP2_HEADERS &&
        frame->hd.type != NGHTTP2_PUSH_PROMISE) return 0;
    H2Session    *s  = ud;
    H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
    if (!sd) {
        sd = sd_new(s->ctx);
        if (!sd) return NGHTTP2_ERR_CALLBACK_FAILURE;
        nghttp2_session_set_stream_user_data(ng, frame->hd.stream_id, sd);
    } else {
        sd_reset_headers(sd);
    }
    return 0;
}

static int cb_on_header(nghttp2_session *ng, const nghttp2_frame *frame,
                         const uint8_t *name, size_t nlen,
                         const uint8_t *value, size_t vlen,
                         uint8_t flags, void *ud) {
    (void)flags; (void)ud;
    H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, frame->hd.stream_id);
    if (!sd) return 0;
    JSContext *ctx = sd->ctx;
    JSValue pair   = JS_NewArray(ctx);
    JS_SetPropertyUint32(ctx, pair, 0, JS_NewStringLen(ctx, (const char *)name,  nlen));
    JS_SetPropertyUint32(ctx, pair, 1, JS_NewStringLen(ctx, (const char *)value, vlen));
    JS_SetPropertyUint32(ctx, sd->headers, sd->hcount++, pair);
    return 0;
}

static int cb_frame_recv(nghttp2_session *ng, const nghttp2_frame *frame,
                          void *ud) {
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    int32_t    sid = frame->hd.stream_id;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS: {
        H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, sid);
        if (!sd) break;
        H2CallbackIndex idx = (frame->headers.cat == NGHTTP2_HCAT_HEADERS)
                              ? H2_CB_HEADERS : H2_CB_STREAM;
        JSValue argv[3] = { JS_NewInt32(ctx, sid),
                            JS_DupValue(ctx, sd->headers),
                            JS_NewInt32(ctx, frame->hd.flags) };
        H2_CALL(s, idx, 3, argv);
        for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
        break;
    }
    case NGHTTP2_SETTINGS: {
        JSValue v = JS_NewBool(ctx, frame->hd.flags & NGHTTP2_FLAG_ACK);
        H2_CALL(s, H2_CB_SETTINGS, 1, &v); JS_FreeValue(ctx, v);
        break;
    }
    case NGHTTP2_PING: {
        JSValue argv[2] = { JS_NewBool(ctx,  frame->hd.flags & NGHTTP2_FLAG_ACK),
                            JS_NewArrayBufferCopy(ctx, frame->ping.opaque_data, 8) };
        H2_CALL(s, H2_CB_PING, 2, argv);
        JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
        break;
    }
    case NGHTTP2_GOAWAY: {
        JSValue opaque = frame->goaway.opaque_data_len
            ? JS_NewArrayBufferCopy(ctx, frame->goaway.opaque_data,
                                    frame->goaway.opaque_data_len)
            : JS_NULL;
        JSValue argv[3] = { JS_NewInt32(ctx, (int32_t)frame->goaway.error_code),
                            JS_NewInt32(ctx, frame->goaway.last_stream_id),
                            opaque };
        H2_CALL(s, H2_CB_GOAWAY, 3, argv);
        for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
        break;
    }
    case NGHTTP2_WINDOW_UPDATE: {
        JSValue argv[2] = { JS_NewInt32(ctx, sid),
                            JS_NewInt32(ctx, frame->window_update.window_size_increment) };
        H2_CALL(s, H2_CB_WND, 2, argv);
        JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
        break;
    }
    case NGHTTP2_PUSH_PROMISE: {
        int32_t       pid = frame->push_promise.promised_stream_id;
        H2StreamData *sd  = nghttp2_session_get_stream_user_data(ng, pid);
        JSValue argv[3] = { JS_NewInt32(ctx, sid),
                            JS_NewInt32(ctx, pid),
                            sd ? JS_DupValue(ctx, sd->headers) : JS_NewArray(ctx) };
        H2_CALL(s, H2_CB_PUSH, 3, argv);
        for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
        break;
    }
    default: break;
    }

    /* raw frame debug — pass numeric type directly, zero alloc */
    JSValue raw[3] = { JS_NewInt32(ctx, frame->hd.type),
                       JS_NewInt32(ctx, sid),
                       JS_NewInt32(ctx, frame->hd.flags) };
    H2_CALL(s, H2_CB_FRAME, 3, raw);
    for (int i = 0; i < 3; i++) JS_FreeValue(ctx, raw[i]);
    return 0;
}

static int cb_frame_send(nghttp2_session *ng, const nghttp2_frame *frame,
                          void *ud) {
    (void)ng;
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    JSValue argv[3] = { JS_NewInt32(ctx, frame->hd.type),
                        JS_NewInt32(ctx, frame->hd.stream_id),
                        JS_NewInt32(ctx, frame->hd.flags) };
    H2_CALL(s, H2_CB_FRAMESENT, 3, argv);
    for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
    return 0;
}

static int cb_data_chunk(nghttp2_session *ng, uint8_t flags, int32_t sid,
                          const uint8_t *data, size_t len, void *ud) {
    (void)ng;
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    JSValue argv[3] = { JS_NewInt32(ctx, sid),
                        JS_NewArrayBufferCopy(ctx, data, len),
                        JS_NewBool(ctx, flags & NGHTTP2_FLAG_END_STREAM) };
    H2_CALL(s, H2_CB_DATA, 3, argv);
    for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
    return 0;
}

static int cb_stream_close(nghttp2_session *ng, int32_t sid,
                            uint32_t error_code, void *ud) {
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    sd_free(nghttp2_session_get_stream_user_data(ng, sid));
    nghttp2_session_set_stream_user_data(ng, sid, NULL);
    JSValue argv[2] = { JS_NewInt32(ctx, sid),
                        JS_NewInt32(ctx, (int32_t)error_code) };
    H2_CALL(s, H2_CB_CLOSE, 2, argv);
    JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
    return 0;
}

static int cb_error(nghttp2_session *ng, int code,
                    const char *msg, size_t len, void *ud) {
    (void)ng;
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    JSValue argv[2] = { JS_NewInt32(ctx, code),
                        JS_NewStringLen(ctx, msg, len) };
    H2_CALL(s, H2_CB_ERROR, 2, argv);
    JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
    return 0;
}

/* ── Class lifecycle ──────────────────────────────────────────── */

static void h2session_finalizer(JSRuntime *rt, JSValue val) {
    H2Session *s = JS_GetOpaque(val, h2session_class_id);
    if (!s) return;
    if (s->ngsession) nghttp2_session_del(s->ngsession);
    for (int i = 0; i < H2_CB_COUNT; i++) JS_FreeValueRT(rt, s->callbacks[i]);
    free(s);
}

static JSClassDef h2session_class = {
    "Session", .finalizer = h2session_finalizer
};

/* ── Constructor ──────────────────────────────────────────────── */

static JSValue js_h2_ctor(JSContext *ctx, JSValue new_target,
                           int argc, JSValue *argv) {
    (void)new_target;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Session(isServer[, settings])");
    H2Session *s = calloc(1, sizeof(*s));
    if (!s) return JS_ThrowOutOfMemory(ctx);
    s->ctx       = ctx;
    s->is_server = JS_ToBool(ctx, argv[0]);
    for (int i = 0; i < H2_CB_COUNT; i++) s->callbacks[i] = JS_NULL;

    nghttp2_session_callbacks *cbs;
    nghttp2_session_callbacks_new(&cbs);
    nghttp2_session_callbacks_set_send_callback(cbs,               h2_cb_send);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs,   cb_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs,          cb_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,      cb_frame_recv);
    nghttp2_session_callbacks_set_on_frame_send_callback(cbs,      cb_frame_send);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, cb_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs,    cb_stream_close);
    nghttp2_session_callbacks_set_error_callback2(cbs,             cb_error);

    nghttp2_settings_entry iv[6]; int niv = 0;
    if (argc >= 2 && JS_IsObject(argv[1])) {
        JSValue v; uint32_t u;
#define S(key, id) v = JS_GetPropertyStr(ctx, argv[1], key); \
        if (!JS_IsUndefined(v)) { JS_ToUint32(ctx,&u,v); \
            iv[niv].settings_id=id; iv[niv++].value=u; } JS_FreeValue(ctx,v);
        S("headerTableSize",      NGHTTP2_SETTINGS_HEADER_TABLE_SIZE)
        S("maxConcurrentStreams", NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)
        S("initialWindowSize",    NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)
        S("maxFrameSize",         NGHTTP2_SETTINGS_MAX_FRAME_SIZE)
        S("maxHeaderListSize",    NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE)
#undef S
        JSValue vp = JS_GetPropertyStr(ctx, argv[1], "enablePush");
        if (!JS_IsUndefined(vp)) {
            iv[niv].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
            iv[niv++].value     = JS_ToBool(ctx, vp) ? 1 : 0;
        }
        JS_FreeValue(ctx, vp);
    }

    int rc = s->is_server
        ? nghttp2_session_server_new(&s->ngsession, cbs, s)
        : nghttp2_session_client_new(&s->ngsession, cbs, s);
    nghttp2_session_callbacks_del(cbs);
    if (rc) { free(s); return JS_ThrowInternalError(ctx, ": %s", nghttp2_strerror(rc)); }

    nghttp2_submit_settings(s->ngsession, NGHTTP2_FLAG_NONE, niv ? iv : NULL, niv);
    nghttp2_session_send(s->ngsession);

    JSValue obj = JS_NewObjectClass(ctx, h2session_class_id);
    JS_SetOpaque(obj, s);
    return obj;
}

/* ── Methods ──────────────────────────────────────────────────── */

static JSValue js_h2_receive(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    JSValue ab; size_t len;
    uint8_t *buf = unpack_buffer(ctx, argv[0], &len, &ab);
    if (!buf) return JS_ThrowTypeError(ctx, "expected ArrayBuffer/TypedArray");
    int rc = nghttp2_session_mem_recv(s->ngsession, buf, len);
    JS_FreeValue(ctx, ab);
    if (rc < 0) return JS_ThrowInternalError(ctx, "mem_recv: %s", nghttp2_strerror(rc));
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_request(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    size_t nvlen; nghttp2_nv *nva = h2_headers_from_js(ctx, argv[0], &nvlen);
    uint8_t flags = (argc >= 2 && JS_ToBool(ctx, argv[1]))
                    ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;
    int32_t id = nghttp2_submit_headers(s->ngsession, flags, -1, NULL, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (id < 0) return JS_ThrowInternalError(ctx, "request: %s", nghttp2_strerror(id));
    nghttp2_session_send(s->ngsession);
    return JS_NewInt32(ctx, id);
}

static JSValue js_h2_respond(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    size_t nvlen; nghttp2_nv *nva = h2_headers_from_js(ctx, argv[1], &nvlen);
    uint8_t flags = (argc >= 3 && JS_ToBool(ctx, argv[2]))
                    ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;
    int rc = nghttp2_submit_headers(s->ngsession, flags, sid, NULL, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (rc < 0) return JS_ThrowInternalError(ctx, "respond: %s", nghttp2_strerror(rc));
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_push(JSContext *ctx, JSValue this_val,
                           int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    size_t nvlen; nghttp2_nv *nva = h2_headers_from_js(ctx, argv[1], &nvlen);
    int32_t pid = nghttp2_submit_push_promise(s->ngsession, NGHTTP2_FLAG_NONE,
                                               sid, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (pid < 0) return JS_ThrowInternalError(ctx, "push: %s", nghttp2_strerror(pid));
    nghttp2_session_send(s->ngsession);
    return JS_NewInt32(ctx, pid);
}

typedef struct { const uint8_t *data; size_t len; size_t off; } H2DataSrc;

static ssize_t data_read_cb(nghttp2_session *ng, int32_t sid, uint8_t *buf,
                              size_t length, uint32_t *data_flags,
                              nghttp2_data_source *src, void *ud) {
    (void)ng; (void)sid; (void)ud;
    H2DataSrc *ds = src->ptr;
    size_t n = ds->len - ds->off; if (n > length) n = length;
    memcpy(buf, ds->data + ds->off, n); ds->off += n;
    if (ds->off >= ds->len) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (ssize_t)n;
}

static JSValue js_h2_write(JSContext *ctx, JSValue this_val,
                            int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    JSValue ab; size_t len;
    uint8_t *buf = unpack_buffer(ctx, argv[1], &len, &ab);
    if (!buf) return JS_ThrowTypeError(ctx, "expected ArrayBuffer/TypedArray");
    uint8_t flags = (argc >= 3 && JS_ToBool(ctx, argv[2]))
                    ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;
    H2DataSrc ds = { buf, len, 0 };
    nghttp2_data_provider dp = { .source.ptr = &ds, .read_callback = data_read_cb };
    int rc = nghttp2_submit_data(s->ngsession, flags, sid, &dp);
    JS_FreeValue(ctx, ab);
    if (rc < 0) return JS_ThrowInternalError(ctx, "write: %s", nghttp2_strerror(rc));
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_trailers(JSContext *ctx, JSValue this_val,
                               int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    size_t nvlen; nghttp2_nv *nva = h2_headers_from_js(ctx, argv[1], &nvlen);
    int rc = nghttp2_submit_headers(s->ngsession, NGHTTP2_FLAG_END_STREAM,
                                    sid, NULL, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (rc < 0) return JS_ThrowInternalError(ctx, "trailers: %s", nghttp2_strerror(rc));
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_reset(JSContext *ctx, JSValue this_val,
                            int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; uint32_t code = NGHTTP2_NO_ERROR;
    JS_ToInt32(ctx, &sid, argv[0]);
    if (argc >= 2) JS_ToUint32(ctx, &code, argv[1]);
    nghttp2_submit_rst_stream(s->ngsession, NGHTTP2_FLAG_NONE, sid, code);
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_wnd_update(JSContext *ctx, JSValue this_val,
                                 int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid, delta;
    JS_ToInt32(ctx, &sid,   argv[0]);
    JS_ToInt32(ctx, &delta, argv[1]);
    nghttp2_submit_window_update(s->ngsession, NGHTTP2_FLAG_NONE, sid, delta);
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_ping(JSContext *ctx, JSValue this_val,
                           int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    uint8_t payload[8] = {0};
    if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        JSValue ab; size_t len;
        uint8_t *buf = unpack_buffer(ctx, argv[0], &len, &ab);
        if (buf) memcpy(payload, buf, len < 8 ? len : 8);
        JS_FreeValue(ctx, ab);
    }
    uint8_t flags = (argc >= 2 && JS_ToBool(ctx, argv[1]))
                    ? NGHTTP2_FLAG_ACK : NGHTTP2_FLAG_NONE;
    nghttp2_submit_ping(s->ngsession, flags, payload);
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_configure(JSContext *ctx, JSValue this_val,
                                int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession || argc < 1) return JS_UNDEFINED;
    nghttp2_settings_entry iv[6]; int niv = 0;
    JSValue v; uint32_t u;
#define S(key, id) v=JS_GetPropertyStr(ctx,argv[0],key); \
    if(!JS_IsUndefined(v)){JS_ToUint32(ctx,&u,v); \
        iv[niv].settings_id=id;iv[niv++].value=u;} JS_FreeValue(ctx,v);
    S("headerTableSize",      NGHTTP2_SETTINGS_HEADER_TABLE_SIZE)
    S("maxConcurrentStreams", NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)
    S("initialWindowSize",    NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE)
    S("maxFrameSize",         NGHTTP2_SETTINGS_MAX_FRAME_SIZE)
    S("maxHeaderListSize",    NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE)
#undef S
    if (!niv) return JS_UNDEFINED;
    nghttp2_submit_settings(s->ngsession, NGHTTP2_FLAG_NONE, iv, niv);
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_goaway(JSContext *ctx, JSValue this_val,
                             int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    uint32_t code = NGHTTP2_NO_ERROR;
    uint8_t *opaque = NULL; size_t opaque_len = 0;
    if (argc >= 1) JS_ToUint32(ctx, &code, argv[0]);
    if (argc >= 2) { JSValue ab; opaque = unpack_buffer(ctx, argv[1], &opaque_len, &ab); JS_FreeValue(ctx, ab); }
    int32_t last = nghttp2_session_get_last_proc_stream_id(s->ngsession);
    nghttp2_submit_goaway(s->ngsession, NGHTTP2_FLAG_NONE, last, code, opaque, opaque_len);
    nghttp2_session_send(s->ngsession);
    return JS_UNDEFINED;
}

static JSValue js_h2_destroy(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)argc; (void)argv;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    nghttp2_session_del(s->ngsession);
    s->ngsession = NULL;
    return JS_UNDEFINED;
}

/* ── Stream tag (user data) ───────────────────────────────────── */

static JSValue js_h2_set_tag(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    H2StreamData *sd = nghttp2_session_get_stream_user_data(s->ngsession, sid);
    if (!sd) return JS_UNDEFINED;
    JS_FreeValue(ctx, sd->userdata);
    sd->userdata = JS_DupValue(ctx, argv[1]);
    return JS_UNDEFINED;
}

static JSValue js_h2_get_tag(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    H2StreamData *sd = nghttp2_session_get_stream_user_data(s->ngsession, sid);
    return sd ? JS_DupValue(ctx, sd->userdata) : JS_UNDEFINED;
}

/* ── Info ─────────────────────────────────────────────────────── */

static JSValue js_h2_stream_info(JSContext *ctx, JSValue this_val,
                                  int argc, JSValue *argv) {
    (void)argc;
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_NULL;
    int32_t sid; JS_ToInt32(ctx, &sid, argv[0]);
    nghttp2_stream *st = nghttp2_session_find_stream(s->ngsession, sid);
    if (!st) return JS_NULL;
    JSValue o = JS_NewObject(ctx);
#define SET(k,v) JS_SetPropertyStr(ctx, o, k, v)
    SET("state",        JS_NewInt32(ctx, nghttp2_stream_get_state(st)));
    SET("weight",       JS_NewInt32(ctx, nghttp2_stream_get_weight(st)));
    SET("depWeight",    JS_NewInt32(ctx, nghttp2_stream_get_sum_dependency_weight(st)));
    SET("localWnd",     JS_NewInt32(ctx, nghttp2_session_get_stream_local_window_size(s->ngsession,  sid)));
    SET("remoteWnd",    JS_NewInt32(ctx, nghttp2_session_get_stream_remote_window_size(s->ngsession, sid)));
#undef SET
    return o;
}

/* ── Live getters ─────────────────────────────────────────────── */

static JSValue js_h2_getter(JSContext *ctx, JSValue this_val, int magic) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s || !s->ngsession) return JS_UNDEFINED;
    switch ((H2GetterMagic)magic) {
    case H2_GET_WANT_READ:  return JS_NewBool(ctx,  nghttp2_session_want_read(s->ngsession));
    case H2_GET_WANT_WRITE: return JS_NewBool(ctx,  nghttp2_session_want_write(s->ngsession));
    case H2_GET_NEXT_SID:   return JS_NewInt32(ctx, nghttp2_session_get_next_stream_id(s->ngsession));
    case H2_GET_LOCAL_WND:  return JS_NewInt32(ctx, nghttp2_session_get_local_window_size(s->ngsession));
    case H2_GET_REMOTE_WND: return JS_NewInt32(ctx, nghttp2_session_get_remote_window_size(s->ngsession));
    }
    return JS_UNDEFINED;
}

/* ── Callback getters/setters ─────────────────────────────────── */

static JSValue js_h2_get_cb(JSContext *ctx, JSValue this_val, int magic) {
    H2Session *s = h2_get(ctx, this_val);
    return s ? JS_DupValue(ctx, s->callbacks[magic]) : JS_UNDEFINED;
}

static JSValue js_h2_set_cb(JSContext *ctx, JSValue this_val,
                              JSValue val, int magic) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_UNDEFINED;
    JS_FreeValue(ctx, s->callbacks[magic]);
    s->callbacks[magic] = JS_DupValue(ctx, val);
    return JS_UNDEFINED;
}

/* ── Prototype ────────────────────────────────────────────────── */

static const JSCFunctionListEntry h2_proto[] = {
    JS_CFUNC_DEF("receive",   1, js_h2_receive),
    JS_CFUNC_DEF("request",   2, js_h2_request),
    JS_CFUNC_DEF("respond",   3, js_h2_respond),
    JS_CFUNC_DEF("push",      2, js_h2_push),
    JS_CFUNC_DEF("write",     3, js_h2_write),
    JS_CFUNC_DEF("trailers",  2, js_h2_trailers),
    JS_CFUNC_DEF("reset",     2, js_h2_reset),
    JS_CFUNC_DEF("wndUpdate", 2, js_h2_wnd_update),
    JS_CFUNC_DEF("ping",      2, js_h2_ping),
    JS_CFUNC_DEF("configure", 1, js_h2_configure),
    JS_CFUNC_DEF("goaway",    2, js_h2_goaway),
    JS_CFUNC_DEF("destroy",   0, js_h2_destroy),
    JS_CFUNC_DEF("setTag",    2, js_h2_set_tag),
    JS_CFUNC_DEF("getTag",    1, js_h2_get_tag),
    JS_CFUNC_DEF("streamInfo",1, js_h2_stream_info),
    /* live getters */
    JS_CGETSET_MAGIC_DEF("wantRead",    js_h2_getter, NULL, H2_GET_WANT_READ),
    JS_CGETSET_MAGIC_DEF("wantWrite",   js_h2_getter, NULL, H2_GET_WANT_WRITE),
    JS_CGETSET_MAGIC_DEF("nextStreamId",js_h2_getter, NULL, H2_GET_NEXT_SID),
    JS_CGETSET_MAGIC_DEF("localWnd",    js_h2_getter, NULL, H2_GET_LOCAL_WND),
    JS_CGETSET_MAGIC_DEF("remoteWnd",   js_h2_getter, NULL, H2_GET_REMOTE_WND),
    /* callbacks */
    JS_CGETSET_MAGIC_DEF("onsend",      js_h2_get_cb, js_h2_set_cb, H2_CB_SEND),
    JS_CGETSET_MAGIC_DEF("onstream",    js_h2_get_cb, js_h2_set_cb, H2_CB_STREAM),
    JS_CGETSET_MAGIC_DEF("onheaders",   js_h2_get_cb, js_h2_set_cb, H2_CB_HEADERS),
    JS_CGETSET_MAGIC_DEF("ondata",      js_h2_get_cb, js_h2_set_cb, H2_CB_DATA),
    JS_CGETSET_MAGIC_DEF("onclose",     js_h2_get_cb, js_h2_set_cb, H2_CB_CLOSE),
    JS_CGETSET_MAGIC_DEF("ongoaway",    js_h2_get_cb, js_h2_set_cb, H2_CB_GOAWAY),
    JS_CGETSET_MAGIC_DEF("onsettings",  js_h2_get_cb, js_h2_set_cb, H2_CB_SETTINGS),
    JS_CGETSET_MAGIC_DEF("onping",      js_h2_get_cb, js_h2_set_cb, H2_CB_PING),
    JS_CGETSET_MAGIC_DEF("onpush",      js_h2_get_cb, js_h2_set_cb, H2_CB_PUSH),
    JS_CGETSET_MAGIC_DEF("onwnd",       js_h2_get_cb, js_h2_set_cb, H2_CB_WND),
    JS_CGETSET_MAGIC_DEF("onframe",     js_h2_get_cb, js_h2_set_cb, H2_CB_FRAME),
    JS_CGETSET_MAGIC_DEF("onframesent", js_h2_get_cb, js_h2_set_cb, H2_CB_FRAMESENT),
    JS_CGETSET_MAGIC_DEF("onerror",     js_h2_get_cb, js_h2_set_cb, H2_CB_ERROR),
};

/* ── Constants ────────────────────────────────────────────────── */

static JSValue make_constants(JSContext *ctx) {
    JSValue o = JS_NewObject(ctx);
    // strip all NGHTTP2_ prefix
#define C(x) JS_SetPropertyStr(ctx, o, #x +8, JS_NewInt32(ctx, x))
    C(NGHTTP2_NO_ERROR); C(NGHTTP2_PROTOCOL_ERROR); C(NGHTTP2_INTERNAL_ERROR);
    C(NGHTTP2_FLOW_CONTROL_ERROR); C(NGHTTP2_SETTINGS_TIMEOUT);
    C(NGHTTP2_STREAM_CLOSED); C(NGHTTP2_FRAME_SIZE_ERROR);
    C(NGHTTP2_REFUSED_STREAM); C(NGHTTP2_CANCEL); C(NGHTTP2_COMPRESSION_ERROR);
    C(NGHTTP2_CONNECT_ERROR); C(NGHTTP2_ENHANCE_YOUR_CALM);
    C(NGHTTP2_INADEQUATE_SECURITY); C(NGHTTP2_HTTP_1_1_REQUIRED);
    C(NGHTTP2_FLAG_NONE); C(NGHTTP2_FLAG_END_STREAM); C(NGHTTP2_FLAG_END_HEADERS);
    C(NGHTTP2_FLAG_PADDED); C(NGHTTP2_FLAG_PRIORITY); C(NGHTTP2_FLAG_ACK);
    C(NGHTTP2_DATA); C(NGHTTP2_HEADERS); C(NGHTTP2_PRIORITY);
    C(NGHTTP2_RST_STREAM); C(NGHTTP2_SETTINGS); C(NGHTTP2_PUSH_PROMISE);
    C(NGHTTP2_PING); C(NGHTTP2_GOAWAY); C(NGHTTP2_WINDOW_UPDATE);
    C(NGHTTP2_CONTINUATION); C(NGHTTP2_ALTSVC); C(NGHTTP2_ORIGIN);
    C(NGHTTP2_STREAM_STATE_IDLE); C(NGHTTP2_STREAM_STATE_OPEN);
    C(NGHTTP2_STREAM_STATE_RESERVED_LOCAL); C(NGHTTP2_STREAM_STATE_RESERVED_REMOTE);
    C(NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL); C(NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE);
    C(NGHTTP2_STREAM_STATE_CLOSED);
    C(NGHTTP2_NV_FLAG_NONE); C(NGHTTP2_NV_FLAG_NO_INDEX);
    C(NGHTTP2_NV_FLAG_NO_COPY_NAME); C(NGHTTP2_NV_FLAG_NO_COPY_VALUE);
#undef C
    return o;
}

/* ── Module init ──────────────────────────────────────────────────
 * Init function is exposed (non-static) so it can be statically
 * linked into a host like cno-cli. When CJS_STATIC_LINK is defined,
 * we skip DEF_MODULE — its emitted `tjs_module_info` symbol would
 * collide with other statically linked extensions in the same binary.
 */

void h2_ns_init(JSContext *ctx, JSValue ns) {
    JSRuntime* rt = JS_GetRuntime(ctx);
    JS_NewClassID(rt, &h2session_class_id);
    JS_NewClass(JS_GetRuntime(ctx), h2session_class_id, &h2session_class);

    JSValue proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, proto, h2_proto, countof(h2_proto));

    JSValue ctor = JS_NewCFunction2(ctx, js_h2_ctor, "Session", 2,
                                    JS_CFUNC_constructor, 0);
    JS_SetConstructor(ctx, ctor, proto);
    JS_SetClassProto(ctx, h2session_class_id, proto);

    JS_SetPropertyStr(ctx, ns, "Session",   ctor);
    JS_SetPropertyStr(ctx, ns, "constants", make_constants(ctx));
}

#ifndef CJS_STATIC_LINK
DEF_MODULE("ext:h2", h2_ns_init, false)
#endif
