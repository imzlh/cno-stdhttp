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

#include <threads.h>

_Thread_local JSClassID h2session_class_id;

static void data_src_free_stream(H2Session *s, int32_t stream_id);
static int data_src_complete_frame(H2Session *s, int32_t stream_id);
static void data_src_free_all(H2Session *s);
static int data_src_submit_pending(H2Session *s, nghttp2_session *ng);
static void trailer_src_free_stream(H2Session *s, int32_t stream_id);
static int trailer_src_complete_frame(H2Session *s, int32_t stream_id);
static void trailer_src_free_all(H2Session *s);
static int trailer_src_submit_pending(H2Session *s, nghttp2_session *ng);
static void pending_src_free_stream(H2Session *s, int32_t stream_id);
static int pending_src_has_terminal(H2Session *s, int32_t stream_id);
static ssize_t data_read_cb(nghttp2_session *ng, int32_t sid, uint8_t *buf,
                            size_t length, uint32_t *data_flags,
                            nghttp2_data_source *src, void *ud);
static int h2_operation_enter(H2Session *s, nghttp2_session **ng);
static void h2_operation_leave(H2Session *s);
static int h2_session_send(H2Session *s, nghttp2_session *ng);
static void h2_destroy_now(H2Session *s);

/* ── Helpers ──────────────────────────────────────────────────── */

static uint8_t *unpack_buffer(JSContext *ctx, JSValue v,
                               size_t *len, JSValue *ab_out) {
    *ab_out = JS_UNDEFINED;
    uint8_t *p = JS_GetArrayBuffer(ctx, len, v);
    if (p) return p;
    if (!JS_HasException(ctx)) return *len == 0 ? (uint8_t *)"" : NULL;
    JSValue array_buffer_error = JS_GetException(ctx);
    JS_FreeValue(ctx, array_buffer_error);
    size_t off, blen;
    JSValue ab = JS_GetTypedArrayBuffer(ctx, v, &off, &blen, NULL);
    if (JS_IsException(ab)) return NULL;
    size_t ablen;
    p = JS_GetArrayBuffer(ctx, &ablen, ab);
    if (!p && (JS_HasException(ctx) || blen != 0)) {
        JS_FreeValue(ctx, ab);
        return NULL;
    }
    if (off > ablen || blen > ablen - off) {
        JS_FreeValue(ctx, ab);
        JS_ThrowRangeError(ctx, "typed array view is outside its buffer");
        return NULL;
    }
    *ab_out = ab; *len = blen;
    return p ? p + off : (uint8_t *)"";
}

static inline H2Session *h2_get(JSContext *ctx, JSValue v) {
    return JS_GetOpaque2(ctx, v, h2session_class_id);
}

/* ── H2StreamData ─────────────────────────────────────────────── */

static H2StreamData *sd_new(H2Session *s, int32_t stream_id) {
    H2StreamData *sd = calloc(1, sizeof(*sd));
    if (!sd) {
        JS_ThrowOutOfMemory(s->ctx);
        return NULL;
    }
    sd->ctx      = s->ctx;
    sd->userdata = JS_UNDEFINED;
    sd->headers  = JS_NewArray(s->ctx);
    if (JS_IsException(sd->headers)) {
        free(sd);
        return NULL;
    }
    sd->stream_id = stream_id;
    sd->session = s;
    sd->next = s->streams;
    s->streams = sd;
    return sd;
}

static void sd_free(H2StreamData *sd) {
    if (!sd) return;
    H2Session *s = sd->session;
    if (s) {
        H2StreamData **link = &s->streams;
        while (*link && *link != sd) link = &(*link)->next;
        if (*link == sd) *link = sd->next;
    }
    JS_FreeValue(sd->ctx, sd->userdata);
    JS_FreeValue(sd->ctx, sd->headers);
    free(sd);
}

static void sd_free_all(H2Session *s) {
    while (s->streams) {
        H2StreamData *sd = s->streams;
        s->streams = sd->next;
        sd->session = NULL;
        sd_free(sd);
    }
}

static void sd_free_all_rt(H2Session *s, JSRuntime *rt) {
    while (s->streams) {
        H2StreamData *sd = s->streams;
        s->streams = sd->next;
        JS_FreeValueRT(rt, sd->userdata);
        JS_FreeValueRT(rt, sd->headers);
        free(sd);
    }
}

static int sd_reset_headers(H2StreamData *sd) {
    JSValue headers = JS_NewArray(sd->ctx);
    if (JS_IsException(headers)) return -1;
    JS_FreeValue(sd->ctx, sd->headers);
    sd->headers = headers;
    sd->hcount  = 0;
    return 0;
}

static H2HeaderEnd *header_end_alloc(void) {
    return calloc(1, sizeof(H2HeaderEnd));
}

static void header_end_link(H2Session *s, H2HeaderEnd *end,
                            int32_t stream_id) {
    end->stream_id = stream_id;
    end->session = s;
    H2HeaderEnd **tail = &s->header_ends;
    while (*tail) tail = &(*tail)->next;
    *tail = end;
}

static void header_end_free(H2HeaderEnd *end) {
    if (!end) return;
    H2Session *s = end->session;
    if (s) {
        H2HeaderEnd **link = &s->header_ends;
        while (*link && *link != end) link = &(*link)->next;
        if (*link == end) *link = end->next;
    }
    free(end);
}

static void header_end_free_stream(H2Session *s, int32_t stream_id) {
    for (H2HeaderEnd *end = s->header_ends; end; end = end->next)
        if (end->stream_id == stream_id) end->retired = 1;
}

static int header_end_complete_frame(H2Session *s, int32_t stream_id) {
    for (H2HeaderEnd *end = s->header_ends; end; end = end->next) {
        if (end->stream_id == stream_id && !end->retired) {
            end->retired = 1;
            return 1;
        }
    }
    return 0;
}

static void header_end_free_all(H2Session *s) {
    while (s->header_ends) {
        H2HeaderEnd *end = s->header_ends;
        s->header_ends = end->next;
        end->session = NULL;
        header_end_free(end);
    }
}

static void header_end_free_retired(H2Session *s) {
    H2HeaderEnd *end = s->header_ends;
    while (end) {
        H2HeaderEnd *next = end->next;
        if (end->retired) header_end_free(end);
        end = next;
    }
}

/* ── nghttp2 callbacks ────────────────────────────────────────── */

static int32_t h2_header_stream_id(const nghttp2_frame *frame) {
    return frame->hd.type == NGHTTP2_PUSH_PROMISE
        ? frame->push_promise.promised_stream_id
        : frame->hd.stream_id;
}

static int cb_begin_headers(nghttp2_session *ng, const nghttp2_frame *frame,
                             void *ud) {
    if (frame->hd.type != NGHTTP2_HEADERS &&
        frame->hd.type != NGHTTP2_PUSH_PROMISE) return 0;
    H2Session *s = ud;
    int32_t stream_id = h2_header_stream_id(frame);
    H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, stream_id);
    if (!sd) {
        sd = sd_new(s, stream_id);
        if (!sd) return NGHTTP2_ERR_CALLBACK_FAILURE;
        if (nghttp2_session_set_stream_user_data(ng, stream_id, sd) < 0) {
            sd_free(sd);
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    } else {
        if (sd_reset_headers(sd) < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int cb_on_header(nghttp2_session *ng, const nghttp2_frame *frame,
                         const uint8_t *name, size_t nlen,
                         const uint8_t *value, size_t vlen,
                         uint8_t flags, void *ud) {
    (void)flags; (void)ud;
    H2StreamData *sd = nghttp2_session_get_stream_user_data(
        ng, h2_header_stream_id(frame));
    if (!sd) return 0;
    JSContext *ctx = sd->ctx;
    JSValue pair = JS_NewArray(ctx);
    if (JS_IsException(pair)) return NGHTTP2_ERR_CALLBACK_FAILURE;
    JSValue js_name = JS_NewStringLen(ctx, (const char *)name, nlen);
    if (JS_IsException(js_name)) {
        JS_FreeValue(ctx, pair);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (JS_SetPropertyUint32(ctx, pair, 0, js_name) < 0) {
        JS_FreeValue(ctx, pair);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    JSValue js_value = JS_NewStringLen(ctx, (const char *)value, vlen);
    if (JS_IsException(js_value)) {
        JS_FreeValue(ctx, pair);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (JS_SetPropertyUint32(ctx, pair, 1, js_value) < 0) {
        JS_FreeValue(ctx, pair);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    if (JS_SetPropertyUint32(ctx, sd->headers, sd->hcount, pair) < 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    sd->hcount++;
    return 0;
}

static int cb_frame_recv(nghttp2_session *ng, const nghttp2_frame *frame,
                          void *ud) {
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    int32_t    sid = frame->hd.stream_id;
    int call_rc = 0;

    switch (frame->hd.type) {
    case NGHTTP2_HEADERS: {
        H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, sid);
        if (!sd) break;
        H2CallbackIndex idx = (frame->headers.cat == NGHTTP2_HCAT_HEADERS)
                              ? H2_CB_HEADERS : H2_CB_STREAM;
        JSValue argv[3] = { JS_NewInt32(ctx, sid),
                            JS_DupValue(ctx, sd->headers),
                            JS_NewInt32(ctx, frame->hd.flags) };
        call_rc = h2_call_cb(ctx, s->callbacks[idx], 3, argv);
        for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
        break;
    }
    case NGHTTP2_SETTINGS: {
        JSValue v = JS_NewBool(ctx, frame->hd.flags & NGHTTP2_FLAG_ACK);
        call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_SETTINGS], 1, &v);
        JS_FreeValue(ctx, v);
        break;
    }
    case NGHTTP2_PING: {
        JSValue argv[2] = { JS_NewBool(ctx,  frame->hd.flags & NGHTTP2_FLAG_ACK),
                            JS_NewArrayBufferCopy(ctx, frame->ping.opaque_data, 8) };
        call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_PING], 2, argv);
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
        call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_GOAWAY], 3, argv);
        for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
        break;
    }
    case NGHTTP2_WINDOW_UPDATE: {
        JSValue argv[2] = { JS_NewInt32(ctx, sid),
                            JS_NewInt32(ctx, frame->window_update.window_size_increment) };
        call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_WND], 2, argv);
        JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
        break;
    }
    case NGHTTP2_PUSH_PROMISE: {
        int32_t       pid = frame->push_promise.promised_stream_id;
        H2StreamData *sd  = nghttp2_session_get_stream_user_data(ng, pid);
        JSValue argv[3] = { JS_NewInt32(ctx, sid),
                            JS_NewInt32(ctx, pid),
                            sd ? JS_DupValue(ctx, sd->headers) : JS_NewArray(ctx) };
        call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_PUSH], 3, argv);
        for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
        break;
    }
    default: break;
    }

    if (call_rc < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (s->destroy_pending) return 0;

    /* raw frame debug — pass numeric type directly, zero alloc */
    JSValue raw[3] = { JS_NewInt32(ctx, frame->hd.type),
                       JS_NewInt32(ctx, sid),
                       JS_NewInt32(ctx, frame->hd.flags) };
    call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_FRAME], 3, raw);
    for (int i = 0; i < 3; i++) JS_FreeValue(ctx, raw[i]);
    return call_rc < 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int cb_frame_send(nghttp2_session *ng, const nghttp2_frame *frame,
                          void *ud) {
    (void)ng;
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    if (frame->hd.type == NGHTTP2_DATA &&
        data_src_complete_frame(s, frame->hd.stream_id))
        s->send_pending = 1;
    if (frame->hd.type == NGHTTP2_HEADERS &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        header_end_complete_frame(s, frame->hd.stream_id);
        trailer_src_complete_frame(s, frame->hd.stream_id);
    }
    JSValue argv[3] = { JS_NewInt32(ctx, frame->hd.type),
                        JS_NewInt32(ctx, frame->hd.stream_id),
                        JS_NewInt32(ctx, frame->hd.flags) };
    int call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_FRAMESENT], 3, argv);
    for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
    return call_rc < 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int cb_frame_not_send(nghttp2_session *ng,
                             const nghttp2_frame *frame,
                             int lib_error_code, void *ud) {
    (void)ng; (void)lib_error_code;
    H2Session *s = ud;
    if (frame->hd.type == NGHTTP2_HEADERS &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        header_end_complete_frame(s, frame->hd.stream_id);
        trailer_src_complete_frame(s, frame->hd.stream_id);
    }
    return 0;
}

static int cb_data_chunk(nghttp2_session *ng, uint8_t flags, int32_t sid,
                          const uint8_t *data, size_t len, void *ud) {
    (void)ng;
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    JSValue argv[3] = { JS_NewInt32(ctx, sid),
                        JS_NewUint8ArrayCopy(ctx, data, len),
                        JS_NewBool(ctx, flags & NGHTTP2_FLAG_END_STREAM) };
    int call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_DATA], 3, argv);
    for (int i = 0; i < 3; i++) JS_FreeValue(ctx, argv[i]);
    return call_rc < 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int cb_stream_close(nghttp2_session *ng, int32_t sid,
                            uint32_t error_code, void *ud) {
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    pending_src_free_stream(s, sid);
    sd_free(nghttp2_session_get_stream_user_data(ng, sid));
    nghttp2_session_set_stream_user_data(ng, sid, NULL);
    JSValue argv[2] = { JS_NewInt32(ctx, sid),
                        JS_NewInt32(ctx, (int32_t)error_code) };
    int call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_CLOSE], 2, argv);
    JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
    return call_rc < 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

static int cb_error(nghttp2_session *ng, int code,
                    const char *msg, size_t len, void *ud) {
    (void)ng;
    H2Session *s   = ud;
    JSContext *ctx = s->ctx;
    JSValue argv[2] = { JS_NewInt32(ctx, code),
                        JS_NewStringLen(ctx, msg, len) };
    int call_rc = h2_call_cb(ctx, s->callbacks[H2_CB_ERROR], 2, argv);
    JS_FreeValue(ctx, argv[0]); JS_FreeValue(ctx, argv[1]);
    return call_rc < 0 ? NGHTTP2_ERR_CALLBACK_FAILURE : 0;
}

/* ── Class lifecycle ──────────────────────────────────────────── */

static void h2session_finalizer(JSRuntime *rt, JSValue val) {
    H2Session *s = JS_GetOpaque(val, h2session_class_id);
    if (!s) return;
    if (s->ngsession) nghttp2_session_del(s->ngsession);
    data_src_free_all(s);
    trailer_src_free_all(s);
    header_end_free_all(s);
    sd_free_all_rt(s, rt);
    for (int i = 0; i < H2_CB_COUNT; i++) JS_FreeValueRT(rt, s->callbacks[i]);
    free(s);
}

static JSClassDef h2session_class = {
    "Session", .finalizer = h2session_finalizer
};

/* ── Constructor ──────────────────────────────────────────────── */

static int h2_add_setting(JSContext *ctx, JSValue obj, const char *key,
                          int32_t id, nghttp2_settings_entry *iv, int *niv) {
    JSValue value = JS_GetPropertyStr(ctx, obj, key);
    if (JS_IsException(value)) return -1;
    if (JS_IsUndefined(value)) {
        JS_FreeValue(ctx, value);
        return 0;
    }
    uint32_t setting;
    if (JS_ToUint32(ctx, &setting, value) < 0) {
        JS_FreeValue(ctx, value);
        return -1;
    }
    JS_FreeValue(ctx, value);
    iv[*niv].settings_id = id;
    iv[(*niv)++].value = setting;
    return 0;
}

static int h2_parse_settings(JSContext *ctx, JSValue obj,
                             nghttp2_settings_entry *iv, int *niv) {
    *niv = 0;
    if (JS_IsUndefined(obj)) return 0;
    if (!JS_IsObject(obj)) {
        JS_ThrowTypeError(ctx, "settings must be an object");
        return -1;
    }
    if (h2_add_setting(ctx, obj, "headerTableSize",
                       NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, iv, niv) < 0 ||
        h2_add_setting(ctx, obj, "maxConcurrentStreams",
                       NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, iv, niv) < 0 ||
        h2_add_setting(ctx, obj, "initialWindowSize",
                       NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, iv, niv) < 0 ||
        h2_add_setting(ctx, obj, "maxFrameSize",
                       NGHTTP2_SETTINGS_MAX_FRAME_SIZE, iv, niv) < 0 ||
        h2_add_setting(ctx, obj, "maxHeaderListSize",
                       NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, iv, niv) < 0)
        return -1;

    JSValue enable_push = JS_GetPropertyStr(ctx, obj, "enablePush");
    if (JS_IsException(enable_push)) return -1;
    if (!JS_IsUndefined(enable_push)) {
        int enabled = JS_ToBool(ctx, enable_push);
        if (enabled < 0) {
            JS_FreeValue(ctx, enable_push);
            return -1;
        }
        iv[*niv].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
        iv[(*niv)++].value = enabled ? 1 : 0;
    }
    JS_FreeValue(ctx, enable_push);
    return 0;
}

static JSValue h2_ng_error(JSContext *ctx, const char *operation, int rc) {
    if (JS_HasException(ctx)) return JS_EXCEPTION;
    return JS_ThrowInternalError(ctx, "%s: %s", operation, nghttp2_strerror(rc));
}

static JSValue js_h2_ctor(JSContext *ctx, JSValue new_target,
                           int argc, JSValue *argv) {
    (void)new_target;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Session(isServer[, settings])");
    int is_server = JS_ToBool(ctx, argv[0]);
    if (is_server < 0) return JS_EXCEPTION;
    H2Session *s = calloc(1, sizeof(*s));
    if (!s) return JS_ThrowOutOfMemory(ctx);
    s->ctx       = ctx;
    s->is_server = is_server;
    for (int i = 0; i < H2_CB_COUNT; i++) s->callbacks[i] = JS_NULL;

    nghttp2_settings_entry iv[6];
    int niv = 0;
    if (argc >= 2 && h2_parse_settings(ctx, argv[1], iv, &niv) < 0) {
        free(s);
        return JS_EXCEPTION;
    }

    nghttp2_session_callbacks *cbs = NULL;
    int rc = nghttp2_session_callbacks_new(&cbs);
    if (rc < 0) {
        free(s);
        return h2_ng_error(ctx, "Session callbacks", rc);
    }
    nghttp2_session_callbacks_set_send_callback(cbs,               h2_cb_send);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs,   cb_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cbs,          cb_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs,      cb_frame_recv);
    nghttp2_session_callbacks_set_on_frame_send_callback(cbs,      cb_frame_send);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(cbs,  cb_frame_not_send);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, cb_data_chunk);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs,    cb_stream_close);
    nghttp2_session_callbacks_set_error_callback2(cbs,             cb_error);

    rc = s->is_server
        ? nghttp2_session_server_new(&s->ngsession, cbs, s)
        : nghttp2_session_client_new(&s->ngsession, cbs, s);
    nghttp2_session_callbacks_del(cbs);
    if (rc < 0) {
        free(s);
        return h2_ng_error(ctx, "Session", rc);
    }

    /* Queue SETTINGS (+ client connection preface) only. Do not session_send
     * here: onsend is still unset, and h2_cb_send would claim bytes written
     * while dropping them — peers never see the preface and reset. */
    rc = nghttp2_submit_settings(s->ngsession, NGHTTP2_FLAG_NONE,
                                 niv ? iv : NULL, (size_t)niv);
    if (rc < 0) {
        h2_destroy_now(s);
        free(s);
        return h2_ng_error(ctx, "Session settings", rc);
    }

    JSValue obj = JS_NewObjectClass(ctx, h2session_class_id);
    if (JS_IsException(obj)) {
        h2_destroy_now(s);
        for (int i = 0; i < H2_CB_COUNT; i++) JS_FreeValue(ctx, s->callbacks[i]);
        free(s);
        return obj;
    }
    JS_SetOpaque(obj, s);
    return obj;
}

/* Drain outbound frames after onsend is wired (or on explicit flush). */
static JSValue js_h2_flush(JSContext *ctx, JSValue this_val,
                            int argc, JSValue *argv) {
    (void)argc; (void)argv;
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    int rc = h2_session_send(s, ng);
    JSValue result = rc < 0 ? h2_ng_error(ctx, "flush", rc) : JS_UNDEFINED;
    h2_operation_leave(s);
    return result;
}

/* ── Methods ──────────────────────────────────────────────────── */

static JSValue js_h2_receive(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "receive(buffer)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;

    JSValue result = JS_UNDEFINED;
    JSValue ab; size_t len;
    uint8_t *buf = unpack_buffer(ctx, argv[0], &len, &ab);
    if (!buf) {
        result = JS_EXCEPTION;
        goto done;
    }
    uint8_t *owned = malloc(len ? len : 1);
    if (!owned) {
        JS_FreeValue(ctx, ab);
        result = JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    if (len) memcpy(owned, buf, len);
    JS_FreeValue(ctx, ab);
    if (s->native_depth != 0) {
        free(owned);
        result = JS_ThrowInternalError(ctx, "receive cannot be called from an HTTP/2 callback");
        goto done;
    }
    s->native_depth++;
    ssize_t rc = nghttp2_session_mem_recv(ng, owned, len);
    s->native_depth--;
    free(owned);
    if (rc < 0) {
        result = h2_ng_error(ctx, "mem_recv", (int)rc);
        goto done;
    }
    if (!s->destroy_pending) {
        int send_rc = h2_session_send(s, ng);
        if (send_rc < 0) result = h2_ng_error(ctx, "receive flush", send_rc);
    }

done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_request(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "request(headers[, endStream])");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    size_t nvlen;
    nghttp2_nv *nva;
    if (h2_headers_from_js(ctx, argv[0], &nva, &nvlen) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    int end_stream = argc >= 2 ? JS_ToBool(ctx, argv[1]) : 0;
    if (end_stream < 0) {
        h2_free_nva(nva, nvlen);
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) {
        h2_free_nva(nva, nvlen);
        goto done;
    }
    H2HeaderEnd *header_end = end_stream ? header_end_alloc() : NULL;
    if (end_stream && !header_end) {
        h2_free_nva(nva, nvlen);
        result = JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    uint8_t flags = end_stream ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;
    int32_t id = nghttp2_submit_headers(ng, flags, -1, NULL, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (id < 0) {
        header_end_free(header_end);
        result = h2_ng_error(ctx, "request", id);
        goto done;
    }
    if (header_end) header_end_link(s, header_end, id);
    int send_rc = h2_session_send(s, ng);
    result = send_rc < 0 ? h2_ng_error(ctx, "request flush", send_rc)
                         : JS_NewInt32(ctx, id);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_respond(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "respond(streamId, headers[, endStream])");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (pending_src_has_terminal(s, sid) ||
        nghttp2_session_get_stream_local_close(ng, sid) == 1) {
        result = JS_ThrowTypeError(ctx, "cannot respond after END_STREAM");
        goto done;
    }
    size_t nvlen;
    nghttp2_nv *nva;
    if (h2_headers_from_js(ctx, argv[1], &nva, &nvlen) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    int end_stream = argc >= 3 ? JS_ToBool(ctx, argv[2]) : 0;
    if (end_stream < 0) {
        h2_free_nva(nva, nvlen);
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) {
        h2_free_nva(nva, nvlen);
        goto done;
    }
    H2HeaderEnd *header_end = end_stream ? header_end_alloc() : NULL;
    if (end_stream && !header_end) {
        h2_free_nva(nva, nvlen);
        result = JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    uint8_t flags = end_stream ? NGHTTP2_FLAG_END_STREAM : NGHTTP2_FLAG_NONE;
    int rc = nghttp2_submit_headers(ng, flags, sid, NULL, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (rc < 0) {
        header_end_free(header_end);
        result = h2_ng_error(ctx, "respond", rc);
        goto done;
    }
    if (header_end) header_end_link(s, header_end, sid);
    rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "respond flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_push(JSContext *ctx, JSValue this_val,
                           int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "push(streamId, headers)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    size_t nvlen;
    nghttp2_nv *nva;
    if (h2_headers_from_js(ctx, argv[1], &nva, &nvlen) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) {
        h2_free_nva(nva, nvlen);
        goto done;
    }
    int32_t pid = nghttp2_submit_push_promise(ng, NGHTTP2_FLAG_NONE,
                                               sid, nva, nvlen, NULL);
    h2_free_nva(nva, nvlen);
    if (pid < 0) {
        result = h2_ng_error(ctx, "push", pid);
        goto done;
    }
    int send_rc = h2_session_send(s, ng);
    result = send_rc < 0 ? h2_ng_error(ctx, "push flush", send_rc)
                         : JS_NewInt32(ctx, pid);
done:
    h2_operation_leave(s);
    return result;
}

static H2DataSrc *data_src_new(H2Session *s, int32_t stream_id,
                                const uint8_t *data, size_t len,
                                int end_stream) {
    H2DataSrc *ds = calloc(1, sizeof(*ds));
    if (!ds) return NULL;
    ds->data = malloc(len ? len : 1);
    if (!ds->data) { free(ds); return NULL; }
    if (len) memcpy(ds->data, data, len);
    ds->len = len;
    ds->stream_id = stream_id;
    ds->end_stream = end_stream;
    ds->session = s;
    H2DataSrc **tail = &s->data_sources;
    while (*tail) tail = &(*tail)->next;
    *tail = ds;
    return ds;
}

static H2TrailerSrc *trailer_src_new(H2Session *s, int32_t stream_id,
                                      nghttp2_nv *nva, size_t nvlen) {
    H2TrailerSrc *ts = calloc(1, sizeof(*ts));
    if (!ts) return NULL;
    ts->stream_id = stream_id;
    ts->nva = nva;
    ts->nvlen = nvlen;
    ts->session = s;
    H2TrailerSrc **tail = &s->trailer_sources;
    while (*tail) tail = &(*tail)->next;
    *tail = ts;
    return ts;
}

static void data_src_free(H2DataSrc *ds) {
    if (!ds) return;
    H2Session *s = ds->session;
    if (s) {
        H2DataSrc **link = &s->data_sources;
        while (*link && *link != ds) link = &(*link)->next;
        if (*link == ds) *link = ds->next;
    }
    free(ds->data);
    free(ds);
}

static void trailer_src_free(H2TrailerSrc *ts) {
    if (!ts) return;
    H2Session *s = ts->session;
    if (s) {
        H2TrailerSrc **link = &s->trailer_sources;
        while (*link && *link != ts) link = &(*link)->next;
        if (*link == ts) *link = ts->next;
    }
    h2_free_nva(ts->nva, ts->nvlen);
    free(ts);
}

static void data_src_free_stream(H2Session *s, int32_t stream_id) {
    for (H2DataSrc *ds = s->data_sources; ds; ds = ds->next)
        if (ds->stream_id == stream_id) ds->retired = 1;
}

static void trailer_src_free_stream(H2Session *s, int32_t stream_id) {
    for (H2TrailerSrc *ts = s->trailer_sources; ts; ts = ts->next)
        if (ts->stream_id == stream_id) ts->retired = 1;
}

static void pending_src_free_stream(H2Session *s, int32_t stream_id) {
    data_src_free_stream(s, stream_id);
    trailer_src_free_stream(s, stream_id);
    header_end_free_stream(s, stream_id);
}

static int pending_src_has_terminal(H2Session *s, int32_t stream_id) {
    for (H2DataSrc *ds = s->data_sources; ds; ds = ds->next)
        if (ds->stream_id == stream_id && ds->end_stream) return 1;
    for (H2TrailerSrc *ts = s->trailer_sources; ts; ts = ts->next)
        if (ts->stream_id == stream_id) return 1;
    for (H2HeaderEnd *end = s->header_ends; end; end = end->next)
        if (end->stream_id == stream_id) return 1;
    return 0;
}

static int data_src_complete_frame(H2Session *s, int32_t stream_id) {
    for (H2DataSrc *ds = s->data_sources; ds; ds = ds->next) {
        if (ds->stream_id == stream_id && ds->submitted &&
            ds->eof && !ds->retired) {
            ds->retired = 1;
            return 1;
        }
    }
    return 0;
}

static int trailer_src_complete_frame(H2Session *s, int32_t stream_id) {
    for (H2TrailerSrc *ts = s->trailer_sources; ts; ts = ts->next) {
        if (ts->stream_id == stream_id && ts->submitted && !ts->retired) {
            ts->retired = 1;
            return 1;
        }
    }
    return 0;
}

static int data_src_has_active(H2Session *s, int32_t stream_id) {
    for (H2DataSrc *ds = s->data_sources; ds; ds = ds->next)
        if (ds->stream_id == stream_id && ds->submitted && !ds->retired)
            return 1;
    return 0;
}

static int data_src_has_pending(H2Session *s, int32_t stream_id) {
    for (H2DataSrc *ds = s->data_sources; ds; ds = ds->next)
        if (ds->stream_id == stream_id && !ds->retired) return 1;
    return 0;
}

static int data_src_submit_pending(H2Session *s, nghttp2_session *ng) {
    for (H2DataSrc *ds = s->data_sources; ds; ds = ds->next) {
        if (ds->retired || ds->submitted ||
            data_src_has_active(s, ds->stream_id))
            continue;
        nghttp2_data_provider provider = {
            .source.ptr = ds,
            .read_callback = data_read_cb,
        };
        uint8_t flags = ds->end_stream
            ? NGHTTP2_FLAG_END_STREAM
            : NGHTTP2_FLAG_NONE;
        int rc = nghttp2_submit_data(ng, flags, ds->stream_id, &provider);
        if (rc < 0) {
            pending_src_free_stream(s, ds->stream_id);
            return rc;
        }
        ds->submitted = 1;
    }
    return 0;
}

static int trailer_src_submit_pending(H2Session *s, nghttp2_session *ng) {
    for (H2TrailerSrc *ts = s->trailer_sources; ts; ts = ts->next) {
        if (ts->retired || ts->submitted ||
            data_src_has_pending(s, ts->stream_id))
            continue;
        int rc = nghttp2_submit_trailer(ng, ts->stream_id,
                                        ts->nva, ts->nvlen);
        if (rc < 0) {
            pending_src_free_stream(s, ts->stream_id);
            return rc;
        }
        h2_free_nva(ts->nva, ts->nvlen);
        ts->nva = NULL;
        ts->nvlen = 0;
        ts->submitted = 1;
    }
    return 0;
}

static void data_src_free_all(H2Session *s) {
    while (s->data_sources) {
        H2DataSrc *ds = s->data_sources;
        s->data_sources = ds->next;
        ds->session = NULL;
        data_src_free(ds);
    }
}

static void trailer_src_free_all(H2Session *s) {
    while (s->trailer_sources) {
        H2TrailerSrc *ts = s->trailer_sources;
        s->trailer_sources = ts->next;
        ts->session = NULL;
        trailer_src_free(ts);
    }
}

static void data_src_free_retired(H2Session *s) {
    H2DataSrc *ds = s->data_sources;
    while (ds) {
        H2DataSrc *next = ds->next;
        if (ds->retired) data_src_free(ds);
        ds = next;
    }
}

static void trailer_src_free_retired(H2Session *s) {
    H2TrailerSrc *ts = s->trailer_sources;
    while (ts) {
        H2TrailerSrc *next = ts->next;
        if (ts->retired) trailer_src_free(ts);
        ts = next;
    }
}

static void h2_destroy_now(H2Session *s) {
    if (!s->ngsession) return;
    nghttp2_session *ng = s->ngsession;
    s->ngsession = NULL;
    s->destroy_pending = 0;
    s->send_pending = 0;
    nghttp2_session_del(ng);
    data_src_free_all(s);
    trailer_src_free_all(s);
    header_end_free_all(s);
    sd_free_all(s);
}

static int h2_operation_enter(H2Session *s, nghttp2_session **ng) {
    if (!s->ngsession || s->destroy_pending) return 0;
    s->operation_depth++;
    *ng = s->ngsession;
    return 1;
}

static void h2_operation_leave(H2Session *s) {
    if (s->operation_depth == 0) return;
    if (--s->operation_depth != 0) return;
    if (s->destroy_pending)
        h2_destroy_now(s);
    else {
        data_src_free_retired(s);
        trailer_src_free_retired(s);
        header_end_free_retired(s);
    }
}

static int h2_session_send(H2Session *s, nghttp2_session *ng) {
    if (s->destroy_pending) return 0;
    if (s->native_depth != 0) {
        s->send_pending = 1;
        return 0;
    }

    int rc;
    do {
        s->send_pending = 0;
        rc = data_src_submit_pending(s, ng);
        if (rc < 0) return rc;
        rc = trailer_src_submit_pending(s, ng);
        if (rc < 0) return rc;
        s->native_depth++;
        rc = nghttp2_session_send(ng);
        s->native_depth--;
    } while (rc == 0 && s->send_pending && !s->destroy_pending);
    return rc;
}

static ssize_t data_read_cb(nghttp2_session *ng, int32_t sid, uint8_t *buf,
                              size_t length, uint32_t *data_flags,
                              nghttp2_data_source *src, void *ud) {
    (void)ng; (void)sid; (void)ud;
    H2DataSrc *ds = src->ptr;
    size_t n = ds->len - ds->off; if (n > length) n = length;
    memcpy(buf, ds->data + ds->off, n); ds->off += n;
    if (ds->off >= ds->len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        ds->eof = 1;
    }
    return (ssize_t)n;
}

static JSValue js_h2_write(JSContext *ctx, JSValue this_val,
                            int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "write(streamId, data[, endStream])");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (pending_src_has_terminal(s, sid) ||
        nghttp2_session_get_stream_local_close(ng, sid) == 1) {
        result = JS_ThrowTypeError(ctx, "cannot write after END_STREAM");
        goto done;
    }
    JSValue ab; size_t len;
    uint8_t *buf = unpack_buffer(ctx, argv[1], &len, &ab);
    if (!buf) {
        result = JS_EXCEPTION;
        goto done;
    }
    int end_stream = argc >= 3 ? JS_ToBool(ctx, argv[2]) : 0;
    if (end_stream < 0) {
        JS_FreeValue(ctx, ab);
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) {
        JS_FreeValue(ctx, ab);
        goto done;
    }
    H2DataSrc *ds = data_src_new(s, sid, buf, len, end_stream);
    if (!ds) {
        JS_FreeValue(ctx, ab);
        result = JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    JS_FreeValue(ctx, ab);
    int rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "write flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_trailers(JSContext *ctx, JSValue this_val,
                               int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "trailers(streamId, headers)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (pending_src_has_terminal(s, sid) ||
        nghttp2_session_get_stream_local_close(ng, sid) == 1) {
        result = JS_ThrowTypeError(ctx, "cannot send trailers after END_STREAM");
        goto done;
    }
    size_t nvlen;
    nghttp2_nv *nva;
    if (h2_headers_from_js(ctx, argv[1], &nva, &nvlen) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) {
        h2_free_nva(nva, nvlen);
        goto done;
    }
    if (!trailer_src_new(s, sid, nva, nvlen)) {
        h2_free_nva(nva, nvlen);
        result = JS_ThrowOutOfMemory(ctx);
        goto done;
    }
    int rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "trailers flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_reset(JSContext *ctx, JSValue this_val,
                            int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "reset(streamId[, errorCode])");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    uint32_t code = NGHTTP2_NO_ERROR;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0 ||
        (argc >= 2 && JS_ToUint32(ctx, &code, argv[1]) < 0)) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) goto done;
    int rc = nghttp2_submit_rst_stream(ng, NGHTTP2_FLAG_NONE, sid, code);
    if (rc < 0) {
        result = h2_ng_error(ctx, "reset", rc);
        goto done;
    }
    rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "reset flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_wnd_update(JSContext *ctx, JSValue this_val,
                                 int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "wndUpdate(streamId, delta)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid, delta;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0 ||
        JS_ToInt32(ctx, &delta, argv[1]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) goto done;
    int rc = nghttp2_submit_window_update(ng, NGHTTP2_FLAG_NONE, sid, delta);
    if (rc < 0) {
        result = h2_ng_error(ctx, "wndUpdate", rc);
        goto done;
    }
    rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "wndUpdate flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_ping(JSContext *ctx, JSValue this_val,
                           int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    uint8_t payload[8] = {0};
    if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        JSValue ab; size_t len;
        uint8_t *buf = unpack_buffer(ctx, argv[0], &len, &ab);
        if (!buf) {
            result = JS_EXCEPTION;
            goto done;
        }
        memcpy(payload, buf, len < 8 ? len : 8);
        JS_FreeValue(ctx, ab);
    }
    int is_ack = argc >= 2 ? JS_ToBool(ctx, argv[1]) : 0;
    if (is_ack < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) goto done;
    uint8_t flags = is_ack ? NGHTTP2_FLAG_ACK : NGHTTP2_FLAG_NONE;
    int rc = nghttp2_submit_ping(ng, flags, payload);
    if (rc < 0) {
        result = h2_ng_error(ctx, "ping", rc);
        goto done;
    }
    rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "ping flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_configure(JSContext *ctx, JSValue this_val,
                                int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "configure(settings)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    nghttp2_settings_entry iv[6];
    int niv;
    if (h2_parse_settings(ctx, argv[0], iv, &niv) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (!niv || s->destroy_pending) goto done;
    int rc = nghttp2_submit_settings(ng, NGHTTP2_FLAG_NONE, iv, (size_t)niv);
    if (rc < 0) {
        result = h2_ng_error(ctx, "configure", rc);
        goto done;
    }
    rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "configure flush", rc);
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_goaway(JSContext *ctx, JSValue this_val,
                             int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    uint32_t code = NGHTTP2_NO_ERROR;
    uint8_t *opaque = NULL;
    size_t opaque_len = 0;
    JSValue ab = JS_UNDEFINED;
    if (argc >= 1 && JS_ToUint32(ctx, &code, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        opaque = unpack_buffer(ctx, argv[1], &opaque_len, &ab);
        if (!opaque) {
            result = JS_EXCEPTION;
            goto done;
        }
    }
    if (s->destroy_pending) goto done;
    int32_t last = nghttp2_session_get_last_proc_stream_id(ng);
    int rc = nghttp2_submit_goaway(ng, NGHTTP2_FLAG_NONE, last, code,
                                   opaque, opaque_len);
    if (rc < 0) {
        result = h2_ng_error(ctx, "goaway", rc);
        goto done;
    }
    rc = h2_session_send(s, ng);
    if (rc < 0) result = h2_ng_error(ctx, "goaway flush", rc);
done:
    JS_FreeValue(ctx, ab);
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_destroy(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    (void)argc; (void)argv;
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!s->ngsession || s->destroy_pending) return JS_UNDEFINED;
    if (s->operation_depth != 0 || s->native_depth != 0)
        s->destroy_pending = 1;
    else
        h2_destroy_now(s);
    return JS_UNDEFINED;
}

/* ── Stream tag (user data) ───────────────────────────────────── */

static JSValue js_h2_set_tag(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 2) return JS_ThrowTypeError(ctx, "setTag(streamId, value)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) goto done;
    H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, sid);
    if (sd) {
        JSValue value = JS_DupValue(ctx, argv[1]);
        JS_FreeValue(ctx, sd->userdata);
        sd->userdata = value;
    }
done:
    h2_operation_leave(s);
    return result;
}

static JSValue js_h2_get_tag(JSContext *ctx, JSValue this_val,
                              int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "getTag(streamId)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
    JSValue result = JS_UNDEFINED;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (!s->destroy_pending) {
        H2StreamData *sd = nghttp2_session_get_stream_user_data(ng, sid);
        if (sd) result = JS_DupValue(ctx, sd->userdata);
    }
done:
    h2_operation_leave(s);
    return result;
}

/* ── Info ─────────────────────────────────────────────────────── */

static JSValue js_h2_stream_info(JSContext *ctx, JSValue this_val,
                                  int argc, JSValue *argv) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (argc < 1) return JS_ThrowTypeError(ctx, "streamInfo(streamId)");
    nghttp2_session *ng;
    if (!h2_operation_enter(s, &ng)) return JS_NULL;
    JSValue result = JS_NULL;
    int32_t sid;
    if (JS_ToInt32(ctx, &sid, argv[0]) < 0) {
        result = JS_EXCEPTION;
        goto done;
    }
    if (s->destroy_pending) goto done;
    nghttp2_stream *st = nghttp2_session_find_stream(ng, sid);
    if (!st) goto done;
    JSValue o = JS_NewObject(ctx);
    if (JS_IsException(o)) {
        result = o;
        goto done;
    }
#define SET(k,v) JS_SetPropertyStr(ctx, o, k, v)
    SET("state",        JS_NewInt32(ctx, nghttp2_stream_get_state(st)));
    SET("weight",       JS_NewInt32(ctx, nghttp2_stream_get_weight(st)));
    SET("depWeight",    JS_NewInt32(ctx, nghttp2_stream_get_sum_dependency_weight(st)));
    SET("localWnd",     JS_NewInt32(ctx, nghttp2_session_get_stream_local_window_size(ng, sid)));
    SET("remoteWnd",    JS_NewInt32(ctx, nghttp2_session_get_stream_remote_window_size(ng, sid)));
#undef SET
    if (JS_HasException(ctx)) {
        JS_FreeValue(ctx, o);
        result = JS_EXCEPTION;
    } else {
        result = o;
    }
done:
    h2_operation_leave(s);
    return result;
}

/* ── Live getters ─────────────────────────────────────────────── */

static JSValue js_h2_getter(JSContext *ctx, JSValue this_val, int magic) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!s->ngsession || s->destroy_pending) return JS_UNDEFINED;
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
    return s ? JS_DupValue(ctx, s->callbacks[magic]) : JS_EXCEPTION;
}

static JSValue js_h2_set_cb(JSContext *ctx, JSValue this_val,
                              JSValue val, int magic) {
    H2Session *s = h2_get(ctx, this_val);
    if (!s) return JS_EXCEPTION;
    if (!JS_IsNull(val) && !JS_IsUndefined(val)) {
        int callback_state = h2_callback_is_set(ctx, val);
        if (callback_state < 0) return JS_EXCEPTION;
        if (callback_state == 0)
            return JS_ThrowTypeError(ctx, "callback must be a function, [function, thisArg], or null");
    }
    JSValue old = s->callbacks[magic];
    s->callbacks[magic] = JS_DupValue(ctx, val);
    JS_FreeValue(ctx, old);
    /* First onsend attach flushes ctor-queued preface/SETTINGS. */
    if (magic == H2_CB_SEND && s->ngsession && !s->destroy_pending &&
        !JS_IsNull(val) && !JS_IsUndefined(val)) {
        nghttp2_session *ng;
        if (!h2_operation_enter(s, &ng)) return JS_UNDEFINED;
        int rc = h2_session_send(s, ng);
        JSValue result = rc < 0 ? h2_ng_error(ctx, "onsend flush", rc)
                                : JS_UNDEFINED;
        h2_operation_leave(s);
        return result;
    }
    return JS_UNDEFINED;
}

/* ── Prototype ────────────────────────────────────────────────── */

static const JSCFunctionListEntry h2_proto[] = {
    JS_CFUNC_DEF("receive",   1, js_h2_receive),
    JS_CFUNC_DEF("flush",     0, js_h2_flush),
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
