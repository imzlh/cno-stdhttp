/**
 * circu:nghttp2
 * Thin QuickJS wrapper around nghttp2. No I/O — pure state machine.
 * Socket/TLS lifecycle is the caller's responsibility.
 */
declare namespace CModuleExternalHTTP2 {

    /* ── Types ──────────────────────────────────────────────────── */

    /** HTTP/2 header pair [name, value] */
    type Header = [string, string];

    /** tjs-style callback: bare function or [fn, thisArg] tuple */
    type Callback<T extends unknown[]> =
        | ((...args: T) => void)
        | [(...args: T) => void, unknown];

    /** nghttp2 frame types Use constants.* to match */
    type FrameType = number;

    /* ── Settings ───────────────────────────────────────────────── */

    interface Settings {
        headerTableSize?: number; // default 4096
        enablePush?: boolean;
        maxConcurrentStreams?: number;
        initialWindowSize?: number; // default 65535
        maxFrameSize?: number; // default 16384
        maxHeaderListSize?: number;
    }

    /* ── Stream info ────────────────────────────────────────────── */

    interface StreamInfo {
        state: number;
        localWindowSize: number;
        remoteWindowSize: number;
        weight: number;
        sumDependencyWeight: number;
    }

    /* ── Session info ───────────────────────────────────────────── */

    interface SessionInfo {
        nextStreamId: number;
        lastProcStreamId: number;
        remoteWindowSize: number;
        localWindowSize: number;
        remoteSettings: Required<Settings>;
        localSettings: Required<Settings>;
        wantRead: boolean;
        wantWrite: boolean;
    }

    /* ── NgHttp2Session ─────────────────────────────────────────── */

    class Session {
        /**
         * @param isServer - true for server mode
         * @param settings - initial local settings
         */
        constructor(isServer: boolean, settings?: Settings);

        /* ── Data pump ──────────────────────────────────────────── */

        /**
         * Feed received bytes into the session.
         * Triggers callbacks synchronously — including onsend for any output frames.
         */
        receive(buffer: Uint8Array | ArrayBuffer): void;

        /* ── Client ─────────────────────────────────────────────── */

        /**
         * Submit a request. Returns stream id.
         * @param headers - e.g. [[':method','GET'],[':path','/']]
         * @param endStream - true if no body will follow
         */
        request(headers: Header[], endStream?: boolean): number;

        /* ── Server ─────────────────────────────────────────────── */

        /**
         * Submit response headers for a stream.
         * @param endStream - true if no body will follow
         */
        respond(streamId: number, headers: Header[], endStream?: boolean): void;

        /**
         * Submit a push promise. Returns promised stream id.
         * Server only.
         */
        pushPromise(streamId: number, headers: Header[]): number;

        /* ── Both sides ─────────────────────────────────────────── */

        /**
         * Submit a DATA frame.
         * @param endStream - true to set END_STREAM flag
         */
        sendData(streamId: number, data: Uint8Array | ArrayBuffer, endStream?: boolean): void;

        /**
         * Submit trailer headers (must have no more data after this).
         */
        sendTrailers(streamId: number, headers: Header[]): void;

        /**
         * Submit RST_STREAM.
         * @param errorCode - default NO_ERROR (0)
         */
        resetStream(streamId: number, errorCode?: number): void;

        /**
         * Submit WINDOW_UPDATE.
         * @param streamId - 0 for connection-level
         */
        submitWindowUpdate(streamId: number, delta: number): void;

        /**
         * Submit a PING frame.
         * @param payload - 8-byte payload, random if omitted
         * @param isAck   - true to send a PING ACK (normally automatic)
         */
        submitPing(payload?: Uint8Array, isAck?: boolean): void;

        /**
         * Submit updated local settings.
         */
        submitSettings(settings: Settings): void;

        /**
         * Submit GOAWAY and begin graceful shutdown.
         * @param errorCode - default NO_ERROR (0)
         */
        goaway(errorCode?: number, opaqueData?: Uint8Array): void;

        /** Terminate the session immediately. Frees all resources. */
        destroy(): void;

        /* ── Per-stream user data ────────────────────────────────── */

        /** Attach arbitrary JS value to a stream. */
        setStreamUserData(streamId: number, data: unknown): void;

        /** Retrieve attached JS value. Returns undefined if not set. */
        getStreamUserData(streamId: number): unknown;

        /* ── Info ───────────────────────────────────────────────── */

        getSessionInfo(): SessionInfo;
        getStreamInfo(streamId: number): StreamInfo | null;

        /* ── Callbacks (C array, tjs-style) ─────────────────────── */

        /**
         * Bytes ready to write to socket. Called once per nghttp2 send callback
         * invocation — wire up directly to your socket write.
         * args: (chunk: Uint8Array)
         */
        onsend: Callback<[chunk: Uint8Array]> | null;

        /**
         * New stream arrived (server) or response headers received (client).
         * args: (streamId: number, headers: Header[], flags: number)
         */
        onstream: Callback<[streamId: number, headers: Header[], flags: number]> | null;

        /**
         * Trailer headers received.
         * args: (streamId: number, headers: Header[], flags: number)
         */
        onheaders: Callback<[streamId: number, headers: Header[], flags: number]> | null;

        /**
         * DATA chunk received.
         * args: (streamId: number, chunk: Uint8Array, endStream: boolean)
         */
        ondata: Callback<[streamId: number, chunk: Uint8Array, endStream: boolean]> | null;

        /**
         * Stream closed.
         * args: (streamId: number, errorCode: number)
         */
        onstreamclose: Callback<[streamId: number, errorCode: number]> | null;

        /**
         * GOAWAY received.
         * args: (errorCode: number, lastStreamId: number, opaqueData: Uint8Array | null)
         */
        ongoaway: Callback<[errorCode: number, lastStreamId: number, opaqueData: Uint8Array | null]> | null;

        /**
         * SETTINGS received or ACKed.
         * args: (isAck: boolean)
         */
        onsettings: Callback<[isAck: boolean]> | null;

        /**
         * PING received or ACKed.
         * args: (isAck: boolean, payload: Uint8Array)
         */
        onping: Callback<[isAck: boolean, payload: Uint8Array]> | null;

        /**
         * PUSH_PROMISE received (client only).
         * args: (streamId: number, promisedStreamId: number, headers: Header[])
         */
        onpushpromise: Callback<[streamId: number, promisedStreamId: number, headers: Header[]]> | null;

        /**
         * WINDOW_UPDATE received.
         * args: (streamId: number, delta: number)  streamId=0 → connection level
         */
        onwindowupdate: Callback<[streamId: number, delta: number]> | null;

        /**
         * Raw frame received. For debugging/extension.
         * args: (frameType: FrameType, streamId: number, flags: number)
         */
        onframerecv: Callback<[frameType: FrameType, streamId: number, flags: number]> | null;

        /**
         * Raw frame sent. For debugging/extension.
         * args: (frameType: FrameType, streamId: number, flags: number)
         */
        onframesend: Callback<[frameType: FrameType, streamId: number, flags: number]> | null;

        /**
         * Session/stream error.
         * args: (errorCode: number, message: string)
         */
        onerror: Callback<[errorCode: number, message: string]> | null;
    }

    /* ── Constants ──────────────────────────────────────────────── */

    const constants: {
        /* Error codes */
        readonly NO_ERROR: number; // 0x0
        readonly PROTOCOL_ERROR: number; // 0x1
        readonly INTERNAL_ERROR: number; // 0x2
        readonly FLOW_CONTROL_ERROR: number; // 0x3
        readonly SETTINGS_TIMEOUT: number; // 0x4
        readonly STREAM_CLOSED: number; // 0x5
        readonly FRAME_SIZE_ERROR: number; // 0x6
        readonly REFUSED_STREAM: number; // 0x7
        readonly CANCEL: number; // 0x8
        readonly COMPRESSION_ERROR: number; // 0x9
        readonly CONNECT_ERROR: number; // 0xa
        readonly ENHANCE_YOUR_CALM: number; // 0xb
        readonly INADEQUATE_SECURITY: number; // 0xc
        readonly HTTP_1_1_REQUIRED: number; // 0xd

        /* Flags */
        readonly FLAG_NONE: number; // 0x0
        readonly FLAG_END_STREAM: number; // 0x1
        readonly FLAG_END_HEADERS: number; // 0x4
        readonly FLAG_PADDED: number; // 0x8
        readonly FLAG_PRIORITY: number; // 0x20
        readonly FLAG_ACK: number; // 0x1

        /* Frame types */
        readonly DATA: number; // 0x0
        readonly HEADERS: number; // 0x1
        readonly PRIORITY: number; // 0x2
        readonly RST_STREAM: number; // 0x3
        readonly SETTINGS: number; // 0x4
        readonly PUSH_PROMISE: number; // 0x5
        readonly PING: number; // 0x6
        readonly GOAWAY: number; // 0x7
        readonly WINDOW_UPDATE: number; // 0x8
        readonly CONTINUATION: number; // 0x9
        readonly ALTSVC: number; // 0xa
        readonly ORIGIN: number; // 0xc

        /* Stream states */
        readonly STREAM_STATE_IDLE: number;
        readonly STREAM_STATE_OPEN: number;
        readonly STREAM_STATE_RESERVED_LOCAL: number;
        readonly STREAM_STATE_RESERVED_REMOTE: number;
        readonly STREAM_STATE_HALF_CLOSED_LOCAL: number;
        readonly STREAM_STATE_HALF_CLOSED_REMOTE: number;
        readonly STREAM_STATE_CLOSED: number;

        /* NV flags */
        readonly NV_FLAG_NONE: number; // 0x0
        readonly NV_FLAG_NO_INDEX: number; // 0x1
        readonly NV_FLAG_NO_COPY_NAME: number; // 0x2
        readonly NV_FLAG_NO_COPY_VALUE: number; // 0x4
    };

    export { Session, constants };
    export type { Header, Callback, Settings, StreamInfo, SessionInfo, FrameType };
}

export default CModuleExternalHTTP2;