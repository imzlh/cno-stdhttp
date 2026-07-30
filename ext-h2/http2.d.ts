/**
 * circu:nghttp2 — names match http2.c (not the aspirational Node-ish aliases).
 * Pure state machine; socket/TLS I/O is the caller's job.
 */
declare namespace CModuleExternalHTTP2 {
    type Header = [string, string];

    type Callback<T extends unknown[]> =
        | ((...args: T) => void)
        | [(...args: T) => void, unknown];

    interface Settings {
        headerTableSize?: number;
        enablePush?: boolean;
        maxConcurrentStreams?: number;
        initialWindowSize?: number;
        maxFrameSize?: number;
        maxHeaderListSize?: number;
    }

    interface StreamInfo {
        state: number;
        weight: number;
        depWeight: number;
        localWnd: number;
        remoteWnd: number;
    }

    class Session {
        constructor(isServer: boolean, settings?: Settings);

        receive(buffer: Uint8Array | ArrayBuffer): void;
        /** Drain outbound queue (preface/SETTINGS/frames) via onsend. */
        flush(): void;
        request(headers: Header[], endStream?: boolean): number;
        respond(streamId: number, headers: Header[], endStream?: boolean): void;
        push(streamId: number, headers: Header[]): number;
        write(streamId: number, data: Uint8Array | ArrayBuffer, endStream?: boolean): void;
        trailers(streamId: number, headers: Header[]): void;
        reset(streamId: number, errorCode?: number): void;
        consume(streamId: number, length: number): void;
        wndUpdate(streamId: number, delta: number): void;
        ping(payload?: Uint8Array, isAck?: boolean): void;
        configure(settings: Settings): void;
        goaway(errorCode?: number, opaqueData?: Uint8Array): void;
        destroy(): void;
        setTag(streamId: number, data: unknown): void;
        getTag(streamId: number): unknown;
        streamInfo(streamId: number): StreamInfo | null;

        readonly wantRead: boolean;
        readonly wantWrite: boolean;
        readonly nextStreamId: number;
        readonly localWnd: number;
        readonly remoteWnd: number;

        onsend: Callback<[chunk: Uint8Array]> | null;
        onstream: Callback<[streamId: number, headers: Header[], flags: number]> | null;
        onheaders: Callback<[streamId: number, headers: Header[], flags: number]> | null;
        ondata: Callback<[streamId: number, chunk: Uint8Array, endStream: boolean]> | null;
        onclose: Callback<[streamId: number, errorCode: number]> | null;
        ongoaway: Callback<[errorCode: number, lastStreamId: number, opaqueData: Uint8Array | null]> | null;
        onsettings: Callback<[isAck: boolean]> | null;
        onping: Callback<[isAck: boolean, payload: Uint8Array]> | null;
        onpush: Callback<[streamId: number, promisedStreamId: number, headers: Header[]]> | null;
        onwnd: Callback<[streamId: number, delta: number]> | null;
        onframe: Callback<[frameType: number, streamId: number, flags: number]> | null;
        onframesent: Callback<[frameType: number, streamId: number, flags: number]> | null;
        onerror: Callback<[errorCode: number, message: string]> | null;
    }

    const constants: {
        readonly NO_ERROR: number;
        readonly PROTOCOL_ERROR: number;
        readonly INTERNAL_ERROR: number;
        readonly FLOW_CONTROL_ERROR: number;
        readonly SETTINGS_TIMEOUT: number;
        readonly STREAM_CLOSED: number;
        readonly FRAME_SIZE_ERROR: number;
        readonly REFUSED_STREAM: number;
        readonly CANCEL: number;
        readonly COMPRESSION_ERROR: number;
        readonly CONNECT_ERROR: number;
        readonly ENHANCE_YOUR_CALM: number;
        readonly INADEQUATE_SECURITY: number;
        readonly HTTP_1_1_REQUIRED: number;
        readonly FLAG_NONE: number;
        readonly FLAG_END_STREAM: number;
        readonly FLAG_END_HEADERS: number;
        readonly FLAG_PADDED: number;
        readonly FLAG_PRIORITY: number;
        readonly FLAG_ACK: number;
        readonly DATA: number;
        readonly HEADERS: number;
        readonly PRIORITY: number;
        readonly RST_STREAM: number;
        readonly SETTINGS: number;
        readonly PUSH_PROMISE: number;
        readonly PING: number;
        readonly GOAWAY: number;
        readonly WINDOW_UPDATE: number;
        readonly CONTINUATION: number;
        readonly ALTSVC: number;
        readonly ORIGIN: number;
        readonly STREAM_STATE_IDLE: number;
        readonly STREAM_STATE_OPEN: number;
        readonly STREAM_STATE_RESERVED_LOCAL: number;
        readonly STREAM_STATE_RESERVED_REMOTE: number;
        readonly STREAM_STATE_HALF_CLOSED_LOCAL: number;
        readonly STREAM_STATE_HALF_CLOSED_REMOTE: number;
        readonly STREAM_STATE_CLOSED: number;
        readonly NV_FLAG_NONE: number;
        readonly NV_FLAG_NO_INDEX: number;
        readonly NV_FLAG_NO_COPY_NAME: number;
        readonly NV_FLAG_NO_COPY_VALUE: number;
    };

    export { Session, constants };
    export type { Header, Callback, Settings, StreamInfo };
}

export default CModuleExternalHTTP2;
