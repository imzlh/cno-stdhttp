/**
 * Load the nghttp2 Session module.
 * Embedded: `@cnojs/http/ext-h2` (CMake CNO_EMBED_EXT_H2).
 * Dynamic:  `ext:h2` (DEF_MODULE when built as .so).
 */

import type CModuleExternalHTTP2 from '../ext-h2/http2';

export type H2Session = CModuleExternalHTTP2.Session;
export type H2Header = CModuleExternalHTTP2.Header;
export type H2Settings = CModuleExternalHTTP2.Settings;
export type H2Constants = typeof CModuleExternalHTTP2.constants;
export type H2Module = {
    Session: typeof CModuleExternalHTTP2.Session;
    constants: H2Constants;
};

function isH2Module(value: unknown): value is H2Module {
    if (value === null || typeof value !== 'object') return false;
    const session = Reflect.get(value, 'Session');
    const constants = Reflect.get(value, 'constants');
    return typeof session === 'function' && constants !== null && typeof constants === 'object';
}

let cached: H2Module | null | undefined;
/** Test-only: same path as embed OFF without rebuilding. */
let forceUnavailable = false;

function tryUse(name: '@cnojs/http/ext-h2' | 'ext:h2'): H2Module | null {
    try {
        const mod = import.meta.use(name);
        return isH2Module(mod) ? mod : null;
    } catch {
        return null;
    }
}

/** null when the native extension is not linked/loaded. */
export function tryLoadH2(): H2Module | null {
    if (forceUnavailable) return null;
    if (cached !== undefined) return cached;
    const mod = tryUse('@cnojs/http/ext-h2') ?? tryUse('ext:h2');
    cached = mod;
    return mod;
}

export function requireH2(): H2Module {
    const mod = tryLoadH2();
    if (!mod) {
        throw new Error(
            'HTTP/2 native extension is not available (build with -DCNO_EMBED_EXT_H2=ON or load ext:h2)',
        );
    }
    return mod;
}

export function h2Available(): boolean {
    return tryLoadH2() !== null;
}

/**
 * Test helper: force the load gate to miss (same path as embed OFF).
 * Does not unload a linked native — only the JS gate used by surfaces.
 */
export function __forceH2Unavailable(force: boolean): void {
    forceUnavailable = force;
    if (force) cached = undefined;
}
