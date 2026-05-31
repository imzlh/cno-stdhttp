/**
 * Debug logging and hexadecimal dump utilities for @cnojs/http.
 *
 * Uses the same DEBUG env var as cts. Add 'http' (or sub-categories) to enable:
 *   DEBUG=*           — everything (including http)
 *   DEBUG=http        — all http sub-categories
 *   DEBUG=http.conn   — connection / DNS / TLS only
 *   DEBUG=http.fetch  — fetch lifecycle only
 *   DEBUG=http.h1     — HTTP/1.x parser events only
 */

const console = import.meta.use('console');
const os = import.meta.use('os');

// ---------------------------------------------------------------------------
// Debug logger — reads the shared DEBUG env var, supports !negation
// ---------------------------------------------------------------------------

let _init = false;
const _enabled  = new Set<string>();
const _disabled = new Set<string>();

function _lazyInit(): void {
    if (_init) return;
    _init = true;
    let raw = '';
    try { raw = os.getenv('DEBUG') ?? ''; } catch {}
    for (const tok of raw.split(',').map((s: string) => s.trim()).filter(Boolean)) {
        if (tok.startsWith('!')) _disabled.add(tok.slice(1));
        else _enabled.add(tok);
    }
}

export function isDebugEnabled(category: string): boolean {
    _lazyInit();
    if (_disabled.has(category) || _disabled.has('http')) return false;
    // category is e.g. 'http.conn' — also check parent 'http' and wildcard '*'
    const parent = category.includes('.') ? category.slice(0, category.indexOf('.')) : null;
    return _enabled.has('*') || _enabled.has(category) || (parent !== null && _enabled.has(parent));
}

export function dbg(category: string, msg: string | (() => string), ...rest: any[]): void {
    if (!isDebugEnabled(category)) return;
    const text = typeof msg === 'function' ? msg() : msg;
    console.log(`\x1b[2m[${category}]\x1b[0m ${text}`, ...rest);
}

/**
 * Hexadecimal debugging output function.
 * @param prefix  Output prefix (e.g. module name)
 * @param data    Data to dump (Buffer, Uint8Array, ArrayBuffer, or number[])
 * @param options Display options
 */
export function hexDump(
    prefix: string,
    data: Uint8Array | number[] | ArrayBuffer,
    options: {
        width?: number;
        showAscii?: boolean;
        showOffset?: boolean;
        dualColumn?: boolean;
        colorize?: boolean;
    } = {}
): void {
    const {
        width = 16, showAscii = true, showOffset = true,
        dualColumn = true, colorize = false
    } = options;

    const bytes = new Uint8Array(data);
    const len = bytes.length;
    const actualWidth = dualColumn ? Math.max(8, width) : width;

    const colors = {
        reset: '\x1b[0m', prefix: '\x1b[36m', offset: '\x1b[33m',
        hex: '\x1b[32m', ascii: '\x1b[37m', nonPrintable: '\x1b[90m', highlight: '\x1b[1m'
    };

    const color = (type: keyof typeof colors, text: string): string =>
        colorize ? `${colors[type]}${text}${colors.reset}` : text;

    let count = 0;
    loop: for (let i = 0; i < len; i += actualWidth) {
        let line = '';
        if (prefix) line += color('prefix', `${prefix}: `);
        if (showOffset) line += color('offset', i.toString(16).padStart(8, '0') + '  ');

        const hexParts: string[] = [];
        const asciiParts: string[] = [];

        for (let j = 0; j < actualWidth; j++) {
            count++;
            if (count == 256) { console.log('...'); break loop; }

            if (i + j < len) {
                const byte = bytes[i + j]!;
                hexParts.push(color('hex', byte.toString(16).padStart(2, '0')));
                if (showAscii) {
                    asciiParts.push(byte >= 32 && byte <= 126
                        ? color('ascii', String.fromCharCode(byte))
                        : color('nonPrintable', '.'));
                }
            } else {
                hexParts.push('  ');
                if (showAscii) asciiParts.push(' ');
            }

            if (dualColumn && j === Math.floor(actualWidth / 2) - 1 && j < actualWidth - 1) {
                hexParts.push(' ');
                if (showAscii) asciiParts.push(' ');
            }
        }

        line += color('hex', hexParts.join(' '));
        if (showAscii) line += '  ' + color('ascii', '|' + asciiParts.join('') + '|');
        console.log(line);
    }
}
