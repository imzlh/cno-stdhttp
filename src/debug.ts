/**
 * Hexadecimal dump utility for debugging network data.
 *
 * Merged from: cts/src/http/debug.ts
 */

const console = import.meta.use('console');

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
