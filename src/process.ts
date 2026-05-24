/**
 * HTTP Progress Display
 * Provides graphical progress bar for slow network connections.
 */

const engine = import.meta.use("engine");
const timers = import.meta.use("timers");
const fs = import.meta.use("fs");
const os = import.meta.use("os");

export interface ProgressOptions {
    total?: number;
    width?: number;
    showSpeed?: boolean;
    showTime?: boolean;
    updateInterval?: number;
    threshold?: number;
}

export class HttpProgressBar {
    private total: number;
    private width: number;
    private showSpeed: boolean;
    private showTime: boolean;
    private updateInterval: number;
    private loaded: number = 0;
    private startTime: number = Date.now();
    private lastUpdateTime: number = Date.now();
    private lastLoaded: number = 0;
    private timer: number | null = null;
    private active: boolean = false;
    private url: string = "";

    constructor(options: ProgressOptions = {}) {
        this.total = options.total || 0;
        this.width = options.width || 40;
        this.showSpeed = options.showSpeed !== false;
        this.showTime = options.showTime !== false;
        this.updateInterval = options.updateInterval || 1000;
    }

    start(url: string): void {
        this.url = url; this.loaded = 0; this.startTime = Date.now();
        this.lastUpdateTime = Date.now(); this.lastLoaded = 0; this.active = true;
        if (this.timer) timers.clearInterval(this.timer);
        this.timer = timers.setInterval(() => { if (this.active) this.render(); }, this.updateInterval);
        this.render();
    }

    update(bytesReceived: number): void { this.loaded = bytesReceived; if (!this.active) this.active = true; }

    complete(): void {
        this.active = false;
        if (this.timer) { timers.clearInterval(this.timer); this.timer = null; }
        this.render(true);
    }

    private render(complete: boolean = false): void {
        const now = Date.now();
        const elapsed = (now - this.startTime) / 1000;
        let percent = 0;
        if (this.total > 0) percent = Math.min(100, Math.round((this.loaded / this.total) * 100));
        const speed = this.calculateSpeed(now);
        let eta = "";
        if (this.total > 0 && this.loaded > 0 && speed > 0) eta = this.formatTime(Math.round((this.total - this.loaded) / speed));
        const filled = Math.round((this.width * percent) / 100);
        const empty = this.width - filled;
        const bar = "█".repeat(filled) + "░".repeat(empty);
        const loadedStr = this.formatSize(this.loaded);
        const totalStr = this.total > 0 ? this.formatSize(this.total) : "???";
        const speedStr = speed > 0 ? `${this.formatSize(speed)}/s` : "";
        let output = `\r[${bar}] ${loadedStr}/${totalStr}`;
        if (this.total > 0) output += ` (${percent}%)`;
        if (this.showSpeed && speedStr) output += ` ${speedStr}`;
        if (this.showTime && eta) output += ` ETA: ${eta}`;
        if (complete) output = `\r[████████████████████████████████████████] ${loadedStr}/${totalStr} (100%) ${speedStr} Time: ${this.formatTime(elapsed)}\n`;
        const buffer = engine.encodeString(output);
        fs.write(os.STDOUT_FILENO, buffer);
    }

    private calculateSpeed(now: number): number {
        const timeDiff = (now - this.lastUpdateTime) / 1000;
        const bytesDiff = this.loaded - this.lastLoaded;
        if (timeDiff <= 0) return 0;
        this.lastUpdateTime = now; this.lastLoaded = this.loaded;
        return bytesDiff / timeDiff;
    }

    private formatSize(bytes: number): string {
        const units = ["B", "KB", "MB", "GB"];
        let size = bytes; let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) { size /= 1024; unitIndex++; }
        return `${size.toFixed(1)}${units[unitIndex]}`;
    }

    private formatTime(seconds: number): string {
        if (seconds < 60) return `${Math.round(seconds)}s`;
        else if (seconds < 3600) return `${Math.floor(seconds / 60)}m${Math.round(seconds % 60)}s`;
        else return `${Math.floor(seconds / 3600)}h${Math.floor((seconds % 3600) / 60)}m`;
    }
}

export function createProgressBar(options?: ProgressOptions): HttpProgressBar {
    return new HttpProgressBar(options);
}
