"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Masscan = void 0;
const child_process_1 = require("child_process");
const tiny_typed_emitter_1 = require("tiny-typed-emitter");
;
;
;
;
// "Print helpful text" - masscan (not very helpful if we want to parse the output programmatically)
const MASSCAN_BANNER_REGEX = /(?:^Starting masscan .* at .*$)|(?:Initiating.*Scan$)|(?:Scanning \d+ hosts .*$)/m;
;
class Masscan extends tiny_typed_emitter_1.TypedEmitter {
    constructor(options, masscanPath = '/usr/bin/masscan') {
        super();
        this.options = options;
        this.masscanPath = masscanPath;
        this.abortController = new AbortController();
        this.buffer = '';
    }
    getOptions() {
        // thanks copilot for not having to write this by hand ;)
        const options = [];
        options.push('--ports', this.options.ports);
        const ranges = Array.isArray(this.options.range) ? this.options.range : [this.options.range];
        ranges.forEach(range => options.push('--range', range));
        if (this.options.exclude) {
            const excludes = Array.isArray(this.options.exclude) ? this.options.exclude : [this.options.exclude];
            excludes.forEach(exclude => options.push('--exclude', exclude));
        }
        this.options.rate && options.push('--rate', this.options.rate.toString());
        this.options.adapter && options.push('--adapter', this.options.adapter);
        this.options.adapterIp && options.push('--adapter-ip', this.options.adapterIp);
        this.options.adapterPort && options.push('--adapter-port', this.options.adapterPort);
        this.options.adapterMac && options.push('--adapter-mac', this.options.adapterMac);
        this.options.routerMac && options.push('--router-mac', this.options.routerMac);
        this.options.ping && options.push('--ping');
        this.options.excludeFile && options.push('--exclude-file', this.options.excludeFile);
        this.options.retries && options.push('--retries', this.options.retries.toString());
        this.options.pcapPayloads && options.push('--pcap-payloads', this.options.pcapPayloads);
        this.options.nmapPayloads && options.push('--nmap-payloads', this.options.nmapPayloads);
        this.options.httpUserAgent && options.push('--http-user-agent', this.options.httpUserAgent);
        this.options.httpHeader && options.push('--http-header', this.options.httpHeader);
        this.options.pcap && options.push('--pcap', this.options.pcap);
        this.options.pfring && options.push('--pfring');
        this.options.resumeIndex && options.push('--resume-index', this.options.resumeIndex.toString());
        this.options.resumeCount && options.push('--resume-count', this.options.resumeCount.toString());
        this.options.shards && options.push('--shards', this.options.shards.join('/'));
        this.options.seed && options.push('--seed', this.options.seed.toString());
        this.options.ttl && options.push('--ttl', this.options.ttl.toString());
        this.options.wait && options.push('--wait', this.options.wait.toString());
        this.options.sendq && options.push('--sendq');
        this.options.additionalOptions && options.push(...this.options.additionalOptions);
        return options;
    }
    scan() {
        return new Promise((resolve, reject) => {
            var _a, _b;
            const options = this.getOptions();
            options.push('--status-ndjson', '--output-format', 'ndjson', '--output-filename', '-');
            this.scanner = (0, child_process_1.spawn)(this.masscanPath, options, {
                killSignal: 'SIGINT',
                signal: this.abortController.signal,
                stdio: ['ignore', 'pipe', 'pipe', 'overlapped'],
            });
            (_a = this.scanner.stdout) === null || _a === void 0 ? void 0 : _a.on('data', (chunkData) => {
                this.buffer += chunkData.toString();
                this.processBuffer();
            });
            (_b = this.scanner.stderr) === null || _b === void 0 ? void 0 : _b.on('data', (chunkData) => {
                // this is fine because stderr is flushed after every line
                const chunks = chunkData.toString()
                    .split(/\r?\n/).map(c => c.trim()); // split just in case
                for (const chunk of chunks) {
                    const stats = this.parseStats(chunk);
                    if (stats) {
                        this.emit('stats', stats);
                    }
                    else if (chunk && !MASSCAN_BANNER_REGEX.test(chunk) && chunk.length > 0) {
                        this.emit('error', new Error(chunk));
                    }
                }
            });
            this.scanner.on('error', error => {
                reject(error);
            });
            this.scanner.on('close', (code, signal) => {
                if (code === 0) {
                    resolve();
                }
                else {
                    reject(new Error(`Masscan exited with code ${code} and signal ${signal}`));
                }
            });
        });
    }
    stop() {
        return __awaiter(this, void 0, void 0, function* () {
            this.abortController.abort();
        });
    }
    processBuffer() {
        const lines = this.buffer.split('\n');
        // check if we have a complete line
        if (lines.length > 1) {
            // process all but the last line, the last line is either empty or incomplete
            for (let i = 0; i < lines.length - 1; i++) {
                const result = this.parseResult(lines[i]);
                if (!result) {
                    continue;
                }
                switch (result.rec_type) {
                    case 'status':
                        this.emit('status', result);
                        break;
                    default:
                        this.emit('error', new Error(`Unsupported result type ${result.rec_type}`));
                }
            }
            // keep the last line in the buffer
            this.buffer = lines[lines.length - 1];
        }
    }
    parseResult(result) {
        try {
            return JSON.parse(result);
        }
        catch (e) {
            // json parse can only throw a SyntaxError
            this.emit('error', e);
            return undefined;
        }
    }
    parseStats(status) {
        try {
            return JSON.parse(status);
        }
        catch (e) {
            return undefined;
        }
    }
}
exports.Masscan = Masscan;
