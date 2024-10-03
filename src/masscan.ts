import { ChildProcess, spawn } from "child_process";
import { TypedEmitter } from "tiny-typed-emitter";

export interface MasscanOptions {
  ports: string;
  range: string | string[];
  exclude?: string | string[];
  rate?: number;
  adapter?: string;
  adapterIp?: string;
  adapterPort?: string;
  adapterMac?: string;
  routerMac?: string;
  ping?: boolean;
  excludeFile?: string;
  retries?: number;
  pcapPayloads?: string;
  nmapPayloads?: string;
  httpUserAgent?: string;
  httpHeader?: string;
  pcap?: string;
  pfring?: boolean;
  resumeIndex?: number;
  resumeCount?: number;
  shards?: [number, number];
  seed?: number;
  ttl?: number;
  wait?: number;
  sendq?: boolean;
  additionalOptions?: string[];
}

// https://github.com/robertdavidgraham/masscan/blob/7b3f6227682f1e12e9eec0cd74b18c503e2e69e4/src/output.c#L72-L77
export type Proto = 'arp' | 'icmp' | 'tcp' | 'udp' | 'sctp' | 'err';
// https://github.com/robertdavidgraham/masscan/blob/7b3f6227682f1e12e9eec0cd74b18c503e2e69e4/src/output.c#L91-L94
export type PortStatus = 'open' | 'closed' | 'up' | 'unknown';

export interface MasscanOutStatus {
  timestamp: string;
  ip: string;
  port: number;
  proto: Proto;
  rec_type: 'status';
  data: {
    status: PortStatus;
    reason: string;
    ttl: number;
  },
};

export type MasscanResult = MasscanOutStatus; // banners not supported for now

export interface MasscanStatsInfinite {
  state: '*';
  rate: {
    kpps: number;
    pps: number;
    synps: number;
    ackps: number;
    tcbps: number;
  },
  tcb: number;
  syn: number;
};

export interface MasscanStatsWaiting {
  state: 'waiting';
  rate: {
    kpps: number;
    pps: number;
  },
  progress: {
    percent: number;
    seconds: number;
    found: number;
    syn: {
      sent: number;
      total: number;
      remaining: number;
    },
  },
};

export interface MasscanStatsRunning {
  state: 'running';
  rate: {
    kpps: number;
    pps: number;
  },
  progress: {
    percent: number;
    eta: {
      hours: number;
      minutes: number;
      seconds: number;
    },
    syn: {
      sent: number;
      total: number;
      remaining: number;
    },
    found: number;
  },
};

export type MasscanStats = MasscanStatsInfinite | MasscanStatsWaiting | MasscanStatsRunning;

// "Print helpful text" - masscan (not very helpful if we want to parse the output programmatically)
const MASSCAN_BANNER_REGEX = /(?:^Starting masscan .* at .*$)|(?:Initiating.*Scan$)|(?:Scanning \d+ hosts .*$)/m;

interface MasscanEvents {
  status: (status: MasscanOutStatus) => void;
  stats: (status: MasscanStats) => void;
  error: (error: Error) => void;
};

export class Masscan extends TypedEmitter<MasscanEvents> {

  private scanner?: ChildProcess;
  private abortController: AbortController = new AbortController();
  private buffer: string = '';

  constructor(private options: MasscanOptions, private masscanPath: string = '/usr/bin/masscan') {
    super();
  }

  private getOptions(): string[] {
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

  public scan(): Promise<void> {
    return new Promise((resolve, reject) => {
      const options = this.getOptions();

      options.push(
        '--status-ndjson',
        '--output-format', 'ndjson',
        '--output-filename', '-',
      );

      this.scanner = spawn(this.masscanPath, options, {
        killSignal: 'SIGINT',
        signal: this.abortController.signal,
        stdio: ['ignore', 'pipe', 'pipe', 'overlapped'],
      });

      this.scanner.stdout?.on('data', (chunkData: Buffer) => {
        this.buffer += chunkData.toString();
        this.processBuffer();
      });

      this.scanner.stderr?.on('data', (chunkData: Buffer) => {
        // this is fine because stderr is flushed after every line
        const chunks = chunkData.toString()
          .split(/\r?\n/).map(c => c.trim()); // split just in case

        for (const chunk of chunks) {
          const stats = this.parseStats(chunk);
          if (stats) {
            this.emit('stats', stats);
          } else if (chunk && !MASSCAN_BANNER_REGEX.test(chunk) && chunk.length > 0) {
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
        } else {
          reject(new Error(`Masscan exited with code ${code} and signal ${signal}`));
        }
      });
    });
  }

  public async stop(): Promise<void> {
    this.abortController.abort();
  }

  private processBuffer() {
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

  private parseResult(result: string): MasscanResult | undefined {
    try {
      return JSON.parse(result);
    } catch (e) {
      // json parse can only throw a SyntaxError
      this.emit('error', e as SyntaxError);
      return undefined;
    }
  }

  private parseStats(status: string): MasscanStats | undefined {
    try {
      return JSON.parse(status);
    } catch (e) {
      return undefined;
    }
  }

}
