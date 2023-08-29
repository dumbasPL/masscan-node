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
export type Proto = 'arp' | 'icmp' | 'tcp' | 'udp' | 'sctp' | 'err';
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
    };
}
export type MasscanResult = MasscanOutStatus;
export interface MasscanStatsInfinite {
    state: '*';
    rate: {
        kpps: number;
        pps: number;
        synps: number;
        ackps: number;
        tcbps: number;
    };
    tcb: number;
    syn: number;
}
export interface MasscanStatsWaiting {
    state: 'waiting';
    rate: {
        kpps: number;
        pps: number;
    };
    progress: {
        percent: number;
        seconds: number;
        found: number;
        syn: {
            sent: number;
            total: number;
            remaining: number;
        };
    };
}
export interface MasscanStatsRunning {
    state: 'running';
    rate: {
        kpps: number;
        pps: number;
    };
    progress: {
        percent: number;
        eta: {
            hours: number;
            minutes: number;
            seconds: number;
        };
        syn: {
            sent: number;
            total: number;
            remaining: number;
        };
        found: number;
    };
}
export type MasscanStats = MasscanStatsInfinite | MasscanStatsWaiting | MasscanStatsRunning;
interface MasscanEvents {
    status: (status: MasscanOutStatus) => void;
    stats: (status: MasscanStats) => void;
    error: (error: Error) => void;
}
export declare class Masscan extends TypedEmitter<MasscanEvents> {
    private options;
    private masscanPath;
    private scanner?;
    private abortController;
    private buffer;
    constructor(options: MasscanOptions, masscanPath?: string);
    private getOptions;
    scan(): Promise<void>;
    stop(): Promise<void>;
    private processBuffer;
    private parseResult;
    private parseStats;
}
export {};
