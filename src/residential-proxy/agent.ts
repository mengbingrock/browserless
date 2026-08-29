import { WebSocket } from 'ws';
import dns from 'node:dns/promises';
import net from 'node:net';
import { randomUUID } from 'node:crypto';

import {
  ResidentialProxyAgentDescriptor,
  ResidentialProxyAgentMessage,
  ResidentialProxyServerMessage,
  parseResidentialProxyMessage,
  residentialProxyAgentPath,
  residentialProxyMaxFrameBytes,
  residentialProxyProtocolVersion,
} from './protocol.js';

const blockedAddresses = new net.BlockList();
for (const [address, prefix, type] of [
  ['0.0.0.0', 8, 'ipv4'],
  ['10.0.0.0', 8, 'ipv4'],
  ['100.64.0.0', 10, 'ipv4'],
  ['127.0.0.0', 8, 'ipv4'],
  ['169.254.0.0', 16, 'ipv4'],
  ['172.16.0.0', 12, 'ipv4'],
  ['192.0.0.0', 24, 'ipv4'],
  ['192.0.2.0', 24, 'ipv4'],
  ['192.168.0.0', 16, 'ipv4'],
  ['198.18.0.0', 15, 'ipv4'],
  ['198.51.100.0', 24, 'ipv4'],
  ['203.0.113.0', 24, 'ipv4'],
  ['224.0.0.0', 4, 'ipv4'],
  ['240.0.0.0', 4, 'ipv4'],
  ['::', 128, 'ipv6'],
  ['::1', 128, 'ipv6'],
  ['fc00::', 7, 'ipv6'],
  ['fe80::', 10, 'ipv6'],
  ['ff00::', 8, 'ipv6'],
  ['2001:db8::', 32, 'ipv6'],
] as const) {
  blockedAddresses.addSubnet(address, prefix, type);
}

export const isPublicProxyAddress = (address: string): boolean => {
  const normalized = address.toLowerCase().replace(/^\[|\]$/g, '');
  // Reject all IPv4-mapped IPv6 forms. Node's BlockList maps IPv4 checks into
  // IPv6 internally, so adding ::ffff:0:0/96 there would also block every
  // ordinary public IPv4 address.
  if (/^::ffff:/.test(normalized) || /^(?:0+:){5}ffff:/.test(normalized)) {
    return false;
  }
  const family = net.isIP(normalized);
  if (!family) return false;
  return !blockedAddresses.check(normalized, family === 4 ? 'ipv4' : 'ipv6');
};

export const hostMatchesAllowlist = (
  host: string,
  allowHosts: readonly string[],
): boolean => {
  const normalized = host.toLowerCase().replace(/\.$/, '');
  return allowHosts.some((entry) => {
    const allowed = entry.trim().toLowerCase().replace(/\.$/, '');
    if (allowed === '*') return true;
    if (allowed.startsWith('*.')) {
      const suffix = allowed.slice(2);
      return normalized === suffix || normalized.endsWith(`.${suffix}`);
    }
    return normalized === allowed;
  });
};

export interface ResidentialProxyAgentOptions {
  allowHosts?: string[];
  allowInsecureServer?: boolean;
  allowPrivateNetworks?: boolean;
  allowedPorts?: number[];
  descriptor: ResidentialProxyAgentDescriptor;
  log?: (message: string) => void;
  reconnect?: boolean;
  serverURL: string;
  token: string;
}

interface AgentTunnel {
  socket: net.Socket;
}

export class ResidentialProxyAgent {
  protected readonly allowHosts: string[];
  protected readonly allowPrivateNetworks: boolean;
  protected readonly allowedPorts: Set<number>;
  protected readonly descriptor: ResidentialProxyAgentDescriptor;
  protected readonly log: (message: string) => void;
  protected readonly reconnect: boolean;
  protected readonly serverURL: URL;
  protected readonly token: string;
  protected tunnels = new Map<string, AgentTunnel>();
  protected ws?: WebSocket;

  constructor({
    allowHosts = ['*'],
    allowInsecureServer = false,
    allowPrivateNetworks = false,
    allowedPorts = [80, 443],
    descriptor,
    log = console.log,
    reconnect = true,
    serverURL,
    token,
  }: ResidentialProxyAgentOptions) {
    if (!token.trim()) throw new Error('An agent token is required');
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(descriptor.id)) {
      throw new Error('Agent id must use 1-64 letters, numbers, _ or -');
    }
    if (!/^[a-z]{2}$/i.test(descriptor.country)) {
      throw new Error('Agent country must be a two-letter ISO country code');
    }
    if (
      !Number.isInteger(descriptor.maxConnections) ||
      descriptor.maxConnections < 1
    ) {
      throw new Error('Agent maxConnections must be a positive integer');
    }
    if (!allowHosts.length)
      throw new Error('At least one allowed host is required');
    if (
      !allowedPorts.length ||
      allowedPorts.some(
        (port) => !Number.isInteger(port) || port < 1 || port > 65_535,
      )
    ) {
      throw new Error('Allowed ports must be integers between 1 and 65535');
    }
    for (const [name, value] of [
      ['region', descriptor.region],
      ['city', descriptor.city],
    ] as const) {
      if (value && (value.length > 64 || /[\u0000-\u001f\u007f]/.test(value))) {
        throw new Error(`Agent ${name} contains invalid characters`);
      }
    }

    const parsed = new URL(serverURL);
    if (parsed.protocol === 'http:') parsed.protocol = 'ws:';
    if (parsed.protocol === 'https:') parsed.protocol = 'wss:';
    if (!['ws:', 'wss:'].includes(parsed.protocol)) {
      throw new Error('Agent server must use http(s) or ws(s)');
    }
    const localServer = ['127.0.0.1', '::1', 'localhost'].includes(
      parsed.hostname,
    );
    if (parsed.protocol !== 'wss:' && !localServer && !allowInsecureServer) {
      throw new Error(
        'Remote agent connections require wss://; use allowInsecureServer only for trusted development networks',
      );
    }
    parsed.pathname = residentialProxyAgentPath;
    parsed.search = '';
    parsed.searchParams.set('version', String(residentialProxyProtocolVersion));
    parsed.searchParams.set('agentId', descriptor.id);
    parsed.searchParams.set('country', descriptor.country.toLowerCase());
    if (descriptor.region) parsed.searchParams.set('region', descriptor.region);
    if (descriptor.city) parsed.searchParams.set('city', descriptor.city);
    parsed.searchParams.set(
      'maxConnections',
      String(descriptor.maxConnections),
    );

    this.allowHosts = allowHosts;
    this.allowPrivateNetworks = allowPrivateNetworks;
    this.allowedPorts = new Set(allowedPorts);
    this.descriptor = descriptor;
    this.log = log;
    this.reconnect = reconnect;
    this.serverURL = parsed;
    this.token = token;
  }

  protected send(message: ResidentialProxyAgentMessage): void {
    if (this.ws?.readyState !== WebSocket.OPEN) return;
    const payload = JSON.stringify(message);
    if (Buffer.byteLength(payload) > residentialProxyMaxFrameBytes) {
      throw new Error('Residential proxy frame exceeds the size limit');
    }
    this.ws.send(payload);
  }

  protected closeTunnel(id: string, notify = false): void {
    const tunnel = this.tunnels.get(id);
    if (!tunnel) return;
    this.tunnels.delete(id);
    tunnel.socket.destroy();
    if (notify) this.send({ id, type: 'end' });
  }

  protected async resolveTarget(
    host: string,
  ): Promise<{ address: string; family: number }> {
    if (!hostMatchesAllowlist(host, this.allowHosts)) {
      throw new Error(`Host "${host}" is not in the agent allowlist`);
    }
    const addresses = await dns.lookup(host, { all: true, verbatim: true });
    if (!addresses.length) throw new Error(`Host "${host}" did not resolve`);
    if (
      !this.allowPrivateNetworks &&
      addresses.some(({ address }) => !isPublicProxyAddress(address))
    ) {
      throw new Error(
        `Host "${host}" resolves to a private or reserved address`,
      );
    }
    return addresses[0];
  }

  protected async openTunnel(
    message: Extract<ResidentialProxyServerMessage, { type: 'open' }>,
  ): Promise<void> {
    const { host, id, port } = message;
    if (this.tunnels.has(id)) throw new Error('Duplicate tunnel id');
    if (this.tunnels.size >= this.descriptor.maxConnections) {
      throw new Error('Agent connection limit reached');
    }
    if (!this.allowedPorts.has(port)) {
      throw new Error(`Port ${port} is not allowed by this agent`);
    }
    const target = await this.resolveTarget(host);
    const socket = net.connect({
      family: target.family,
      host: target.address,
      port,
    });
    this.tunnels.set(id, { socket });

    socket.once('connect', () => {
      this.log(`Opened ${host}:${port} (${id.slice(0, 8)})`);
      this.send({ id, type: 'opened' });
    });
    socket.on('data', (data) => {
      try {
        this.send({ data: data.toString('base64'), id, type: 'data' });
      } catch {
        socket.destroy();
      }
    });
    socket.once('end', () => {
      this.tunnels.delete(id);
      this.send({ id, type: 'end' });
    });
    socket.once('error', (error) => {
      this.tunnels.delete(id);
      this.send({ id, message: error.message, type: 'error' });
    });
    socket.once('close', () => this.tunnels.delete(id));
  }

  protected handleMessage(raw: unknown): void {
    const message =
      parseResidentialProxyMessage<ResidentialProxyServerMessage>(raw);
    if (
      !message ||
      typeof message.type !== 'string' ||
      typeof message.id !== 'string'
    ) {
      this.ws?.close(1003, 'Invalid residential proxy frame');
      return;
    }
    if (message.type === 'open') {
      if (
        typeof message.host !== 'string' ||
        !message.host ||
        !Number.isInteger(message.port)
      ) {
        this.send({ id: message.id, message: 'Invalid target', type: 'error' });
        return;
      }
      this.openTunnel(message).catch((error) =>
        this.send({
          id: message.id,
          message: error instanceof Error ? error.message : String(error),
          type: 'error',
        }),
      );
      return;
    }
    const tunnel = this.tunnels.get(message.id);
    if (!tunnel) return;
    if (message.type === 'data' && typeof message.data === 'string') {
      tunnel.socket.write(Buffer.from(message.data, 'base64'));
    } else if (message.type === 'end') {
      tunnel.socket.end();
    } else {
      this.ws?.close(1003, 'Unknown residential proxy frame type');
    }
  }

  protected connectOnce(signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      let opened = false;
      const ws = new WebSocket(this.serverURL, {
        headers: { 'x-residential-proxy-token': this.token },
        maxPayload: residentialProxyMaxFrameBytes,
      });
      this.ws = ws;

      const abort = () => ws.close(1000, 'Agent stopped');
      signal?.addEventListener('abort', abort, { once: true });
      ws.once('open', () => {
        opened = true;
        this.log(
          `Connected agent ${this.descriptor.id} (${this.descriptor.country.toUpperCase()})`,
        );
      });
      ws.on('message', (data) => this.handleMessage(data));
      ws.once('error', (error) => {
        if (!opened) reject(error);
      });
      ws.once('close', (code, reason) => {
        signal?.removeEventListener('abort', abort);
        for (const id of this.tunnels.keys()) this.closeTunnel(id);
        this.ws = undefined;
        this.log(
          `Agent disconnected (${code}${reason.length ? `: ${reason}` : ''})`,
        );
        resolve();
      });
    });
  }

  public async run(signal?: AbortSignal): Promise<void> {
    let delay = 1_000;
    while (!signal?.aborted) {
      try {
        await this.connectOnce(signal);
        delay = 1_000;
      } catch (error) {
        this.log(
          `Agent connection failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (!this.reconnect || signal?.aborted) break;
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay = Math.min(delay * 2, 30_000);
    }
  }

  public stop(): void {
    this.ws?.close(1000, 'Agent stopped');
    for (const id of this.tunnels.keys()) this.closeTunnel(id);
  }
}

export const makeResidentialProxyAgentId = (): string => randomUUID();
