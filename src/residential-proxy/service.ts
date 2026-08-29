import { WebSocket, WebSocketServer } from 'ws';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Duplex } from 'node:stream';
import type { IncomingMessage } from 'node:http';
import net from 'node:net';

import {
  BadRequest,
  Config,
  Logger,
  ServiceUnavailable,
  Unauthorized,
} from '@browserless.io/browserless';
import {
  ResidentialProxyAgentDescriptor,
  ResidentialProxyAgentMessage,
  ResidentialProxyRotation,
  ResidentialProxySelector,
  ResidentialProxyServerMessage,
  agentMatchesSelector,
  normalizeGeo,
  parseResidentialProxyMessage,
  residentialProxyMaxFrameBytes,
  residentialProxyProtocolVersion,
} from './protocol.js';

const proxyHeaderLimit = 64 * 1024;

interface RegisteredAgent {
  activeConnections: number;
  connectedAt: number;
  descriptor: ResidentialProxyAgentDescriptor;
  heartbeat?: NodeJS.Timeout;
  isAlive: boolean;
  lastSeen: number;
  tunnels: Set<string>;
  ws: WebSocket;
}

interface TunnelState {
  agent: RegisteredAgent;
  cleaned: boolean;
  id: string;
  openReject: (error: Error) => void;
  openResolve: (id: string) => void;
  openTimer: NodeJS.Timeout;
  opened: boolean;
  socket: net.Socket;
}

interface ProxyLeaseState {
  id: string;
  pinnedAgentId?: string;
  rotation: ResidentialProxyRotation;
  selector: ResidentialProxySelector;
  server: net.Server;
  sockets: Set<net.Socket>;
}

export interface ResidentialProxyLease {
  id: string;
  proxyURL: string;
}

export interface ResidentialProxyAgentStatus extends ResidentialProxyAgentDescriptor {
  activeConnections: number;
  connectedAt: number;
  lastSeen: number;
}

export interface ParsedProxyRequest {
  host: string;
  initialData: Buffer;
  isConnect: boolean;
  port: number;
}

const stripIPv6Brackets = (host: string): string =>
  host.replace(/^\[|\]$/g, '');

export const parseProxyRequest = (buffer: Buffer): ParsedProxyRequest => {
  const headerEnd = buffer.indexOf('\r\n\r\n');
  if (headerEnd < 0) throw new BadRequest('Incomplete proxy request headers');
  const headerText = buffer.subarray(0, headerEnd).toString('latin1');
  const lines = headerText.split('\r\n');
  const [method, target, version] = lines[0]?.split(' ') ?? [];
  if (!method || !target || !/^HTTP\/1\.[01]$/.test(version)) {
    throw new BadRequest('Invalid proxy request line');
  }

  if (method.toUpperCase() === 'CONNECT') {
    let authority: URL;
    try {
      authority = new URL(`http://${target}`);
    } catch {
      throw new BadRequest('Invalid CONNECT authority');
    }
    const port = authority.port ? Number(authority.port) : 443;
    if (!authority.hostname || port < 1 || port > 65_535) {
      throw new BadRequest('Invalid CONNECT target');
    }
    return {
      host: stripIPv6Brackets(authority.hostname),
      initialData: buffer.subarray(headerEnd + 4),
      isConnect: true,
      port,
    };
  }

  let url: URL;
  try {
    url = new URL(target);
  } catch {
    throw new BadRequest('Plain HTTP proxy requests require an absolute URL');
  }
  if (url.protocol !== 'http:') {
    throw new BadRequest('Non-CONNECT proxy requests must use http://');
  }
  const port = url.port ? Number(url.port) : 80;
  const cleanLines = lines.filter(
    (line, index) =>
      index === 0 || !line.toLowerCase().startsWith('proxy-authorization:'),
  );
  cleanLines[0] = `${method} ${url.pathname || '/'}${url.search} ${version}`;
  const rewritten = Buffer.from(`${cleanLines.join('\r\n')}\r\n\r\n`, 'latin1');
  return {
    host: stripIPv6Brackets(url.hostname),
    initialData: Buffer.concat([rewritten, buffer.subarray(headerEnd + 4)]),
    isConnect: false,
    port,
  };
};

const selectorKey = (selector: ResidentialProxySelector): string =>
  [selector.country, selector.region, selector.city]
    .map((value) => normalizeGeo(value) ?? '*')
    .join(':');

const parsePositiveInteger = (
  value: string | null,
  fallback: number,
): number => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
};

export class ResidentialProxyService {
  protected agents = new Map<string, RegisteredAgent>();
  protected leases = new Map<string, ProxyLeaseState>();
  protected logger = new Logger('residential-proxy');
  protected roundRobin = new Map<string, number>();
  protected tunnels = new Map<string, TunnelState>();
  protected wsServer = new WebSocketServer({
    maxPayload: residentialProxyMaxFrameBytes,
    noServer: true,
  });

  constructor(protected readonly config: Config) {}

  protected connectTimeout(): number {
    const value = this.config.getResidentialProxyConnectTimeout();
    return Number.isFinite(value) && value > 0 ? value : 15_000;
  }

  protected assertEnabled(): void {
    if (!this.config.getResidentialProxyEnabled()) {
      throw new ServiceUnavailable(
        'Residential proxying is disabled; set RESIDENTIAL_PROXY_ENABLED=true',
      );
    }
    if (!this.config.getResidentialProxyAgentToken()) {
      throw new ServiceUnavailable(
        'RESIDENTIAL_PROXY_AGENT_TOKEN must be configured',
      );
    }
  }

  protected tokenMatches(actual: string): boolean {
    const expected = this.config.getResidentialProxyAgentToken() ?? '';
    const digest = (value: string) =>
      createHash('sha256').update(value).digest();
    return timingSafeEqual(digest(actual), digest(expected));
  }

  protected parseAgentDescriptor(
    request: IncomingMessage & { parsed: URL },
  ): ResidentialProxyAgentDescriptor {
    const params = request.parsed.searchParams;
    const id = params.get('agentId')?.trim() ?? '';
    const country = params.get('country')?.trim().toLowerCase() ?? '';
    const region = params.get('region')?.trim() || undefined;
    const city = params.get('city')?.trim() || undefined;
    const version = Number(params.get('version'));
    const configuredLimit =
      this.config.getResidentialProxyMaxConnectionsPerAgent();
    const serverLimit =
      Number.isInteger(configuredLimit) && configuredLimit > 0
        ? configuredLimit
        : 20;
    const maxConnections = Math.min(
      parsePositiveInteger(params.get('maxConnections'), serverLimit),
      serverLimit,
    );
    if (version !== residentialProxyProtocolVersion) {
      throw new BadRequest(
        `Unsupported residential proxy protocol version "${params.get('version') ?? ''}"`,
      );
    }
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(id)) {
      throw new BadRequest('Agent id must use 1-64 letters, numbers, _ or -');
    }
    if (!/^[a-z]{2}$/.test(country)) {
      throw new BadRequest('Agent country must be a two-letter ISO code');
    }
    for (const [name, value] of [
      ['region', region],
      ['city', city],
    ] as const) {
      if (value && (value.length > 64 || /[\u0000-\u001f\u007f]/.test(value))) {
        throw new BadRequest(`Agent ${name} contains invalid characters`);
      }
    }
    return { city, country, id, maxConnections, region };
  }

  protected send(
    agent: RegisteredAgent,
    message: ResidentialProxyServerMessage,
  ): void {
    if (agent.ws.readyState !== WebSocket.OPEN) {
      throw new ServiceUnavailable('Residential proxy agent disconnected');
    }
    const payload = JSON.stringify(message);
    if (Buffer.byteLength(payload) > residentialProxyMaxFrameBytes) {
      throw new Error('Residential proxy frame exceeds the size limit');
    }
    agent.ws.send(payload);
  }

  protected cleanupTunnel(
    tunnel: TunnelState,
    error?: Error,
    notifyAgent = false,
  ): void {
    if (tunnel.cleaned) return;
    tunnel.cleaned = true;
    clearTimeout(tunnel.openTimer);
    this.tunnels.delete(tunnel.id);
    tunnel.agent.tunnels.delete(tunnel.id);
    tunnel.agent.activeConnections = Math.max(
      0,
      tunnel.agent.activeConnections - 1,
    );
    if (!tunnel.opened && error) tunnel.openReject(error);
    if (notifyAgent && tunnel.agent.ws.readyState === WebSocket.OPEN) {
      try {
        this.send(tunnel.agent, { id: tunnel.id, type: 'end' });
      } catch {
        // The agent is already gone; local cleanup still completes.
      }
    }
  }

  protected handleAgentMessage(agent: RegisteredAgent, raw: unknown): void {
    agent.lastSeen = Date.now();
    const message =
      parseResidentialProxyMessage<ResidentialProxyAgentMessage>(raw);
    if (!message || typeof message.id !== 'string') {
      agent.ws.close(1003, 'Invalid residential proxy frame');
      return;
    }
    const tunnel = this.tunnels.get(message.id);
    if (!tunnel || tunnel.agent !== agent) return;

    if (message.type === 'opened') {
      if (!tunnel.opened) {
        tunnel.opened = true;
        clearTimeout(tunnel.openTimer);
        tunnel.openResolve(tunnel.id);
      }
      return;
    }
    if (message.type === 'data' && typeof message.data === 'string') {
      tunnel.socket.write(Buffer.from(message.data, 'base64'));
      return;
    }
    if (message.type === 'end') {
      tunnel.socket.end();
      this.cleanupTunnel(tunnel);
      return;
    }
    if (message.type === 'error') {
      const error = new Error(
        typeof message.message === 'string'
          ? message.message
          : 'Residential proxy agent rejected the tunnel',
      );
      if (tunnel.opened) tunnel.socket.destroy();
      this.cleanupTunnel(tunnel, error);
      return;
    }
    agent.ws.close(1003, 'Unknown residential proxy frame type');
  }

  protected registerAgent(
    ws: WebSocket,
    descriptor: ResidentialProxyAgentDescriptor,
  ): RegisteredAgent {
    const prior = this.agents.get(descriptor.id);
    prior?.ws.close(4001, 'Replaced by a newer connection');
    const agent: RegisteredAgent = {
      activeConnections: 0,
      connectedAt: Date.now(),
      descriptor,
      isAlive: true,
      lastSeen: Date.now(),
      tunnels: new Set(),
      ws,
    };
    this.agents.set(descriptor.id, agent);
    this.logger.info(
      `Residential proxy agent "${descriptor.id}" connected (${descriptor.country.toUpperCase()}${descriptor.region ? `/${descriptor.region}` : ''}${descriptor.city ? `/${descriptor.city}` : ''})`,
    );

    ws.on('pong', () => {
      agent.isAlive = true;
      agent.lastSeen = Date.now();
    });
    ws.on('message', (data) => this.handleAgentMessage(agent, data));
    ws.on('error', (error) =>
      this.logger.warn(
        `Residential proxy agent "${descriptor.id}" error: ${error.message}`,
      ),
    );
    agent.heartbeat = setInterval(() => {
      if (!agent.isAlive) {
        ws.terminate();
        return;
      }
      agent.isAlive = false;
      ws.ping();
    }, 30_000);
    agent.heartbeat.unref?.();

    ws.once('close', () => {
      clearInterval(agent.heartbeat);
      if (this.agents.get(descriptor.id) === agent) {
        this.agents.delete(descriptor.id);
      }
      for (const id of [...agent.tunnels]) {
        const tunnel = this.tunnels.get(id);
        if (!tunnel) continue;
        const error = new Error('Residential proxy agent disconnected');
        tunnel.socket.destroy();
        this.cleanupTunnel(tunnel, error);
      }
      this.logger.info(
        `Residential proxy agent "${descriptor.id}" disconnected`,
      );
    });
    return agent;
  }

  public async acceptAgent(
    request: IncomingMessage & { parsed: URL },
    socket: Duplex,
    head: Buffer,
  ): Promise<void> {
    this.assertEnabled();
    const supplied = request.headers['x-residential-proxy-token'];
    if (typeof supplied !== 'string' || !this.tokenMatches(supplied)) {
      throw new Unauthorized('Bad or missing residential proxy agent token');
    }
    const descriptor = this.parseAgentDescriptor(request);

    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        if (error) reject(error);
        else resolve();
      };
      socket.once('close', () => finish());
      socket.once('error', () => finish());
      this.wsServer.handleUpgrade(request, socket, head, (ws) => {
        const agent = this.registerAgent(ws, descriptor);
        ws.once('close', () => finish());
        ws.once('error', () => finish());
        agent.lastSeen = Date.now();
      });
    });
  }

  protected availableAgents(
    selector: ResidentialProxySelector,
  ): RegisteredAgent[] {
    return [...this.agents.values()].filter(
      (agent) =>
        agent.ws.readyState === WebSocket.OPEN &&
        agent.activeConnections < agent.descriptor.maxConnections &&
        agentMatchesSelector(agent.descriptor, selector),
    );
  }

  protected selectAgent(
    selector: ResidentialProxySelector,
    pinnedAgentId?: string,
  ): RegisteredAgent {
    if (pinnedAgentId) {
      const pinned = this.agents.get(pinnedAgentId);
      if (
        pinned &&
        pinned.ws.readyState === WebSocket.OPEN &&
        pinned.activeConnections < pinned.descriptor.maxConnections
      ) {
        return pinned;
      }
      throw new ServiceUnavailable(
        'Pinned residential proxy agent is unavailable',
      );
    }
    const agents = this.availableAgents(selector);
    if (!agents.length) {
      throw new ServiceUnavailable(
        `No residential proxy agent is available for ${selectorKey(selector)}`,
      );
    }
    const key = selectorKey(selector);
    const cursor = this.roundRobin.get(key) ?? 0;
    const agent = agents[cursor % agents.length];
    this.roundRobin.set(key, (cursor + 1) % agents.length);
    return agent;
  }

  protected openTunnel(
    socket: net.Socket,
    agent: RegisteredAgent,
    host: string,
    port: number,
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const id = randomUUID();
      const tunnel: TunnelState = {
        agent,
        cleaned: false,
        id,
        openReject: reject,
        openResolve: resolve,
        opened: false,
        openTimer: setTimeout(() => {
          const error = new Error(
            'Residential proxy agent connection timed out',
          );
          socket.destroy();
          this.cleanupTunnel(tunnel, error, true);
        }, this.connectTimeout()),
        socket,
      };
      this.tunnels.set(id, tunnel);
      agent.tunnels.add(id);
      agent.activeConnections++;
      socket.once('close', () => this.cleanupTunnel(tunnel, undefined, true));
      socket.once('error', (error) => this.cleanupTunnel(tunnel, error, true));
      try {
        this.send(agent, { host, id, port, type: 'open' });
      } catch (error) {
        socket.destroy();
        this.cleanupTunnel(tunnel, error as Error);
      }
    });
  }

  protected readProxyHeaders(socket: net.Socket): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      const timeout = setTimeout(
        () => finish(new Error('Proxy request header timed out')),
        this.connectTimeout(),
      );
      const onData = (data: Buffer) => {
        buffer = Buffer.concat([buffer, data]);
        if (buffer.length > proxyHeaderLimit) {
          finish(new Error('Proxy request headers are too large'));
          return;
        }
        if (buffer.includes('\r\n\r\n')) {
          socket.pause();
          finish(undefined, buffer);
        }
      };
      const finish = (error?: Error, value?: Buffer) => {
        clearTimeout(timeout);
        socket.off('data', onData);
        socket.off('close', onClose);
        socket.off('error', onError);
        if (error) reject(error);
        else resolve(value!);
      };
      const onClose = () => finish(new Error('Proxy client disconnected'));
      const onError = (error: Error) => finish(error);
      socket.on('data', onData);
      socket.once('close', onClose);
      socket.once('error', onError);
    });
  }

  protected writeProxyError(
    socket: net.Socket,
    status: number,
    message: string,
  ) {
    const body = `${message}\n`;
    const reason =
      status === 400
        ? 'Bad Request'
        : status === 503
          ? 'Service Unavailable'
          : 'Bad Gateway';
    socket.end(
      `HTTP/1.1 ${status} ${reason}\r\n` +
        'Connection: close\r\n' +
        'Content-Type: text/plain\r\n' +
        `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
  }

  protected async handleProxyClient(
    socket: net.Socket,
    lease: ProxyLeaseState,
  ): Promise<void> {
    lease.sockets.add(socket);
    socket.once('close', () => lease.sockets.delete(socket));
    try {
      const header = await this.readProxyHeaders(socket);
      socket.pause();
      const request = parseProxyRequest(header);
      const agent = this.selectAgent(
        lease.selector,
        lease.rotation === 'session' ? lease.pinnedAgentId : undefined,
      );
      const tunnelId = await this.openTunnel(
        socket,
        agent,
        request.host,
        request.port,
      );
      if (request.isConnect) {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      }
      if (request.initialData.length) {
        this.send(agent, {
          data: request.initialData.toString('base64'),
          id: tunnelId,
          type: 'data',
        });
      }
      socket.on('data', (data) => {
        if (!this.tunnels.has(tunnelId)) return;
        try {
          this.send(agent, {
            data: data.toString('base64'),
            id: tunnelId,
            type: 'data',
          });
        } catch {
          socket.destroy();
        }
      });
      socket.resume();
    } catch (error) {
      const status =
        error instanceof BadRequest
          ? 400
          : error instanceof ServiceUnavailable
            ? 503
            : 502;
      this.writeProxyError(
        socket,
        status,
        error instanceof Error ? error.message : String(error),
      );
    }
  }

  public async acquireLease(
    selector: ResidentialProxySelector,
    rotation: ResidentialProxyRotation = 'session',
  ): Promise<ResidentialProxyLease> {
    this.assertEnabled();
    const host = this.config.getResidentialProxyHost();
    if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
      throw new BadRequest('RESIDENTIAL_PROXY_HOST must be loopback-only');
    }
    const pinnedAgent =
      rotation === 'session' ? this.selectAgent(selector) : undefined;
    if (rotation === 'connection' && !this.availableAgents(selector).length) {
      throw new ServiceUnavailable(
        `No residential proxy agent is available for ${selectorKey(selector)}`,
      );
    }

    const id = randomUUID();
    const server = net.createServer((socket) => {
      const lease = this.leases.get(id);
      if (!lease) {
        socket.destroy();
        return;
      }
      this.handleProxyClient(socket, lease).catch((error) => {
        this.logger.warn(`Residential proxy client failed: ${error}`);
        socket.destroy();
      });
    });
    const lease: ProxyLeaseState = {
      id,
      pinnedAgentId: pinnedAgent?.descriptor.id,
      rotation,
      selector,
      server,
      sockets: new Set(),
    };
    this.leases.set(id, lease);
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen({ host, port: 0 }, () => {
        server.off('error', reject);
        resolve();
      });
    }).catch((error) => {
      this.leases.delete(id);
      throw error;
    });
    const address = server.address();
    if (!address || typeof address === 'string') {
      await this.releaseLease(id);
      throw new Error('Residential proxy listener did not expose a TCP port');
    }
    const urlHost =
      host === '::1' ? '[::1]' : host === 'localhost' ? 'localhost' : host;
    return { id, proxyURL: `http://${urlHost}:${address.port}` };
  }

  public async releaseLease(id: string): Promise<void> {
    const lease = this.leases.get(id);
    if (!lease) return;
    this.leases.delete(id);
    for (const socket of lease.sockets) socket.destroy();
    await new Promise<void>((resolve) => lease.server.close(() => resolve()));
  }

  public getAgents(): ResidentialProxyAgentStatus[] {
    return [...this.agents.values()].map((agent) => ({
      ...agent.descriptor,
      activeConnections: agent.activeConnections,
      connectedAt: agent.connectedAt,
      lastSeen: agent.lastSeen,
    }));
  }

  public async shutdown(): Promise<void> {
    await Promise.all(
      [...this.leases.keys()].map((id) => this.releaseLease(id)),
    );
    for (const agent of this.agents.values()) {
      clearInterval(agent.heartbeat);
      agent.ws.close(1001, 'Browserless is shutting down');
    }
    this.agents.clear();
    this.wsServer.close();
  }
}
