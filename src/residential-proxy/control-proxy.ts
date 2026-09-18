import type { Duplex } from 'node:stream';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

/**
 * Dials the browserless control channel through a local circumvention client
 * (sing-box, Xray, an SSH -D tunnel, a corporate CONNECT proxy...).
 *
 * This deliberately covers the agent's WebSocket only. Tunnelled traffic still
 * leaves the machine through `net.connect`, because routing it through the
 * same proxy would replace the residential IP with the proxy's exit address --
 * which is exactly what a residential agent exists to avoid.
 */
export type ControlProxyProtocol = 'http' | 'https' | 'socks';

const socksVersion = 5;
const socksNoAuth = 0x00;
const socksUserPass = 0x02;
const socksConnect = 0x01;
const socksReserved = 0x00;
const socksAddressIPv4 = 0x01;
const socksAddressDomain = 0x03;
const socksAddressIPv6 = 0x04;
const connectHeaderLimit = 16 * 1024;

const socksErrors: Record<number, string> = {
  1: 'general SOCKS server failure',
  2: 'connection not allowed by ruleset',
  3: 'network unreachable',
  4: 'host unreachable',
  5: 'connection refused',
  6: 'TTL expired',
  7: 'command not supported',
  8: 'address type not supported',
};

export const parseControlProxyURL = (
  value: string,
): { protocol: ControlProxyProtocol; url: URL } => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(
      `Invalid control proxy URL "${value}"; expected socks5://host:port or http://host:port`,
    );
  }
  const protocol: ControlProxyProtocol | undefined = {
    'http:': 'http' as const,
    'https:': 'https' as const,
    'socks:': 'socks' as const,
    'socks5:': 'socks' as const,
    'socks5h:': 'socks' as const,
  }[url.protocol];
  if (!protocol) {
    throw new Error(
      `Unsupported control proxy protocol "${url.protocol}"; use socks5, socks5h, http or https`,
    );
  }
  if (!url.hostname) throw new Error('Control proxy URL is missing a host');
  return { protocol, url };
};

/** Reads exactly `bytes` from a socket, buffering across chunk boundaries. */
const readExactly = (socket: net.Socket, bytes: number): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    if (bytes === 0) return resolve(Buffer.alloc(0));
    const chunks: Buffer[] = [];
    let length = 0;
    const cleanup = () => {
      socket.removeListener('readable', onReadable);
      socket.removeListener('error', onError);
      socket.removeListener('end', onEnd);
    };
    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };
    const onEnd = () =>
      onError(new Error('Control proxy closed the connection'));
    const onReadable = () => {
      let chunk: Buffer | null;
      while ((chunk = socket.read(Math.min(bytes - length, 65_536))) !== null) {
        chunks.push(chunk);
        length += chunk.length;
        if (length >= bytes) {
          cleanup();
          return resolve(Buffer.concat(chunks, bytes));
        }
      }
    };
    socket.on('readable', onReadable);
    socket.once('error', onError);
    socket.once('end', onEnd);
    onReadable();
  });

const socksAddress = (host: string): Buffer => {
  if (net.isIPv4(host)) {
    return Buffer.concat([
      Buffer.from([socksAddressIPv4]),
      Buffer.from(host.split('.').map(Number)),
    ]);
  }
  if (net.isIPv6(host)) {
    const groups = host.split(':');
    const filled: string[] = [];
    const missing = 8 - groups.filter(Boolean).length;
    for (const group of groups) {
      if (group === '') {
        for (let index = 0; index < missing; index++) filled.push('0');
      } else {
        filled.push(group);
      }
    }
    const address = Buffer.alloc(16);
    filled.slice(0, 8).forEach((group, index) => {
      address.writeUInt16BE(parseInt(group || '0', 16), index * 2);
    });
    return Buffer.concat([Buffer.from([socksAddressIPv6]), address]);
  }
  const name = Buffer.from(host, 'utf8');
  if (name.length > 255)
    throw new Error('Control proxy target host is too long');
  // Domain form keeps DNS resolution at the proxy, so the local resolver never
  // sees (or gets poisoned on) the control endpoint's name.
  return Buffer.concat([Buffer.from([socksAddressDomain, name.length]), name]);
};

const socksHandshake = async (
  socket: net.Socket,
  url: URL,
  host: string,
  port: number,
): Promise<void> => {
  const username = decodeURIComponent(url.username);
  const password = decodeURIComponent(url.password);
  const methods = username ? [socksNoAuth, socksUserPass] : [socksNoAuth];
  socket.write(Buffer.from([socksVersion, methods.length, ...methods]));
  const greeting = await readExactly(socket, 2);
  if (greeting[0] !== socksVersion) {
    throw new Error('Control proxy is not a SOCKS5 server');
  }
  if (greeting[1] === socksUserPass) {
    if (!username) throw new Error('Control proxy requires SOCKS5 credentials');
    const user = Buffer.from(username, 'utf8');
    const pass = Buffer.from(password, 'utf8');
    socket.write(
      Buffer.concat([
        Buffer.from([0x01, user.length]),
        user,
        Buffer.from([pass.length]),
        pass,
      ]),
    );
    const status = await readExactly(socket, 2);
    if (status[1] !== 0x00) {
      throw new Error('Control proxy rejected the SOCKS5 credentials');
    }
  } else if (greeting[1] !== socksNoAuth) {
    throw new Error('Control proxy offered no supported SOCKS5 auth method');
  }

  socket.write(
    Buffer.concat([
      Buffer.from([socksVersion, socksConnect, socksReserved]),
      socksAddress(host),
      Buffer.from([port >> 8, port & 0xff]),
    ]),
  );
  const reply = await readExactly(socket, 4);
  if (reply[1] !== 0x00) {
    throw new Error(
      `Control proxy refused the connection: ${socksErrors[reply[1]] ?? `code ${reply[1]}`}`,
    );
  }
  const boundLength =
    reply[3] === socksAddressIPv4
      ? 4
      : reply[3] === socksAddressIPv6
        ? 16
        : (await readExactly(socket, 1))[0];
  await readExactly(socket, boundLength + 2);
};

const connectHandshake = async (
  socket: net.Socket,
  url: URL,
  host: string,
  port: number,
): Promise<void> => {
  const authority = net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
  const headers = [`CONNECT ${authority} HTTP/1.1`, `Host: ${authority}`];
  if (url.username) {
    const credentials = Buffer.from(
      `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`,
      'utf8',
    ).toString('base64');
    headers.push(`Proxy-Authorization: Basic ${credentials}`);
  }
  socket.write(`${headers.join('\r\n')}\r\n\r\n`);

  let buffer = Buffer.alloc(0);
  while (!buffer.includes('\r\n\r\n')) {
    if (buffer.length > connectHeaderLimit) {
      throw new Error('Control proxy sent oversized CONNECT headers');
    }
    buffer = Buffer.concat([buffer, await readExactly(socket, 1)]);
  }
  const headerEnd = buffer.indexOf('\r\n\r\n');
  const statusLine = buffer
    .subarray(0, buffer.indexOf('\r\n'))
    .toString('latin1');
  if (!/^HTTP\/1\.[01] 200/.test(statusLine)) {
    throw new Error(`Control proxy refused CONNECT: ${statusLine}`);
  }
  const rest = buffer.subarray(headerEnd + 4);
  if (rest.length) socket.unshift(rest);
};

export const connectThroughControlProxy = async (
  proxy: string,
  host: string,
  port: number,
  timeout = 20_000,
): Promise<net.Socket> => {
  const { protocol, url } = parseControlProxyURL(proxy);
  const proxyPort = Number(url.port) || (protocol === 'https' ? 443 : 1080);
  const socket: net.Socket =
    protocol === 'https'
      ? tls.connect({
          host: url.hostname,
          port: proxyPort,
          servername: url.hostname,
        })
      : net.connect({ host: url.hostname, port: proxyPort });

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Control proxy ${url.host} timed out`)),
      timeout,
    );
    const settle = (error?: Error) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    socket.once('error', settle);
    socket.once(protocol === 'https' ? 'secureConnect' : 'connect', () =>
      settle(),
    );
  }).catch((error) => {
    socket.destroy();
    throw error;
  });

  try {
    if (protocol === 'socks') await socksHandshake(socket, url, host, port);
    else await connectHandshake(socket, url, host, port);
  } catch (error) {
    socket.destroy();
    throw error;
  }
  return socket;
};

/**
 * An `http.Agent` whose sockets are dialled through the control proxy. Passed
 * to `ws` so only the control WebSocket is affected.
 */
export class ControlProxyAgent extends https.Agent {
  constructor(
    protected readonly proxy: string,
    protected readonly secureEndpoint: boolean,
  ) {
    super({ keepAlive: false, maxSockets: 4 });
    parseControlProxyURL(proxy);
    // http.request refuses an agent whose protocol does not match the request,
    // and this one subclasses https.Agent to serve both ws:// and wss://.
    (this as { protocol?: string }).protocol = secureEndpoint
      ? 'https:'
      : 'http:';
  }

  public createConnection(
    options: http.ClientRequestArgs & { servername?: string },
    callback?: (error: Error | null, socket: Duplex) => void,
  ): undefined {
    const host = options.host ?? 'localhost';
    const port = Number(options.port) || (this.secureEndpoint ? 443 : 80);
    const fail = (error: Error) =>
      callback?.(error, undefined as unknown as Duplex);
    connectThroughControlProxy(this.proxy, host, port)
      .then((socket) => {
        if (!this.secureEndpoint) return callback?.(null, socket);
        const secured = tls.connect({
          host,
          servername: options.servername ?? (net.isIP(host) ? undefined : host),
          socket,
        });
        secured.once('error', (error) => socket.destroy(error));
        callback?.(null, secured);
      })
      .catch((error) => fail(error as Error));
    return undefined;
  }
}

export const createControlProxyAgent = (
  proxy: string,
  secureEndpoint: boolean,
): ControlProxyAgent => new ControlProxyAgent(proxy, secureEndpoint);
