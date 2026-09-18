import http from 'node:http';
import net from 'node:net';

import { Config } from '@browserless.io/browserless';
import { expect } from 'chai';
import {
  ResidentialProxyAgent,
  hostMatchesAllowlist,
  isPublicProxyAddress,
} from './agent.js';
import { agentMatchesSelector } from './protocol.js';
import { ResidentialProxyService, parseProxyRequest } from './service.js';
import {
  AgentHandshake,
  SecureChannel,
  ServerHandshake,
} from './secure-channel.js';
import {
  connectThroughControlProxy,
  parseControlProxyURL,
} from './control-proxy.js';

const listen = (server: http.Server, host = '127.0.0.1') =>
  new Promise<number>((resolve) => {
    server.listen({ host, port: 0 }, () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('Server did not bind a TCP port');
      }
      resolve(address.port);
    });
  });

const closeServer = (server: http.Server) =>
  new Promise<void>((resolve) => server.close(() => resolve()));

const waitFor = async (predicate: () => boolean, timeout = 3_000) => {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('Timed out waiting for condition');
};

describe('Residential proxy safety and selection', () => {
  it('blocks private/reserved IPs and permits public IPs', () => {
    expect(isPublicProxyAddress('127.0.0.1')).to.equal(false);
    expect(isPublicProxyAddress('169.254.169.254')).to.equal(false);
    expect(isPublicProxyAddress('192.168.1.1')).to.equal(false);
    expect(isPublicProxyAddress('::1')).to.equal(false);
    expect(isPublicProxyAddress('::ffff:127.0.0.1')).to.equal(false);
    expect(isPublicProxyAddress('8.8.8.8')).to.equal(true);
    expect(isPublicProxyAddress('2606:4700:4700::1111')).to.equal(true);
  });

  it('matches explicit host and wildcard allowlists', () => {
    expect(hostMatchesAllowlist('example.com', ['example.com'])).to.equal(true);
    expect(hostMatchesAllowlist('api.example.com', ['*.example.com'])).to.equal(
      true,
    );
    expect(hostMatchesAllowlist('example.net', ['*.example.com'])).to.equal(
      false,
    );
  });

  it('matches agents by case-insensitive geo selectors', () => {
    const agent = { city: 'Los Angeles', country: 'US', region: 'CA' };
    expect(agentMatchesSelector(agent, { country: 'us' })).to.equal(true);
    expect(
      agentMatchesSelector(agent, {
        city: 'los angeles',
        country: 'US',
        region: 'ca',
      }),
    ).to.equal(true);
    expect(agentMatchesSelector(agent, { country: 'DE' })).to.equal(false);
  });

  it('parses CONNECT and rewrites plain HTTP proxy requests', () => {
    const connect = parseProxyRequest(
      Buffer.from(
        'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n',
      ),
    );
    expect(connect).to.include({
      host: 'example.com',
      isConnect: true,
      port: 443,
    });

    const plain = parseProxyRequest(
      Buffer.from(
        'GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: secret\r\n\r\n',
      ),
    );
    expect(plain).to.include({
      host: 'example.com',
      isConnect: false,
      port: 80,
    });
    expect(plain.initialData.toString()).to.include('GET /path?q=1 HTTP/1.1');
    expect(plain.initialData.toString()).not.to.include('Proxy-Authorization');
  });
});

describe('ResidentialProxyService', function () {
  this.timeout(10_000);

  it('relays HTTP and CONNECT while rotating outbound user-PC agents', async () => {
    const target = http.createServer((_req, res) => {
      res.end('relayed-through-agent');
    });
    const targetPort = await listen(target);

    const config = new Config();
    config.setResidentialProxyEnabled(true);
    config.setResidentialProxyAgentToken('agent-secret');
    config.setResidentialProxyHost('127.0.0.1');
    config.setResidentialProxyConnectTimeout(2_000);
    const service = new ResidentialProxyService(config);
    const relay = http.createServer();
    relay.on('upgrade', (request, socket, head) => {
      const req = request as typeof request & { parsed: URL };
      req.parsed = new URL(request.url || '/', 'http://localhost');
      service.acceptAgent(req, socket, head).catch(() => socket.destroy());
    });
    const relayPort = await listen(relay);

    const controller = new AbortController();
    const openedAgents = new Set<string>();
    const makeAgent = (id: string) =>
      new ResidentialProxyAgent({
        allowHosts: ['127.0.0.1'],
        allowPrivateNetworks: true,
        allowedPorts: [targetPort],
        descriptor: { country: 'US', id, maxConnections: 2 },
        log: (message) => {
          if (message.startsWith('Opened ')) openedAgents.add(id);
        },
        reconnect: false,
        serverURL: `http://127.0.0.1:${relayPort}`,
        token: 'agent-secret',
      });
    const agents = [
      makeAgent('local-test-agent-a'),
      makeAgent('local-test-agent-b'),
    ];
    const running = Promise.all(
      agents.map((agent) => agent.run(controller.signal)),
    );

    try {
      await waitFor(() => service.getAgents().length === 2);
      const lease = await service.acquireLease({ country: 'us' }, 'connection');
      const proxy = new URL(lease.proxyURL);
      const response = await new Promise<string>((resolve, reject) => {
        const socket = net.connect({
          host: proxy.hostname,
          port: Number(proxy.port),
        });
        let data = '';
        socket.setEncoding('utf8');
        socket.once('connect', () =>
          socket.write(
            `GET http://127.0.0.1:${targetPort}/test HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`,
          ),
        );
        socket.on('data', (chunk) => (data += chunk));
        socket.once('end', () => resolve(data));
        socket.once('error', reject);
      });
      expect(response).to.include('200 OK');
      expect(response).to.include('relayed-through-agent');

      const connectedResponse = await new Promise<string>((resolve, reject) => {
        const socket = net.connect({
          host: proxy.hostname,
          port: Number(proxy.port),
        });
        let data = '';
        let tunnelReady = false;
        socket.setEncoding('utf8');
        socket.once('connect', () =>
          socket.write(
            `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\n\r\n`,
          ),
        );
        socket.on('data', (chunk) => {
          data += chunk;
          if (!tunnelReady && data.includes('\r\n\r\n')) {
            tunnelReady = true;
            socket.write(
              `GET /inside-connect HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nConnection: close\r\n\r\n`,
            );
          }
        });
        socket.once('end', () => resolve(data));
        socket.once('error', reject);
      });
      expect(connectedResponse).to.include('200 Connection Established');
      expect(connectedResponse).to.include('relayed-through-agent');
      expect([...openedAgents].sort()).to.deep.equal([
        'local-test-agent-a',
        'local-test-agent-b',
      ]);
      await service.releaseLease(lease.id);
    } finally {
      controller.abort();
      agents.forEach((agent) => agent.stop());
      await running;
      await service.shutdown();
      await closeServer(relay);
      await closeServer(target);
    }
  });
});

/** Minimal SOCKS5 CONNECT server, enough to prove the control channel uses it. */
const startSocksServer = async (): Promise<{
  close: () => Promise<void>;
  port: number;
  targets: string[];
}> => {
  const targets: string[] = [];
  const server = net.createServer((client) => {
    let stage: 'greeting' | 'request' | 'piped' = 'greeting';
    let buffer = Buffer.alloc(0);
    client.on('data', (chunk) => {
      if (stage === 'piped') return;
      buffer = Buffer.concat([buffer, Buffer.from(chunk)]);
      if (stage === 'greeting') {
        if (buffer.length < 2 || buffer.length < 2 + buffer[1]) return;
        buffer = buffer.subarray(2 + buffer[1]);
        client.write(Buffer.from([0x05, 0x00]));
        stage = 'request';
      }
      if (stage === 'request') {
        if (buffer.length < 5) return;
        const type = buffer[3];
        const addressLength =
          type === 0x01 ? 4 : type === 0x04 ? 16 : buffer[4] + 1;
        if (buffer.length < 4 + addressLength + 2) return;
        const body = buffer.subarray(4, 4 + addressLength);
        const host =
          type === 0x01
            ? [...body].join('.')
            : body.subarray(1).toString('utf8');
        const port = buffer.readUInt16BE(4 + addressLength);
        const rest = buffer.subarray(4 + addressLength + 2);
        targets.push(`${host}:${port}`);
        stage = 'piped';
        const upstream = net.connect({ host, port }, () => {
          client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          if (rest.length) upstream.write(rest);
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.once('error', () => client.destroy());
      }
    });
    client.once('error', () => client.destroy());
  });
  const port = await new Promise<number>((resolve) => {
    server.listen({ host: '127.0.0.1', port: 0 }, () => {
      const address = server.address();
      if (!address || typeof address === 'string') throw new Error('no port');
      resolve(address.port);
    });
  });
  return {
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    port,
    targets,
  };
};

describe('Residential proxy end-to-end encryption', () => {
  const handshakePair = (serverToken: string, agentToken: string) => {
    const server = new ServerHandshake(serverToken, 2);
    const agent = new AgentHandshake(agentToken, 2);
    const hello = server.hello();
    const { auth } = agent.auth(hello, { descriptor: { hello: 'world' } });
    return { agent, auth, server };
  };

  it('completes a mutually authenticated handshake and seals the descriptor', () => {
    const { agent, auth, server } = handshakePair('shared', 'shared');
    expect(JSON.stringify(auth)).to.not.include('world');
    const { channel, payload, ready } = server.accept<{
      descriptor: { hello: string };
    }>(auth);
    expect(payload.descriptor.hello).to.equal('world');
    expect(() => agent.confirm(ready)).to.not.throw();
    expect(channel).to.be.an.instanceOf(SecureChannel);
  });

  it('rejects an agent that does not hold the shared token', () => {
    const { auth, server } = handshakePair('shared', 'wrong-token');
    expect(() => server.accept(auth)).to.throw(/failed the handshake/);
  });

  it('rejects a server that does not hold the shared token', () => {
    const honest = new AgentHandshake('shared', 2);
    const rogue = new ServerHandshake('not-the-token', 2);
    const { auth } = honest.auth(rogue.hello(), { descriptor: {} });
    // The rogue server cannot derive the keys, so it cannot forge "ready".
    const forged = {
      box: Buffer.from('nonsense').toString('base64url'),
      t: 'ready' as const,
    };
    expect(() => honest.confirm(forged)).to.throw();
    expect(auth.mac).to.be.a('string');
  });

  it('round-trips frames and refuses tampered, replayed or foreign ones', () => {
    const key = Buffer.alloc(32, 7);
    const other = Buffer.alloc(32, 9);
    const sender = new SecureChannel(key, other);
    const receiver = new SecureChannel(other, key);

    const frame = sender.seal({ id: 'abc', type: 'end' });
    expect(frame.toString('utf8')).to.not.include('abc');
    expect(receiver.open<{ id: string }>(frame).id).to.equal('abc');

    const second = sender.seal({ id: 'def', type: 'end' });
    expect(() => receiver.open(frame)).to.throw(/out of order/);
    const tampered = Buffer.from(second);
    tampered[tampered.length - 1] ^= 0xff;
    expect(() => receiver.open(tampered)).to.throw();
    expect(() => new SecureChannel(key, key).open(second)).to.throw();
  });

  it('pads short frames so payload sizes are less distinguishable', () => {
    const key = Buffer.alloc(32, 3);
    const sizes = new Set<number>();
    for (let index = 0; index < 24; index++) {
      sizes.add(
        new SecureChannel(key, key).seal({ id: 'x', type: 'end' }).length,
      );
    }
    expect(sizes.size).to.be.greaterThan(1);
  });
});

describe('Residential proxy control-channel proxying', () => {
  it('validates control proxy URLs', () => {
    expect(parseControlProxyURL('socks5://127.0.0.1:1080').protocol).to.equal(
      'socks',
    );
    expect(parseControlProxyURL('http://127.0.0.1:8080').protocol).to.equal(
      'http',
    );
    expect(() => parseControlProxyURL('ftp://127.0.0.1')).to.throw(
      /Unsupported control proxy protocol/,
    );
    expect(() => parseControlProxyURL('not a url')).to.throw(
      /Invalid control proxy URL/,
    );
  });

  it('reaches a target through a SOCKS5 control proxy', async () => {
    const target = http.createServer((_req, res) => res.end('via-socks'));
    const targetPort = await listen(target);
    const socks = await startSocksServer();
    try {
      const socket = await connectThroughControlProxy(
        `socks5://127.0.0.1:${socks.port}`,
        '127.0.0.1',
        targetPort,
      );
      const body = await new Promise<string>((resolve, reject) => {
        let data = '';
        socket.setEncoding('utf8');
        socket.write(
          `GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`,
        );
        socket.on('data', (chunk) => (data += chunk));
        socket.once('end', () => resolve(data));
        socket.once('error', reject);
      });
      expect(body).to.include('via-socks');
      expect(socks.targets).to.deep.equal([`127.0.0.1:${targetPort}`]);
    } finally {
      await socks.close();
      await closeServer(target);
    }
  });
});

describe('ResidentialProxyService transport modes', function () {
  this.timeout(10_000);

  const startService = async (configure?: (config: Config) => void) => {
    const config = new Config();
    config.setResidentialProxyEnabled(true);
    config.setResidentialProxyAgentToken('agent-secret');
    config.setResidentialProxyHost('127.0.0.1');
    config.setResidentialProxyConnectTimeout(2_000);
    configure?.(config);
    const service = new ResidentialProxyService(config);
    const relay = http.createServer();
    relay.on('upgrade', (request, socket, head) => {
      const req = request as typeof request & { parsed: URL };
      req.parsed = new URL(request.url || '/', 'http://localhost');
      service.acceptAgent(req, socket, head).catch(() => socket.destroy());
    });
    const port = await listen(relay);
    return { config, port, relay, service };
  };

  it('registers an encrypted agent whose control channel uses a SOCKS5 proxy', async () => {
    const { port, relay, service } = await startService();
    const socks = await startSocksServer();
    const controller = new AbortController();
    const agent = new ResidentialProxyAgent({
      allowHosts: ['127.0.0.1'],
      allowPrivateNetworks: true,
      controlProxy: `socks5://127.0.0.1:${socks.port}`,
      descriptor: {
        city: 'Los Angeles',
        country: 'US',
        id: 'socks-agent',
        maxConnections: 2,
        region: 'CA',
      },
      reconnect: false,
      serverURL: `http://127.0.0.1:${port}`,
      token: 'agent-secret',
    });
    const running = agent.run(controller.signal);
    try {
      await waitFor(() => service.getAgents().length === 1);
      expect(service.getAgents()[0]).to.include({
        city: 'Los Angeles',
        country: 'us',
        id: 'socks-agent',
      });
      expect(socks.targets).to.deep.equal([`127.0.0.1:${port}`]);
    } finally {
      controller.abort();
      agent.stop();
      await running;
      await service.shutdown();
      await socks.close();
      await closeServer(relay);
    }
  });

  it('refuses a legacy plaintext agent when encryption is required', async () => {
    const { port, relay, service } = await startService((config) =>
      config.setResidentialProxyRequireEncryption(true),
    );
    const controller = new AbortController();
    const agent = new ResidentialProxyAgent({
      descriptor: { country: 'US', id: 'legacy-agent', maxConnections: 1 },
      legacyPlaintext: true,
      log: () => {},
      reconnect: false,
      serverURL: `http://127.0.0.1:${port}`,
      token: 'agent-secret',
    });
    const running = agent.run(controller.signal);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect(service.getAgents()).to.have.length(0);
    } finally {
      controller.abort();
      agent.stop();
      await running;
      await service.shutdown();
      await closeServer(relay);
    }
  });

  it('rejects an encrypted agent that presents the wrong token', async () => {
    const { port, relay, service } = await startService();
    const controller = new AbortController();
    const agent = new ResidentialProxyAgent({
      descriptor: { country: 'US', id: 'imposter-agent', maxConnections: 1 },
      log: () => {},
      reconnect: false,
      serverURL: `http://127.0.0.1:${port}`,
      token: 'not-the-agent-secret',
    });
    const running = agent.run(controller.signal);
    try {
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect(service.getAgents()).to.have.length(0);
    } finally {
      controller.abort();
      agent.stop();
      await running;
      await service.shutdown();
      await closeServer(relay);
    }
  });
});
