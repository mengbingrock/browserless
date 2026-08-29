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
