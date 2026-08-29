#!/usr/bin/env node

import os from 'node:os';
import { parseArgs } from 'node:util';

import {
  ResidentialProxyAgent,
  makeResidentialProxyAgentId,
} from '../build/exports.js';

const { values } = parseArgs({
  options: {
    'allow-host': { multiple: true, type: 'string' },
    'allow-insecure': { default: false, type: 'boolean' },
    'allowed-port': { multiple: true, type: 'string' },
    city: { type: 'string' },
    consent: { default: false, type: 'boolean' },
    country: { type: 'string' },
    help: { default: false, short: 'h', type: 'boolean' },
    id: { type: 'string' },
    'max-connections': { default: '20', type: 'string' },
    region: { type: 'string' },
    server: { type: 'string' },
    token: { type: 'string' },
  },
  strict: true,
});

const usage = `
Browserless residential proxy agent

Usage:
  browserless-residential-agent --server https://browserless.example.com \\
    --country US --token AGENT_TOKEN --consent

Required:
  --server URL          Browserless server URL (remote servers require HTTPS/WSS)
  --country CODE        Two-letter ISO country code describing this PC
  --consent             Confirm the owner permits this PC's internet connection

Security controls:
  --allow-host PATTERN  Allowed destination, repeatable (default: *)
  --allowed-port PORT   Allowed TCP port, repeatable (default: 80, 443)
  --max-connections N   Concurrent tunnel cap (default: 20)
  --allow-insecure      Permit ws:// to a non-local trusted development server

Optional geo tags:
  --region REGION
  --city CITY
  --id ID               Stable agent id (default: hostname plus random suffix)

The token may be supplied with RESIDENTIAL_PROXY_AGENT_TOKEN instead of --token.
`;

if (values.help) {
  console.log(usage.trim());
  process.exit(0);
}

const consent =
  values.consent ||
  ['1', 'true', 'yes'].includes(
    (process.env.RESIDENTIAL_PROXY_CONSENT ?? '').toLowerCase(),
  );
if (!consent) {
  throw new Error(
    'Explicit owner consent is required. Pass --consent or set RESIDENTIAL_PROXY_CONSENT=true.',
  );
}
if (!values.server) throw new Error('--server is required');
if (!values.country) throw new Error('--country is required');
const token = values.token ?? process.env.RESIDENTIAL_PROXY_AGENT_TOKEN;
if (!token) {
  throw new Error('--token or RESIDENTIAL_PROXY_AGENT_TOKEN is required');
}

const parseList = (input, fallback) =>
  input?.flatMap((value) => value.split(',')).filter(Boolean) ?? fallback;
const allowedPorts = parseList(values['allowed-port'], ['80', '443']).map(
  Number,
);
const hostname = os
  .hostname()
  .replace(/[^a-zA-Z0-9_-]/g, '-')
  .slice(0, 48);
const agentId =
  values.id ??
  `${hostname || 'agent'}-${makeResidentialProxyAgentId().slice(0, 8)}`;
const maxConnections = Number(values['max-connections']);
const controller = new AbortController();
const stop = () => controller.abort();
process.once('SIGINT', stop);
process.once('SIGTERM', stop);

const agent = new ResidentialProxyAgent({
  allowHosts: parseList(values['allow-host'], ['*']),
  allowInsecureServer: values['allow-insecure'],
  allowedPorts,
  descriptor: {
    city: values.city,
    country: values.country,
    id: agentId,
    maxConnections,
    region: values.region,
  },
  serverURL: values.server,
  token,
});

console.log(
  `Starting consented residential agent ${agentId}; public destinations only, ports ${allowedPorts.join(', ')}`,
);
await agent.run(controller.signal);
