import {
  APITags,
  BrowserlessRoutes,
  Request,
  WebSocketRoute,
  WebsocketRoutes,
} from '@browserless.io/browserless';
import { Duplex } from 'node:stream';

export interface QuerySchema {
  /** v1 only: v2 agents send their descriptor inside the encrypted handshake. */
  agentId?: string;
  city?: string;
  country?: string;
  maxConnections?: number;
  region?: string;
  version: number;
}

export default class ResidentialProxyAgentWebSocketRoute extends WebSocketRoute {
  name = BrowserlessRoutes.ResidentialProxyAgentWebSocketRoute;
  // v2 agents authenticate inside the encrypted handshake; v1 agents present
  // the dedicated x-residential-proxy-token header.
  auth = false;
  concurrency = false;
  description = `Accepts an outbound WebSocket connection from a consenting residential proxy agent. Agents prove the dedicated agent token during an encrypted handshake and never expose a listening port on the user's PC.`;
  path = WebsocketRoutes.residentialProxyAgent;
  tags = [APITags.management];

  async handler(req: Request, socket: Duplex, head: Buffer): Promise<void> {
    return this.browserManager()
      .getResidentialProxy()
      .acceptAgent(req, socket, head);
  }
}
