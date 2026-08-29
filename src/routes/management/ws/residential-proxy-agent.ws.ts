import {
  APITags,
  BrowserlessRoutes,
  Request,
  WebSocketRoute,
  WebsocketRoutes,
} from '@browserless.io/browserless';
import { Duplex } from 'node:stream';

export interface QuerySchema {
  agentId: string;
  city?: string;
  country: string;
  maxConnections?: number;
  region?: string;
  version: number;
}

export default class ResidentialProxyAgentWebSocketRoute extends WebSocketRoute {
  name = BrowserlessRoutes.ResidentialProxyAgentWebSocketRoute;
  // Agents authenticate with the dedicated x-residential-proxy-token header.
  auth = false;
  concurrency = false;
  description = `Accepts an outbound WebSocket connection from a consenting residential proxy agent. Agents use a dedicated token and never expose a listening port on the user's PC.`;
  path = WebsocketRoutes.residentialProxyAgent;
  tags = [APITags.management];

  async handler(req: Request, socket: Duplex, head: Buffer): Promise<void> {
    return this.browserManager()
      .getResidentialProxy()
      .acceptAgent(req, socket, head);
  }
}
