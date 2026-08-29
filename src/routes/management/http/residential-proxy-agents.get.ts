import {
  APITags,
  BrowserlessRoutes,
  HTTPManagementRoutes,
  HTTPRoute,
  Methods,
  Request,
  ResidentialProxyAgentStatus,
  contentTypes,
  jsonResponse,
} from '@browserless.io/browserless';
import { ServerResponse } from 'node:http';

export type ResponseSchema = ResidentialProxyAgentStatus[];

export default class ResidentialProxyAgentsGetRoute extends HTTPRoute {
  name = BrowserlessRoutes.ResidentialProxyAgentsGetRoute;
  accepts = [contentTypes.any];
  auth = true;
  browser = null;
  concurrency = false;
  contentTypes = [contentTypes.json];
  description = `Lists connected residential proxy agents, their self-declared geo tags, capacity, and connection counts. Agent tokens and client IPs are never returned.`;
  method = Methods.get;
  path = HTTPManagementRoutes.residentialProxyAgents;
  tags = [APITags.management];

  async handler(_req: Request, res: ServerResponse): Promise<void> {
    return jsonResponse(
      res,
      200,
      this.browserManager().getResidentialProxy().getAgents(),
    );
  }
}
