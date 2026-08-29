export const residentialProxyAgentPath = '/residential-proxy/agent';
export const residentialProxyProtocolVersion = 1;
export const residentialProxyMaxFrameBytes = 1024 * 1024;

export interface ResidentialProxyGeo {
  city?: string;
  country: string;
  region?: string;
}

export interface ResidentialProxySelector {
  city?: string;
  country?: string;
  region?: string;
}

export type ResidentialProxyRotation = 'connection' | 'session';

export interface ResidentialProxyAgentDescriptor extends ResidentialProxyGeo {
  id: string;
  maxConnections: number;
}

export type ResidentialProxyServerMessage =
  | {
      host: string;
      id: string;
      port: number;
      type: 'open';
    }
  | {
      data: string;
      id: string;
      type: 'data';
    }
  | {
      id: string;
      type: 'end';
    };

export type ResidentialProxyAgentMessage =
  | {
      id: string;
      type: 'opened';
    }
  | {
      data: string;
      id: string;
      type: 'data';
    }
  | {
      id: string;
      type: 'end';
    }
  | {
      id: string;
      message: string;
      type: 'error';
    };

export const normalizeGeo = (value: string | undefined): string | undefined =>
  value?.trim().toLowerCase() || undefined;

export const agentMatchesSelector = (
  agent: ResidentialProxyGeo,
  selector: ResidentialProxySelector,
): boolean =>
  (!selector.country ||
    normalizeGeo(agent.country) === normalizeGeo(selector.country)) &&
  (!selector.region ||
    normalizeGeo(agent.region) === normalizeGeo(selector.region)) &&
  (!selector.city || normalizeGeo(agent.city) === normalizeGeo(selector.city));

export const parseResidentialProxyMessage = <T>(raw: unknown): T | null => {
  try {
    const text =
      typeof raw === 'string'
        ? raw
        : Buffer.isBuffer(raw)
          ? raw.toString('utf8')
          : Array.isArray(raw)
            ? Buffer.concat(raw).toString('utf8')
            : raw instanceof ArrayBuffer
              ? Buffer.from(raw).toString('utf8')
              : '';
    if (!text || Buffer.byteLength(text) > residentialProxyMaxFrameBytes) {
      return null;
    }
    const value = JSON.parse(text);
    return value && typeof value === 'object' && !Array.isArray(value)
      ? (value as T)
      : null;
  } catch {
    return null;
  }
};
