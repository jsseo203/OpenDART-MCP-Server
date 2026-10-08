import { createLocalJWKSet, jwtVerify } from 'jose';

export function connectorOrigin(): string {
  return (process.env.CONNECTOR_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'http://localhost:3000').replace(/\/$/, '');
}

export async function verifyConnectorToken(_req: Request, bearerToken?: string) {
  if (!bearerToken || !process.env.OAUTH_JWKS) return undefined;
  try {
    const privateKeys = JSON.parse(process.env.OAUTH_JWKS).keys;
    const publicKeys = privateKeys.map(({ kty, n, e, kid, alg, use }: Record<string, string>) => ({ kty, n, e, kid, alg, use }));
    const { payload } = await jwtVerify(bearerToken, createLocalJWKSet({ keys: publicKeys }), {
      issuer: `${connectorOrigin()}/oauth`,
      audience: `${connectorOrigin()}/api/mcp`,
      algorithms: ['RS256'],
    });
    const scopes = String(payload.scope || '').split(' ');
    if (payload.sub !== 'owner' || !scopes.includes('dart:read')) return undefined;
    return { token: bearerToken, scopes, clientId: String(payload.client_id || 'opendart-chatgpt') };
  } catch { return undefined; }
}
