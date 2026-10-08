import express from 'express';
import next from 'next';
import Provider, { errors } from 'oidc-provider';
import { OAuthStore } from './oauth-store.mjs';
import { timingSafeEqual, createHash } from 'node:crypto';

const dev = process.env.NODE_ENV !== 'production';
const port = Number(process.env.PORT || 3000);
const origin = (process.env.CONNECTOR_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`).replace(/\/$/, '');
const issuer = `${origin}/oauth`;
if (!process.env.CONNECTOR_LOGIN_PASSWORD || !process.env.OAUTH_JWKS || !process.env.OAUTH_COOKIE_SECRET) {
  throw new Error('Connector authentication configuration is missing');
}
const audience = `${origin}/api/mcp`;
const oidc = new Provider(issuer, {
  adapter: OAuthStore,
  clients: [{
    client_id: 'opendart-chatgpt',
    client_name: 'OpenDART Private Connector',
    redirect_uris: [
      'https://chatgpt.com/connector_platform_oauth_redirect',
      ...(dev ? ['http://localhost:3000/test-callback'] : []),
      ...(process.env.OAUTH_REDIRECT_URIS || '').split(',').filter(Boolean),
    ],
    response_types: ['code'],
    grant_types: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_method: 'none',
  }],
  jwks: JSON.parse(process.env.OAUTH_JWKS),
  cookies: { keys: [process.env.OAUTH_COOKIE_SECRET] },
  scopes: ['openid', 'offline_access', 'dart:read'],
  pkce: { required: () => true },
  features: {
    devInteractions: { enabled: false },
    resourceIndicators: {
      enabled: true,
      defaultResource: () => audience,
      useGrantedResource: () => true,
      getResourceServerInfo: (_ctx, resource) => {
        if (resource !== audience) throw new errors.InvalidTarget();
        return { scope: 'dart:read', audience, accessTokenTTL: 86400, accessTokenFormat: 'jwt', jwt: { sign: { alg: 'RS256' } } };
      },
    },
  },
  findAccount: async (_ctx, id) => id === 'owner' ? { accountId: id, claims: async () => ({ sub: id }) } : undefined,
  interactions: { url: (_ctx, interaction) => `/oauth/interaction/${interaction.uid}` },
});
oidc.proxy = true;
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
const attempts = new Map();
const html = (uid, error = '') => `<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>OpenDART 연결 인증</title><body style="font-family:system-ui;max-width:440px;margin:64px auto;padding:24px"><h1>OpenDART 연결 인증</h1><p>연결용 비밀번호를 입력하면 ChatGPT에 DART 공개 공시 조회 권한을 부여합니다.</p><p>비밀번호는 Render의 CONNECTOR_LOGIN_PASSWORD 설정에서 확인할 수 있습니다.</p><p style="color:#a00">${error}</p><form method="post" action="/oauth/interaction/${encodeURIComponent(uid)}"><label>연결용 비밀번호 <input style="display:block;width:100%;margin:16px 0;padding:10px" type="password" name="password" required autocomplete="current-password"></label><button style="padding:12px 18px" type="submit">인증하고 연결</button></form></body></html>`;
app.get('/oauth/interaction/:uid', async (req, res, nextFn) => {
  try {
    const details = await oidc.interactionDetails(req, res);
    if (details.prompt.name === 'consent' && details.session?.accountId === 'owner') {
      const grant = details.grantId ? await oidc.Grant.find(details.grantId) : new oidc.Grant({ accountId: 'owner', clientId: details.params.client_id });
      const missing = details.prompt.details;
      if (missing.missingOIDCScope) grant.addOIDCScope(missing.missingOIDCScope.join(' '));
      if (missing.missingOIDCClaims) grant.addOIDCClaims(missing.missingOIDCClaims);
      for (const [resource, scopes] of Object.entries(missing.missingResourceScopes || {})) grant.addResourceScope(resource, scopes.join(' '));
      return oidc.interactionFinished(req, res, { consent: { grantId: await grant.save() } }, { mergeWithLastSubmission: true });
    }
    res.set({ 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", 'Referrer-Policy': 'no-referrer' });
    res.type('html').send(html(details.uid));
  } catch (e) { nextFn(e); }
});
app.post('/oauth/interaction/:uid', express.urlencoded({ extended: false, limit: '4kb' }), async (req, res, nextFn) => {
  try {
    if (req.headers.origin && req.headers.origin !== origin) return res.status(403).send('Invalid origin');
    const details = await oidc.interactionDetails(req, res);
    const now = Date.now();
    for (const [key, entry] of attempts) if (now > entry.until) attempts.delete(key);
    const ip = req.ip;
    const record = attempts.get(ip) || { count: 0, until: now + 15 * 60 * 1000 };
    if (record.count >= 10) return res.status(429).send('Please try again in 15 minutes');
    const hash = value => createHash('sha256').update(value).digest();
    if (!timingSafeEqual(hash(String(req.body.password || '')), hash(process.env.CONNECTOR_LOGIN_PASSWORD))) {
      record.count++; attempts.set(ip, record);
      return res.status(401).type('html').send(html(details.uid, '비밀번호를 확인하세요.'));
    }
    attempts.delete(ip);
    await oidc.interactionFinished(req, res, { login: { accountId: 'owner' } }, { mergeWithLastSubmission: false });
  } catch (e) { nextFn(e); }
});
// RFC 8414 path for an authorization server with /oauth in its issuer.
app.get('/.well-known/oauth-authorization-server/oauth', async (_req, res) => {
  const metadata = await fetch(`${issuer}/.well-known/openid-configuration`).then(r => r.json());
  res.json(metadata);
});
app.use('/oauth', oidc.callback());
const nextApp = next({ dev });
await nextApp.prepare();
const handle = nextApp.getRequestHandler();
app.use((req, res) => handle(req, res));
app.use((err, _req, res, _next) => {
  console.error('Connector request failed:', err.code || err.name || 'unknown');
  if (!res.headersSent) res.status(500).send('Connector request failed');
});
app.listen(port, '0.0.0.0', () => console.log('OpenDART connector ready'));
