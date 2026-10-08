const ready = ['OPENDART_API_KEY','CONNECTOR_LOGIN_PASSWORD','OAUTH_COOKIE_SECRET','OAUTH_JWKS'].every(key => !!process.env[key]);
if (ready) {
  await import('./server.mjs');
} else {
  // Boot an unconfigured, fail-closed service while secrets await owner approval.
  const { default: next } = await import('next');
  const { createServer } = await import('node:http');
  const app = next({ dev: false });
  await app.prepare();
  const handler = app.getRequestHandler();
  createServer((req, res) => handler(req, res)).listen(Number(process.env.PORT || 3000), '0.0.0.0');
  console.log('OpenDART connector awaiting private configuration');
}
