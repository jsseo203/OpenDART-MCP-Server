export function GET() {
  const configured = !!(process.env.OPENDART_API_KEY && process.env.OAUTH_JWKS && process.env.CONNECTOR_LOGIN_PASSWORD);
  return Response.json({ status: configured ? 'ok' : 'unconfigured' }, { status: configured ? 200 : 503 });
}
