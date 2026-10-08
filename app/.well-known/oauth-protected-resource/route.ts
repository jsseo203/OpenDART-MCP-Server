import { connectorOrigin } from '@/lib/connector-auth';
export function GET() {
  const origin = connectorOrigin();
  return Response.json({ resource: `${origin}/api/mcp`, authorization_servers: [`${origin}/oauth`], scopes_supported: ['dart:read'], bearer_methods_supported: ['header'] });
}
