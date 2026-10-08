import { createMcpHandler, withMcpAuth } from 'mcp-handler';
import { registerAllTools } from '@/lib/tools';
import { connectorOrigin, verifyConnectorToken } from '@/lib/connector-auth';

const mcpHandler = createMcpHandler(
  server => { registerAllTools(server); },
  { capabilities: {} },
  { basePath: '/api', maxDuration: 60, verboseLogs: false, disableSse: true },
);
const handler = withMcpAuth(mcpHandler, verifyConnectorToken, {
  required: true,
  requiredScopes: ['dart:read'],
  resourceUrl: connectorOrigin(),
});
export { handler as GET, handler as POST, handler as DELETE };
