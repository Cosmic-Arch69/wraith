#!/usr/bin/env node
// Wraith MCP stdio server
// Exposes pentest tools to Claude agents via MCP protocol

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { PENTEST_TOOLS, handleTool } from './tools.js';

const server = new Server(
  { name: 'wraith-tools', version: '0.1.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: PENTEST_TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const result = handleTool(name, (args ?? {}) as Record<string, unknown>);
  return {
    content: [{ type: 'text', text: result }],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
