// MCP tool definitions and handlers for credential management
// Part of Wraith v2.1 Features F2 + F5

import { join } from 'node:path';
import { CredentialStore } from '../services/credential-store.js';
import { generateMutations } from '../services/mutation-engine.js';
import type { CredentialScope, CredentialSource } from '../types/index.js';

export const CRED_TOOLS = [
  {
    name: 'cred_add',
    description: 'Add a discovered credential to the shared credential store.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        username: { type: 'string', description: 'Username' },
        password: { type: 'string', description: 'Plaintext password (if known)' },
        hash: { type: 'string', description: 'NTLM or Kerberos hash (if no plaintext)' },
        source: {
          type: 'string',
          enum: ['sqli', 'spray', 'kerberoast', 'asrep', 'lsass', 'dcsync', 'config', 'responder', 'unknown'],
          description: 'How this credential was obtained',
        },
        scope: {
          type: 'string',
          enum: ['web', 'domain', 'local', 'unknown'],
          description: 'Credential scope',
        },
        hosts_valid: {
          type: 'array',
          items: { type: 'string' },
          description: 'IPs where this credential is confirmed valid',
        },
        hosts_failed: {
          type: 'array',
          items: { type: 'string' },
          description: 'IPs where this credential failed',
        },
        protocol_valid: {
          type: 'array',
          items: { type: 'string' },
          description: 'Protocols confirmed valid (smb, winrm, rdp, http, ldap)',
        },
        protocol_failed: {
          type: 'array',
          items: { type: 'string' },
          description: 'Protocols confirmed failed',
        },
      },
      required: ['username', 'source', 'scope'],
    },
  },
  {
    name: 'cred_query',
    description: 'Query credentials from the store with optional filters.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        protocol: { type: 'string', description: 'Filter by protocol (e.g. smb, winrm, http)' },
        host: { type: 'string', description: 'Filter by host IP (tested on this host)' },
        scope: {
          type: 'string',
          enum: ['web', 'domain', 'local', 'unknown'],
          description: 'Filter by credential scope',
        },
        untested_for_host: { type: 'string', description: 'Return creds not yet tested on this host IP' },
        untested_for_protocol: { type: 'string', description: 'Return creds not yet tested on this protocol' },
      },
      required: [],
    },
  },
  {
    name: 'generate_mutations',
    description: 'Generate password mutation candidates based on known context (domain, usernames, hostnames).',
    inputSchema: {
      type: 'object' as const,
      properties: {
        passwords: {
          type: 'array',
          items: { type: 'string' },
          description: 'Known base passwords to mutate',
        },
        domain: { type: 'string', description: 'Domain name (e.g. YASHnet.local)' },
        usernames: {
          type: 'array',
          items: { type: 'string' },
          description: 'Known usernames for username-based mutations',
        },
        hostnames: {
          type: 'array',
          items: { type: 'string' },
          description: 'Known hostnames for hostname-based mutations',
        },
      },
      required: ['domain'],
    },
  },
];

// Singleton store -- lazy init on first use
let _store: CredentialStore | null = null;

function getStore(): CredentialStore {
  if (_store === null) {
    const logDir = process.env.WRAITH_LOG_DIR ?? join(process.cwd(), 'attack-logs');
    _store = new CredentialStore(logDir);
  }
  return _store;
}

export function handleCredTool(name: string, input: Record<string, unknown>): string {
  switch (name) {

    case 'cred_add': {
      const store = getStore();
      const cred = store.add({
        username: input.username as string,
        password: input.password as string | undefined,
        hash: input.hash as string | undefined,
        source: (input.source as CredentialSource) ?? 'unknown',
        scope: (input.scope as CredentialScope) ?? 'unknown',
        hosts_valid: (input.hosts_valid as string[]) ?? [],
        hosts_failed: (input.hosts_failed as string[]) ?? [],
        protocol_valid: (input.protocol_valid as string[]) ?? [],
        protocol_failed: (input.protocol_failed as string[]) ?? [],
      });
      return `Credential stored: [${cred.id}] ${cred.username} (scope=${cred.scope}, source=${cred.source})`;
    }

    case 'cred_query': {
      const store = getStore();
      const results = store.query({
        protocol: input.protocol as string | undefined,
        host: input.host as string | undefined,
        scope: input.scope as CredentialScope | undefined,
        untested_for_host: input.untested_for_host as string | undefined,
        untested_for_protocol: input.untested_for_protocol as string | undefined,
      });

      if (results.length === 0) {
        return 'No credentials match the given filters.';
      }

      const lines = results.map(c => {
        const secret = c.password ? `pass=${c.password}` : c.hash ? `hash=${c.hash.slice(0, 16)}...` : 'no-secret';
        return `[${c.id}] ${c.username} | ${secret} | scope=${c.scope} | valid=${c.hosts_valid.join(',') || 'none'} | failed=${c.hosts_failed.join(',') || 'none'}`;
      });

      const stats = store.getStats();
      lines.push(`\nTotal: ${stats.total} | Cracked: ${stats.cracked} | By scope: ${JSON.stringify(stats.by_scope)}`);
      return lines.join('\n');
    }

    case 'generate_mutations': {
      const passwords = (input.passwords as string[] | undefined) ?? [];
      const domain = input.domain as string;
      const usernames = (input.usernames as string[] | undefined) ?? [];
      const hostnames = (input.hostnames as string[] | undefined) ?? [];

      const mutations = generateMutations(passwords, { domain, usernames, hostnames });
      return `Generated ${mutations.length} password candidates:\n${mutations.join('\n')}`;
    }

    default:
      return `Unknown cred tool: ${name}`;
  }
}
